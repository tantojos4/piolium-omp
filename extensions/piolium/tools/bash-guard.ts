/**
 * Guarded `bash` for child audit sessions.
 *
 * Child sessions are spawned through the SDK with `noExtensions: true`, so an
 * extension-level `pi.on("tool_call")` hook never fires for them and the
 * builtin `bash` cannot be policed from the extension layer. The SDK also has
 * no permission prompt in headless sessions — the `permissionMode:
 * bypassPermissions` frontmatter in `agents/` is descriptive, not enforced.
 *
 * The one seam that does work is tool shadowing: a `customTools` entry named
 * `bash` replaces the builtin in the child's tool registry. So this module
 * builds a bash tool that is identical to the builtin except for two guards:
 *
 *   1. A **default timeout**. The builtin's `timeout` argument is optional and
 *      the model usually omits it, which means an unbounded command (a
 *      `find /` that walks every mount) hangs the phase forever — phases run
 *      with no timeout of their own, so nothing else ever fires the abort.
 *      `BashSpawnHook` cannot set a timeout, so the clamp lives in a wrapped
 *      `BashOperations.exec`.
 *   2. A **command blocklist**, applied in `BashSpawnHook` — throwing there
 *      rejects the command before the shell spawns and hands the model an
 *      actionable error it can correct from, rather than silently rewriting
 *      what it asked for.
 *
 * This is defense in depth, not a sandbox. The blocklist stops the obvious
 * whole-filesystem and host-destructive mistakes; it will not stop a
 * determined adversarial command. Untrusted repositories still belong in a
 * sandboxed working directory (see the security note in README).
 */

import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import {
	type BashOperations,
	type BashSpawnContext,
	type ToolDefinition,
	createBashToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { tokenizeCommandArgs } from "../command-target.ts";
import { readBooleanEnv, readPositiveIntEnv, readTrimmedEnv } from "../retry.ts";

/**
 * Local shell backend for the guarded `bash` tool.
 *
 * Pi ships this as `createLocalBashOperations`, but omp's legacy-pi shim
 * (`@earendil-works/pi-coding-agent` → `omp-legacy-pi-bundled:
 * @oh-my-pi/pi-coding-agent`) does not re-export it, so a package that imports
 * the helper fails validation at load. The surface is small and stable, so we
 * implement it here instead of depending on the host re-exporting it.
 */
function localBashOperations(shellPath?: string): BashOperations {
	const shell = shellPath ?? process.env.SHELL ?? "/bin/bash";
	return {
		exec: async (command, cwd, { onData, signal, timeout, env }) => {
			const timeoutMs = timeout === undefined ? undefined : timeout * 1000;
			// Reject an unusable cwd with an actionable message rather than a bare
			// ENOENT from the spawn below.
			await access(cwd).catch(() => {
				throw new Error(`Working directory does not exist: ${cwd}\nCannot execute bash commands.`);
			});
			const child = spawn(shell, ["-c", command], {
				cwd,
				detached: process.platform !== "win32",
				env: env ?? process.env,
				stdio: ["ignore", "pipe", "pipe"],
				windowsHide: true,
			});
			const killTree = () => {
				if (!child.pid) return;
				try {
					process.kill(-child.pid, "SIGKILL");
				} catch {
					child.kill("SIGKILL");
				}
			};
			let timedOut = false;
			const timeoutHandle =
				timeoutMs === undefined
					? undefined
					: setTimeout(() => {
							timedOut = true;
							killTree();
						}, timeoutMs);
			const onAbort = () => killTree();
			try {
				child.stdout?.on("data", onData);
				child.stderr?.on("data", onData);
				if (signal) {
					if (signal.aborted) onAbort();
					else signal.addEventListener("abort", onAbort, { once: true });
				}
				const exitCode = await new Promise<number | null>((resolve, reject) => {
					child.on("error", reject);
					child.on("close", resolve);
				});
				if (signal?.aborted) throw new Error("aborted");
				if (timedOut) throw new Error(`timeout:${timeout}`);
				return { exitCode };
			} finally {
				clearTimeout(timeoutHandle);
				if (signal) signal.removeEventListener("abort", onAbort);
			}
		},
	};
}

/** Applied when the model omits `timeout`. 15 min is well past any sane repo-scoped command. */
export const DEFAULT_BASH_TIMEOUT_MS = 15 * 60 * 1000;
/** Ceiling on a model-supplied `timeout`, so the model cannot opt back into "forever". */
export const DEFAULT_BASH_TIMEOUT_MAX_MS = 60 * 60 * 1000;

const TIMEOUT_ENV = "PIOLIUM_BASH_TIMEOUT_MS";
const TIMEOUT_MAX_ENV = "PIOLIUM_BASH_TIMEOUT_MAX_MS";
const BLOCKLIST_ENV = "PIOLIUM_BASH_BLOCKLIST";
const GUARD_ENV = "PIOLIUM_BASH_GUARD";

/**
 * Path arguments that mean "somewhere at or near the filesystem root". Matched
 * as whole tokens, so `/etc/passwd` is fine while a bare `/etc` is not.
 */
const ROOT_PATHS = new Set([
	"/",
	"/*",
	"~",
	"~/",
	"$HOME",
	"${HOME}",
	"/Applications",
	"/System",
	"/Library",
	"/Users",
	"/Volumes",
	"/bin",
	"/dev",
	"/etc",
	"/home",
	"/mnt",
	"/opt",
	"/private",
	"/proc",
	"/root",
	"/sbin",
	"/srv",
	"/sys",
	"/usr",
	"/var",
]);

/** Commands that recurse by default — a root path argument means "walk the whole disk". */
const ALWAYS_RECURSIVE = new Set(["find", "fd", "fdfind", "rg", "ag", "ack", "tree", "du", "ncdu"]);

/** Commands that only recurse when asked; the flag test below gates them. */
const OPT_IN_RECURSIVE = new Set(["grep", "egrep", "fgrep", "ls", "cp", "chmod", "chown", "chgrp"]);

const RECURSIVE_FLAG = /^-(?:-recursive$|[a-zA-Z]*[rR])/;

/**
 * Targets that make a recursive `rm` catastrophic. A superset of ROOT_PATHS:
 * `.` and `..` must not go in ROOT_PATHS itself, or the allowed
 * `find . -name '*.ts'` would be blocked as a whole-filesystem scan.
 */
const DESTRUCTIVE_RM_TARGETS = new Set([...ROOT_PATHS, ".", "./", "..", "../"]);

/** Whole-command patterns whose danger is in the literal text, not the path arguments. */
const LITERAL_RULES: ReadonlyArray<{ id: string; pattern: RegExp; reason: string }> = [
	{
		id: "fork-bomb",
		pattern: /:\s*\(\s*\)\s*\{[^}]*\|[^}]*&[^}]*\}\s*;\s*:/,
		reason: "fork bomb",
	},
	{
		id: "mkfs",
		pattern: /\bmkfs(?:\.[a-z0-9]+)?\b/,
		reason: "filesystem format",
	},
	{
		id: "raw-device-write",
		pattern: /(?:\bdd\b[^\n]*\bof=|>\s*)\/dev\/(?:sd|hd|nvme|disk|rdisk|vd|mmcblk)/,
		reason: "raw block-device write",
	},
	{
		id: "device-shred",
		pattern: /\b(?:shred|wipefs)\b[^\n]*\/dev\//,
		reason: "block-device wipe",
	},
	{
		id: "host-power",
		pattern: /\b(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b/,
		reason: "host power control",
	},
];

export interface BashGuardViolation {
	/** Stable rule id — useful for tests and for operators reading logs. */
	rule: string;
	reason: string;
}

/**
 * Split a command line into the pipeline/list segments a shell would run
 * separately, so `ls -la && find / -name x` is checked as two commands rather
 * than one blob where `ls` masks `find`.
 */
function splitSegments(command: string): string[] {
	return command
		.split(/\n|;|&&|\|\||\||&/)
		.map((segment) => segment.trim())
		.filter((segment) => segment.length > 0);
}

/**
 * Strip the prefixes that sit in front of the real command word — leading env
 * assignments (`FOO=bar cmd`) and privilege/wrapper words — so `sudo find /`
 * is recognized as `find`.
 */
function commandWord(tokens: string[]): { name: string; args: string[] } | undefined {
	let index = 0;
	while (index < tokens.length) {
		const token = tokens[index];
		if (token === undefined) return undefined;
		if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token) || token === "sudo" || token === "doas") {
			index += 1;
			continue;
		}
		break;
	}
	const raw = tokens[index];
	if (raw === undefined) return undefined;
	const name = raw.split("/").pop() ?? raw;
	return { name, args: tokens.slice(index + 1) };
}

function hasRecursiveFlag(args: string[]): boolean {
	return args.some((arg) => RECURSIVE_FLAG.test(arg));
}

function rootPathArg(
	args: string[],
	targets: ReadonlySet<string> = ROOT_PATHS,
): string | undefined {
	return args.find((arg) => targets.has(arg));
}

function checkSegment(segment: string): BashGuardViolation | undefined {
	const parsed = commandWord(tokenizeCommandArgs(segment));
	if (!parsed) return undefined;
	const { name, args } = parsed;

	// `rm -rf /` and friends. Checked before the scan rules because the reason
	// we report should say "destructive", not "whole-filesystem scan".
	if (name === "rm" && hasRecursiveFlag(args)) {
		const target = rootPathArg(args, DESTRUCTIVE_RM_TARGETS);
		if (target) {
			return { rule: "destructive-rm", reason: `recursive delete of ${target}` };
		}
	}

	const recursive =
		ALWAYS_RECURSIVE.has(name) || (OPT_IN_RECURSIVE.has(name) && hasRecursiveFlag(args));
	if (!recursive) return undefined;
	const target = rootPathArg(args);
	if (!target) return undefined;
	return { rule: "whole-filesystem-scan", reason: `${name} recursing from ${target}` };
}

/**
 * Extra operator-supplied patterns from `PIOLIUM_BASH_BLOCKLIST` — newline-
 * separated JS regex sources, matched case-insensitively. Unparseable entries
 * are ignored rather than failing every command in the audit.
 */
function operatorRules(): RegExp[] {
	const raw = readTrimmedEnv(BLOCKLIST_ENV);
	if (!raw) return [];
	const rules: RegExp[] = [];
	for (const line of raw.split("\n")) {
		const source = line.trim();
		if (!source) continue;
		try {
			rules.push(new RegExp(source, "i"));
		} catch {
			// Bad pattern: skip it. Blocking the whole audit over a typo in an
			// env var is worse than running with one fewer rule.
		}
	}
	return rules;
}

function isBashGuardEnabled(): boolean {
	return readBooleanEnv(GUARD_ENV, true);
}

/**
 * Decide whether a command is blocked. Exported so the policy is testable
 * without spawning a shell.
 */
export interface BashGuardPolicy {
	enabled: boolean;
	operatorRules: RegExp[];
}

/**
 * Snapshot the env-derived guard policy. Resolved once per tool rather than
 * once per command: the operator blocklist is immutable for the tool's life,
 * matching how the timeout policy is already resolved.
 */
export function resolveBashGuardPolicy(): BashGuardPolicy {
	return { enabled: isBashGuardEnabled(), operatorRules: operatorRules() };
}

export function checkBashCommand(
	command: string,
	policy: BashGuardPolicy = resolveBashGuardPolicy(),
): BashGuardViolation | undefined {
	if (!policy.enabled) return undefined;

	for (const rule of LITERAL_RULES) {
		if (rule.pattern.test(command)) return { rule: rule.id, reason: rule.reason };
	}
	for (const pattern of policy.operatorRules) {
		if (pattern.test(command)) {
			return {
				rule: "operator-blocklist",
				reason: `matches ${BLOCKLIST_ENV} pattern ${pattern.source}`,
			};
		}
	}
	for (const segment of splitSegments(command)) {
		const violation = checkSegment(segment);
		if (violation) return violation;
	}
	return undefined;
}

export interface BashTimeoutPolicy {
	/** Seconds applied when the model supplies no `timeout`. */
	defaultSeconds: number;
	/** Seconds a model-supplied `timeout` is clamped to. */
	maxSeconds: number;
}

export function resolveBashTimeoutPolicy(): BashTimeoutPolicy {
	const defaultMs = readPositiveIntEnv(TIMEOUT_ENV, DEFAULT_BASH_TIMEOUT_MS);
	const maxMs = Math.max(
		defaultMs,
		readPositiveIntEnv(TIMEOUT_MAX_ENV, DEFAULT_BASH_TIMEOUT_MAX_MS),
	);
	return {
		defaultSeconds: Math.max(1, Math.ceil(defaultMs / 1000)),
		maxSeconds: Math.max(1, Math.ceil(maxMs / 1000)),
	};
}

export function clampBashTimeoutSeconds(
	requested: number | undefined,
	policy: BashTimeoutPolicy,
): number {
	if (requested === undefined || !Number.isFinite(requested) || requested <= 0) {
		return policy.defaultSeconds;
	}
	return Math.min(requested, policy.maxSeconds);
}

/**
 * Wrap `BashOperations` so every exec carries a timeout. `BashSpawnHook` only
 * gets `{ command, cwd, env }` back, so this is the only place the timeout can
 * be applied without rewriting the command into a `timeout(1)` call — which
 * isn't portable (macOS ships no `timeout`).
 */
export function withBashTimeout(base: BashOperations, policy: BashTimeoutPolicy): BashOperations {
	return {
		exec: (command, cwd, options) =>
			base.exec(command, cwd, {
				...options,
				timeout: clampBashTimeoutSeconds(options.timeout, policy),
			}),
	};
}

export function createBashGuardSpawnHook(): (context: BashSpawnContext) => BashSpawnContext {
	const policy = resolveBashGuardPolicy();
	return (context) => {
		const violation = checkBashCommand(context.command, policy);
		if (!violation) return context;
		throw new Error(
			[
				`Blocked by the piolium bash guard (${violation.rule}): ${violation.reason}.`,
				`Scope the command to the audited repository (${context.cwd}) or a subdirectory instead.`,
				`An operator can relax this with ${BLOCKLIST_ENV}, or disable it entirely with ${GUARD_ENV}=0.`,
			].join(" "),
		);
	};
}

export interface GuardedBashOptions {
	/** Shell path from settings, so the guarded tool matches the builtin's shell. */
	shellPath?: string;
	/** Shell setup prefix from settings, likewise. */
	commandPrefix?: string;
}

/**
 * Build the `bash` tool for a child session. The name is deliberately `bash`:
 * a `customTools` entry shadows the builtin of the same name in the child's
 * tool registry, which is the only interception point available to us.
 */
export function createGuardedBashTool(
	cwd: string,
	options: GuardedBashOptions = {},
): ToolDefinition {
	const policy = resolveBashTimeoutPolicy();
	const definition = createBashToolDefinition(cwd, {
		operations: withBashTimeout(localBashOperations(options.shellPath), policy),
		...(options.commandPrefix ? { commandPrefix: options.commandPrefix } : {}),
		...(options.shellPath ? { shellPath: options.shellPath } : {}),
		spawnHook: createBashGuardSpawnHook(),
	});

	return {
		...definition,
		description: [
			definition.description,
			`Commands time out after ${policy.defaultSeconds}s by default (max ${policy.maxSeconds}s via the timeout argument).`,
			"Whole-filesystem scans and host-destructive commands are rejected — scope every command to the audited repository.",
		].join(" "),
	} as ToolDefinition;
}
