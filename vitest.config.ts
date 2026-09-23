import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
	resolve: {
		alias: {
			// OMP's plugin loader rewrites `@earendil-works/*` onto its bundled `@oh-my-pi/*`
			// copy, where `CustomEditor` lives at `pi-tui/prompt/custom-editor`.  Upstream Pi
			// has no such file, so vitest resolves this spec through the upstream SDK root
			// instead.
			"@earendil-works/pi-tui/prompt/custom-editor": resolve(
				root,
				"extensions/piolium/_stubs/pi-tui-custom-editor.ts",
			),
		},
	},
	test: {
		include: ["test/**/*.test.ts"],
		environment: "node",
		// Audit-state tests use real fs in tmp dirs; serial keeps them simple.
		fileParallelism: false,
		coverage: {
			provider: "v8",
			include: ["extensions/**/*.ts"],
			exclude: ["extensions/**/_vendor/**", "extensions/**/_stubs/**"],
			reporter: ["text", "html"],
		},
	},
});
