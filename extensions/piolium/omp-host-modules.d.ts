/**
 * Host-only module declarations.
 *
 * `@earendil-works/pi-tui/prompt/custom-editor` exists only on OMP: its plugin
 * loader rewrites `@earendil-works/*` imports onto its bundled `@oh-my-pi/*`
 * copy, where the file lives at `src/prompt/custom-editor.ts`. Upstream
 * `@earendil-works/pi-tui` ships no such module and neither barrel re-exports
 * the class, so TypeScript cannot resolve the specifier from the installed
 * packages.
 *
 * Declare only the surface piolium's `PioliumPromptPrefixEditor` uses. The base
 * class is declared as `Editor` (which upstream does export) so the subclass
 * still satisfies `EditorComponent` at the `setEditorComponent` boundary.
 */

declare module "@earendil-works/pi-tui/prompt/custom-editor" {
	import { Editor } from "@earendil-works/pi-tui";
	import type { EditorTheme, TUI } from "@earendil-works/pi-tui";
	import type { KeybindingsManager } from "@earendil-works/pi-coding-agent";

	export class CustomEditor extends Editor {
		constructor(
			tui: TUI,
			theme: EditorTheme,
			keybindings: KeybindingsManager,
			options?: { paddingX?: number },
		);
	}
}
