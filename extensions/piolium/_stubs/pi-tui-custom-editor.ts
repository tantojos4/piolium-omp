/**
 * Test-only stand-in for OMP's `@earendil-works/pi-tui/prompt/custom-editor`.
 *
 * That module exists only on OMP, where the plugin loader rewrites
 * `@earendil-works/*` onto its bundled `@oh-my-pi/*` copy. Upstream Pi ships no
 * such file, so vitest resolves this shim through the alias in
 * `vitest.config.ts`. Upstream exports the same class from its SDK root, so
 * re-exporting it keeps the tests faithful to the runtime class.
 */

export { CustomEditor } from "@earendil-works/pi-coding-agent";
