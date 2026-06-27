// Bundles the tinfoil SDK's SecureClient (+ fetchAttestationBundle) into a
// single browser-loadable script. Only SecureClient is pulled in — the
// OpenAI-dependent TinfoilAI class is tree-shaken out, keeping the bundle small.
//
//   node build-vendor.mjs     # writes vendor/tinfoil.js
//
// The frontend loads vendor/tinfoil.js via <script>, then uses Tinfoil.SecureClient.
import * as esbuild from "esbuild";

// The verifier pulls in a few node built-ins (zlib, node:fs, node:path, …) that
// only appear in dead code paths on the browser EHBP route: TLS pinning (browser-
// stubbed), test files, CLIs, and a node-only TUF storage fallback. The browser
// code uses Web Crypto / DecompressionStream / fetch instead. Stub them to an
// empty module — same as webpack's `fallback: { …: false }`.
const emptyNodeBuiltins = {
  name: "empty-node-builtins",
  setup(build) {
    const nodeMods = [
      "zlib", "crypto", "node:crypto", "fs", "node:fs", "node:fs/promises",
      "path", "node:path", "os", "node:os", "stream", "node:stream",
      "http", "https", "node:http", "node:https", "url", "node:url",
      "util", "node:util", "buffer", "node:buffer", "assert", "node:assert",
      "test", "node:test", "tty", "node:tty",
    ];
    const filter = new RegExp(`^(${nodeMods.join("|")})$`);
    build.onResolve({ filter }, () => ({ path: "empty", namespace: "empty-mod" }));
    build.onLoad({ filter: /.*/, namespace: "empty-mod" }, () => ({
      contents: "export default {};",
      loader: "js",
    }));
  },
};

await esbuild.build({
  entryPoints: ["vendor-entry.js"],
  bundle: true,
  format: "iife",
  globalName: "Tinfoil",
  outfile: "vendor/tinfoil.js",
  target: "es2020",
  platform: "browser",
  legalComments: "none",
  logLevel: "info",
  plugins: [emptyNodeBuiltins],
});
