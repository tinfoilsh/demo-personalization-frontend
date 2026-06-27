// Browser entry: expose the low-level clients + error types. We deep-import
// from dist files to bypass the package root's re-exports of TinfoilAI + the
// OpenAI SDK (which would otherwise bloat the bundle by ~hundreds of KB).
// esbuild still applies tinfoil's `browser` field remappings.
export { SecureClient } from "./node_modules/tinfoil/dist/secure-client.js";
export { UnverifiedClient } from "./node_modules/tinfoil/dist/unverified-client.js";
export {
  AttestationError,
  ConfigurationError,
  FetchError,
  TinfoilError,
} from "./node_modules/tinfoil/dist/verifier.js";
