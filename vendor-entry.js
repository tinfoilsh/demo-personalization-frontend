// Browser entry: expose only the low-level attesting client + error types. We
// deep-import SecureClient directly from its dist file to bypass the package
// root's re-exports of TinfoilAI + the OpenAI SDK (which would otherwise bloat
// the bundle by ~hundreds of KB). esbuild still applies tinfoil's `browser`
// field remappings (pinned-tls-fetch → browser stub, etc.). Error classes come
// from the verifier package (re-exported by tinfoil's verifier.js shim).
export { SecureClient } from "./node_modules/tinfoil/dist/secure-client.js";
export {
  AttestationError,
  ConfigurationError,
  FetchError,
  TinfoilError,
} from "./node_modules/tinfoil/dist/verifier.js";
