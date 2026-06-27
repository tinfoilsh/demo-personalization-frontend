// The enclave the frontend talks to. The Tinfoil CVM shim in front of the
// control server terminates TLS + speaks EHBP, so the client encrypts request
// bodies end-to-end. Attestation is disabled for now (the enclave is TDX, which
// the JS SDK's verifier doesn't support yet) — see the footer.
// Override at runtime on the connect screen (persisted to localStorage under
// `pz.apiBase`).
window.DEFAULT_API_BASE =
  "https://demo-personalization.tinfoil.containers.tinfoil.dev";
