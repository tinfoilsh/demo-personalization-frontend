// The enclave the frontend talks to. The Tinfoil CVM shim in front of the
// control server terminates TLS + speaks EHBP, so a SecureClient constructed
// against this URL attests and encrypts request bodies end-to-end.
// Override at runtime on the connect screen (persisted to localStorage under
// `pz.apiBase`).
window.DEFAULT_API_BASE =
  "https://demo-personalization.tinfoil.containers.tinfoil.dev";

// GitHub repo the enclave image is verified against (code attestation).
// Must match the repo the enclave was built/released from.
window.TINFOIL_CONFIG_REPO = "tinfoilsh/demo-personalization";
