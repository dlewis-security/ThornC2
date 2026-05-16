const manifest = {
  "title": "AES-256-CBC (PKCS7)",
  "component_type": "stager_crypto",
  "author": "ph3eds",
  "description": "Baseline symmetric cipher for THORNPLD blobs. Uses the RustCrypto `aes` + `cbc` crates in no_std mode. Key length: 32 bytes. IV length: 16 bytes. PKCS7 padding is stripped from the plaintext. The component exposes a single free function `crypto::decrypt_in_place` matching the shared stager crypto contract.",
  "parameters": [],
  "cargo_deps": {
    "aes": { "version": "0.8", "features": [] },
    "cbc": "0.1"
  }
}
export { manifest }
