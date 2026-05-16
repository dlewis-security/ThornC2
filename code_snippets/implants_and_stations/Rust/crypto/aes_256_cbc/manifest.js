const manifest = {
  "title": "AES-256-CBC",
  "component_type": "crypto",
  "author": "ph3eds",
  "description": "AES-256-CBC encrypt/decrypt with PKCS7 padding and base64 transport encoding. Key and IV are patched into the binary at build time via magic-header config block.",
  "mitre": [
    "T1573.001"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1573/001/"
  ],
  "parameters": [
    {
      "name": "key",
      "placeholder": "{{KEY}}",
      "type": "",
      "description": "32-byte AES key (patched at build time)",
      "default": ""
    },
    {
      "name": "iv",
      "placeholder": "{{IV}}",
      "type": "",
      "description": "16-byte AES IV (patched at build time)",
      "default": ""
    }
  ],
  "cargo_deps": {
    "aes": "0.8",
    "cbc": "0.1",
    "base64": "0.22"
  }
}
export { manifest }
