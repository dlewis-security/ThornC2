const manifest = {
  "title": "Shellcode Load (Inline)",
  "task_type": "shellcode_load_inline",
  "description": "Deliver AES-256-CBC encrypted shellcode inline through the C2 channel. The operator CLI encrypts the payload using the implant's key/IV before dispatch — no external hosting required.",
  "parameters": [
    {
      "name": "payload",
      "description": "AES-256-CBC encrypted shellcode, base64-encoded (set by CLI)"
    }
  ]
}
export { manifest }
