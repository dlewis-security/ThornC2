const manifest = {
  "title": "BOF Execute (Inline)",
  "task_type": "bof_inline",
  "description": "Execute a Beacon Object File (BOF) in-process via the C2 channel. The operator CLI packs the COFF .o file with arguments, AES-256-CBC encrypts the bundle, and dispatches it — no external hosting required.",
  "parameters": [
    {
      "name": "payload",
      "description": "AES-256-CBC encrypted BOF bundle, base64-encoded (set by CLI)"
    }
  ]
}
export { manifest }
