const manifest = {
  "title": "LSASS Minidump (Out-MiniDump)",
  "task_type": "ps_lsass_dump",
  "description": "Dump LSASS to a minidump file via Out-MiniDump in-memory. CLI auto-downloads the .dmp after task completes.",
  "parameters": [
    {
      "name": "command",
      "description": "Full powershell invocation: powershell -w hidden -ep bypass -EncodedCommand <b64> (set by CLI)"
    }
  ]
}
export { manifest }
