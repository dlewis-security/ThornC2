const manifest = {
  "title": "Invoke-Mimikatz (DumpCreds)",
  "task_type": "ps_mimikatz",
  "description": "Run Invoke-Mimikatz -DumpCreds entirely in-memory via PowerShell EncodedCommand. No disk write. Operator CLI encodes the PS1 + invocation as UTF-16LE base64 before dispatch.",
  "parameters": [
    {
      "name": "command",
      "description": "Full powershell invocation: powershell -w hidden -ep bypass -EncodedCommand <b64> (set by CLI)"
    }
  ]
}
export { manifest }
