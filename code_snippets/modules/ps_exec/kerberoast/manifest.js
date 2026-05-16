const manifest = {
  "title": "Invoke-Kerberoast",
  "task_type": "ps_kerberoast",
  "description": "Run Invoke-Kerberoast in-memory via PowerShell EncodedCommand. Returns hashes in Hashcat format. Operator CLI encodes the PS1 + invocation with optional domain/user filter.",
  "parameters": [
    {
      "name": "command",
      "description": "Full powershell invocation: powershell -w hidden -ep bypass -EncodedCommand <b64> (set by CLI)"
    }
  ]
}
export { manifest }
