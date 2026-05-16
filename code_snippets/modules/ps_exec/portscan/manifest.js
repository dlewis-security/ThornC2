const manifest = {
  "title": "Invoke-Portscan",
  "task_type": "ps_portscan",
  "description": "Run Invoke-Portscan in-memory via PowerShell EncodedCommand. Operator CLI encodes PS1 + invocation with target hosts and ports.",
  "parameters": [
    {
      "name": "command",
      "description": "Full powershell invocation: powershell -w hidden -ep bypass -EncodedCommand <b64> (set by CLI)"
    }
  ]
}
export { manifest }
