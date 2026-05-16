const manifest = {
  "title": "PowerUpSQL Discovery",
  "task_type": "ps_powerupsql",
  "description": "Run PowerUpSQL in-memory to enumerate SQL Server instances on the domain. Calls Get-SQLInstanceDomain | Get-SQLServerInfo.",
  "parameters": [
    {
      "name": "command",
      "description": "Full powershell invocation: powershell -w hidden -ep bypass -EncodedCommand <b64> (set by CLI)"
    }
  ]
}
export { manifest }
