const manifest = {
  "title": "SharpHound (BloodHound Collector)",
  "task_type": "ps_sharphound",
  "description": "Run Invoke-BloodHound in-memory to collect AD data for BloodHound. CLI auto-downloads the output zip after task completes.",
  "parameters": [
    {
      "name": "command",
      "description": "Full powershell invocation: powershell -w hidden -ep bypass -EncodedCommand <b64> (set by CLI)"
    }
  ]
}
export { manifest }
