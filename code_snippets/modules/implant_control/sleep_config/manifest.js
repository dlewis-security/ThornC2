const manifest = {
  "title": "Sleep Config",
  "task_type": "implant_control",
  "author": "ph3eds",
  "description": "Update the beacon sleep interval on an active implant without recompiling.",
  "parameters": [
    {
      "name": "interval",
      "placeholder": "{{INTERVAL}}",
      "type": "",
      "description": "Sleep interval in milliseconds",
      "default": "30000"
    }
  ]
}
export { manifest }
