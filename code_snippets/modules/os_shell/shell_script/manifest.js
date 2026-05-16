 const manifest = {
  "title": "Shell Script",
  "task_type": "os_shell",
  "author": "ph3eds",
  "description": "Schedule generic shell scripts. This allows the operator to specify multiple commands in a single script file for execution.",
  "parameters":[
    {
      "name": "script",
      "placeholder": "{{SCRIPT}}",
      "type": "textarea",
      "description": "Shell Script to run",
      "default": ""
    }
  ]
}
export {manifest}
