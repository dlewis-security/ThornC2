 const manifest = {
  "title": "Shell Command",
  "task_type": "os_shell",
  "author": "ph3eds",
  "description": "Schedule generic shell command 'one-liners' on linux systems.",
  "parameters":[
    {
      "name": "command",
      "placeholder": "{{COMMAND}}",
      "type": "",
      "description": "OS Command to run",
      "default": ""
    }
  ]
}
export {manifest}
