const manifest = {
  "title": "TCP Relay Shell",
  "task_type": "revshell",
  "author": "ph3eds",
  "description": "Connect back to the station TCP relay and spawn an interactive cmd.exe shell.",
  "parameters": [
    {
      "name": "host",
      "placeholder": "{{HOST}}",
      "type": "string",
      "description": "Station relay host",
      "default": "127.0.0.1"
    },
    {
      "name": "port",
      "placeholder": "{{PORT}}",
      "type": "string",
      "description": "Station relay port",
      "default": "4444"
    },
    {
      "name": "token",
      "placeholder": "{{TOKEN}}",
      "type": "string",
      "description": "8-char hex session token used to pair operator and implant connections",
      "default": ""
    }
  ]
}
export { manifest }
