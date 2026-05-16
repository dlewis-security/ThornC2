 const manifest = {
  "title": "HTTP Demo Station Channel",
  "component_type": "station_channel",
  "author": "3iprm",
  "description": "Most basic HTTP station for demo purposes",
  "mitre": ["T1071.001"],
  "references": ["https://attack.mitre.org/techniques/T1071/001/"],
  "parameters":[
    {
      "name": "c2_server",
      "placeholder": "{{C2_SERVER}}",
      "type": "",
      "description": "C2 server to use for get_task and task_io.",
      "default": ""
    },
    {
      "name": "relay_port",
      "placeholder": "{{RELAY_PORT}}",
      "type": "",
      "description": "TCP port for the reverse shell relay listener.",
      "default": "4444"
    },
    {
      "name": "cover_redirect",
      "placeholder": "{{COVER_REDIRECT}}",
      "type": "",
      "description": "URL to redirect non-beacon traffic to.",
      "default": "https://www.microsoft.com"
    }
  ]
}
export {manifest}
