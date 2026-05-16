 const manifest = {
  "title": "MD5 Username",
  "component_type": "keying",
  "author": "3iprm",
  "description": "Keying based on MD5 hash of username.",
  "mitre": ["T1497.001"],
  "references": ["https://attack.mitre.org/techniques/T1497/001/"],
  "parameters":[
    {
      "name": "username",
      "placeholder": "{{USERNAME}}",
      "type": "",
      "description": "Username of the target user.",
      "default": ""
    },
    {
      "name": "station",
      "placeholder": "{{STATION}}",
      "type": "",
      "description": "Station for callback channel.",
      "default": ""
    }
  ]
}
export {manifest}
