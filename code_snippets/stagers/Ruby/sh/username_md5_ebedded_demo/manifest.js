 const manifest = {
  "title": "Demo MD5 Username In Base64 Embedded Payload",
  "file_type": "sh",
  "payload_type": "Ruby",
  "author": "ph3eds",
  "description": "Demo bash stager with keying based on MD5 hash of username.",
  "mitre": ["T1059.004"],
  "references": ["https://attack.mitre.org/techniques/T1059/004/"],
  "parameters":[
    {
      "name": "username",
      "placeholder": "{{USERNAME}}",
      "type": "",
      "description": "Username of the target user.",
      "default": ""
    }
  ]
}
export {manifest}
