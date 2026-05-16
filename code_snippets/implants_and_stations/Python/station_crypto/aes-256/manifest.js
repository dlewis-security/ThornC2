 const manifest = {
  "title": "AES-256 Crypto",
  "component_type": "station_crypto",
  "author": "eiprm",
  "description": "AES-256 crypto for Station.",
  "mitre": ["T1132.001"],
  "references": ["https://attack.mitre.org/techniques/T1132/001/"],
  "parameters":[
      {
        "name": "key",
        "placeholder": "{{0123456789abcdef0123456789abcdef}}",
        "type": "",
        "description": "Key used for AES-256. Length of 32.",
        "default": ""
      },
      {
        "name": "iv",
        "placeholder": "{{1337deadbeef1337}}",
        "type": "",
        "description": "Initalization Vector for AES-256. Length of 16.",
        "default": ""
      }
    ]
  }
export {manifest}
