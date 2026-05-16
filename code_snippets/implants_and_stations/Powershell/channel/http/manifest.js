 const manifest = {
  "title": "HTTP Channel",
  "component_type": "channel",
  "author": "3iprm",
  "description": "Most basic HTTP callback",
  "mitre": ["T1071.001"],
  "references": ["https://attack.mitre.org/techniques/T1071/001/"],
  "parameters":[
    {
      "name": "implant_id",
      "placeholder": "{{IMP_ID}}",
      "type": "",
      "description": "Unique ID to track instances of this implant on a per-op or per-target basis.",
      "default": ""
    }
  ]
}
export {manifest}
