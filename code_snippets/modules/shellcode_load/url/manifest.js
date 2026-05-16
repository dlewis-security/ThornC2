const manifest = {
  "title": "Shellcode Load (URL)",
  "task_type": "shellcode_load",
  "author": "ph3eds",
  "description": "Download shellcode from a URL and execute it in a new thread via VirtualAlloc/CreateThread.",
  "mitre": ["T1055", "T1105"],
  "references": [
    "https://attack.mitre.org/techniques/T1055/",
    "https://attack.mitre.org/techniques/T1105/"
  ],
  "parameters": [
    {
      "name": "url",
      "placeholder": "{{URL}}",
      "type": "",
      "description": "URL to fetch shellcode from (e.g. http://10.0.0.1/beacon.bin)",
      "default": ""
    }
  ]
}
export { manifest }
