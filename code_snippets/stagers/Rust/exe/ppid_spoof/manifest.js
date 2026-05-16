const manifest = {
  "title": "Rust PE Stager \u2014 PPID Spoof + CreateRemoteThread",
  "file_type": "exe",
  "payload_type": "Rust",
  "author": "ph3eds",
  "description": "Spawns a sacrificial process with a spoofed parent PID (explorer.exe by default), then injects shellcode via the classic VirtualAllocEx \u2192 WriteProcessMemory \u2192 VirtualProtect(RX) \u2192 CreateRemoteThread chain. No OEP patching, no SetThreadContext, no thread suspension. Use to isolate whether PPID spoofing alone is sufficient or whether the injection technique is the AV trigger.",
  "mitre": [
    "T1055.003",
    "T1134.004"
  ],
  "references": [],
  "parameters": [],
  "cargo_deps": {
    "aes": "0.8",
    "cbc": "0.1",
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_Foundation",
        "Win32_System_Diagnostics_ToolHelp",
        "Win32_System_LibraryLoader",
        "Win32_System_Threading"
      ]
    }
  }
}
export { manifest }
