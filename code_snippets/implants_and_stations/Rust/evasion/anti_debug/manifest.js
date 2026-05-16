const manifest = {
  "title": "Anti-Debug",
  "component_type": "evasion",
  "author": "ph3eds",
  "description": "Checks for attached debuggers at startup via IsDebuggerPresent, PEB BeingDebugged flag, and hardware breakpoint registers (Dr0-Dr3). Exits silently if any check fires.",
  "mitre": [
    "T1622"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1622/"
  ],
  "parameters": [],
  "cargo_deps": {
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_System_Diagnostics_Debug",
        "Win32_System_Kernel"
      ]
    }
  }
}
export { manifest }
