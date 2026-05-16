const manifest = {
  "title": "AMSI Hardware Breakpoint",
  "component_type": "evasion",
  "author": "ph3eds",
  "description": "Bypasses AMSI via hardware breakpoint on AmsiScanBuffer. Uses DR1 debug register + VEH — no memory patching, invisible to AmsiRegistrationProtection. Coexists with etw_hwbp (DR0). Pair with powershell_clr execution component.",
  "mitre": [
    "T1562.001"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1562/001/"
  ],
  "parameters": [],
  "cargo_deps": {
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_System_LibraryLoader"
      ]
    }
  }
}
export { manifest }
