const manifest = {
  "title": "ETW Patch",
  "component_type": "evasion",
  "author": "ph3eds",
  "description": "Patches EtwEventWrite with xor eax,eax; ret to suppress ETW telemetry. ETW-only — does not touch AMSI. Pair with ntdll_unhook (run unhook first, then patch).",
  "mitre": [
    "T1562.006"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1562/006/"
  ],
  "parameters": [],
  "cargo_deps": {
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_System_LibraryLoader",
        "Win32_System_Memory"
      ]
    }
  }
}
export { manifest }
