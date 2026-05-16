const manifest = {
  "title": "Block Non-Microsoft DLLs",
  "component_type": "evasion",
  "author": "ph3eds",
  "description": "Applies ProcessSignaturePolicy mitigation to the current process, blocking injection of any DLL not signed by Microsoft. Prevents AV/EDR from loading their inspection modules into the implant process.",
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
        "Win32_System_Threading",
        "Win32_System_SystemServices"
      ]
    }
  }
}
export { manifest }
