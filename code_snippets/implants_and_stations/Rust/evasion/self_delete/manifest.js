const manifest = {
  "title": "Self-Deletion",
  "component_type": "evasion",
  "author": "ph3eds",
  "description": "Deletes the implant binary from disk at startup using the rename-to-ADS then FILE_DISPOSITION_INFO technique. The process continues running in memory while leaving no file artifact on disk.",
  "mitre": [
    "T1070.004"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1070/004/"
  ],
  "parameters": [],
  "cargo_deps": {
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_Foundation",
        "Win32_Storage_FileSystem",
        "Win32_System_Memory"
      ]
    }
  }
}
export { manifest }
