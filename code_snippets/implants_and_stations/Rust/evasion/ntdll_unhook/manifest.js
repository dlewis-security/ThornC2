const manifest = {
  "title": "NTDLL Unhooking",
  "component_type": "evasion",
  "author": "ph3eds",
  "description": "Maps ntdll.dll from disk via CreateFileMapping, reads the clean .text section, and overwrites the in-process ntdll .text to remove AV/EDR userland hooks. No child process is spawned.",
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
        "Win32_Foundation",
        "Win32_Security",
        "Win32_Storage_FileSystem",
        "Win32_System_Diagnostics_Debug",
        "Win32_System_LibraryLoader",
        "Win32_System_Memory",
        "Win32_System_SystemInformation",
        "Win32_System_SystemServices"
      ]
    }
  }
}
export { manifest }
