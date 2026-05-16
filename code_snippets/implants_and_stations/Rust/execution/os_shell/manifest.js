const manifest = {
  "title": "OS Shell (cmd.exe)",
  "component_type": "execution",
  "author": "ph3eds",
  "description": "Executes commands via cmd.exe /c, capturing combined stdout/stderr. CREATE_NO_WINDOW suppresses console visibility.",
  "mitre": [
    "T1059.003"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1059/003/"
  ],
  "parameters": [],
  "cargo_deps": {
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_Foundation",
        "Win32_Networking_WinHttp",
        "Win32_Security",
        "Win32_System_Diagnostics_ToolHelp",
        "Win32_System_LibraryLoader",
        "Win32_System_Memory",
        "Win32_System_Threading"
      ]
    }
  }
}
export { manifest }
