const manifest = {
  "title": "PowerShell (In-Process CLR)",
  "component_type": "execution",
  "author": "ph3eds",
  "description": "Runs operator commands via a hosted CLR in the implant process using rustclr. No powershell.exe child process is spawned. Before each command, disables AMSI by nulling amsiContext/amsiSession via CLR reflection with Unicode normalization obfuscation — avoids AmsiRegistrationProtection. Pair with the 'ETW Patch + NTDLL Unhook' evasion component.",
  "mitre": [
    "T1059.001",
    "T1055"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1059/001/",
    "https://github.com/joaoviictorti/rustclr"
  ],
  "parameters": [],
  "cargo_deps": {
    "rustclr": "0.3.4",
    "base64": "0.22",
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_Foundation",
        "Win32_System_Diagnostics_ToolHelp",
        "Win32_Security",
        "Win32_System_Threading",
        "Win32_System_Memory",
        "Win32_System_LibraryLoader",
        "Win32_Networking_WinHttp"
      ]
    }
  }
}
export { manifest }
