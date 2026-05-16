const manifest = {
  "title": "Evasive Sleep (WaitForSingleObject)",
  "component_type": "sleep",
  "author": "ph3eds",
  "description": "Callstack-spoofed sleep via WaitForSingleObject(NtCurrentProcess). Allocates a clean stack, JMPs through a kernel32 gadget so no stomped-module frames appear during sleep. DR registers saved/cleared before sleep and restored after to defeat HSB hardware-breakpoint detection. Falls back to direct call if gadget scan fails.",
  "mitre": [
    "T1497.003"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1497/003/",
    "https://github.com/thefLink/Hunt-Sleeping-Beacons"
  ],
  "parameters": [],
  "cargo_deps": {
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_Foundation",
        "Win32_System_LibraryLoader",
        "Win32_System_Threading"
      ]
    }
  }
}
export { manifest }
