const manifest = {
  "title": "Rust PE Stager — Dynamic Inject (Section Mapped)",
  "file_type": "exe",
  "payload_type": "Rust",
  "author": "ph3eds",
  "description": "Enumerates running processes at runtime and selects the best injection target from a priority-ordered candidate list baked into the config at build time. Filters candidates by session (same logon session), architecture (x64 only), and open access. Injects via NtCreateSection + NtMapViewOfSection shared mapping — shellcode is written locally (no cross-process NtWriteVirtualMemory), then mapped RX into the target. No PPID spoofing, no process spawning. LoadLibraryA and GetProcAddress are resolved via PEB walk + export hash (no kernel32 imports in the IAT), defeating static malware-ML classifiers. Designed to evade Elastic EDR behavioral detections (remote memory write, PPID spoofing, suspicious parent-child) AND static file classification. Never RWX in the target.",
  "mitre": [
    "T1055.012",
    "T1057"
  ],
  "references": [],
  "parameters": [],
  "cargo_deps": {
    "aes": "0.8",
    "cbc": "0.1"
  },
  "cargo_build_deps": {
    "winresource": "0.1"
  }
}
export { manifest }
