const manifest = {
  "title": "Rust PE Stager — ThornLDR-Style (no_std, no CRT)",
  "file_type": "exe",
  "payload_type": "Rust",
  "author": "ph3eds",
  "description": "A tiny no_std, no-main-CRT Rust PE stager modeled on the thornldr reflective loader. Avoids Rust std (no backtrace machinery, no /rustc/ library paths, no mingw CRT startup) and resolves all Win32 APIs at runtime via PEB walk + DJB2 export hashing — no IAT imports beyond what the loader needs. Finds a THORNPLD blob inside a user-dropped ZIP, decrypts it with a modular crypto trait (AES-256-CBC baseline), enumerates running processes, picks a best-match injection target, and maps shellcode via NtCreateSection + NtMapViewOfSection (shared mapping, no cross-process write). Designed to shrink the static feature surface that Elastic ProtectionML keys on when fingerprinting standard Rust executables.",
  "mitre": [
    "T1055.012",
    "T1057"
  ],
  "references": [],
  "parameters": [],
  "uses_crypto": true,
  "uses_inject": true,
  "cargo_deps": {},
  "cargo_build_deps": {
    "winresource": "0.1"
  }
}
export { manifest }
