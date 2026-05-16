const manifest = {
  "title": "Section Map (NtCreateSection + NtMapViewOfSection)",
  "component_type": "stager_inject",
  "description": "Page-file-backed shared RWX section. Map the section RW into our own process, memcpy shellcode, remap RX into the target, then NtCreateThreadEx at the remote view. No cross-process WriteProcessMemory. Lowest friction, but produces an unbacked RX region in the target which Elastic's Memory Threat Prevention and PE-sieve classify as suspicious.",
  "cargo_deps": {}
}
export { manifest }
