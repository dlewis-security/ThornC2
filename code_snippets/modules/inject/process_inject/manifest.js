const manifest = {
  "title": "Process Inject",
  "task_type": "process_inject",
  "description": "Inject AES-256-CBC encrypted shellcode into a remote process. Supports three techniques: section_map (shared mapping, no cross-process write), module_stomp (xpsservices.dll .text overwrite, MEM_IMAGE backing), classic (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread).",
  "parameters": [
    {
      "name": "method",
      "description": "Injection technique: section_map, module_stomp, or classic"
    },
    {
      "name": "pid",
      "description": "Target process ID"
    },
    {
      "name": "payload",
      "description": "AES-256-CBC encrypted shellcode, base64-encoded (set by CLI)"
    }
  ]
}
export { manifest }
