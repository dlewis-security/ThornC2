const manifest = {
  "title": "Anti-Sandbox (API Hammering)",
  "component_type": "evasion",
  "author": "ph3eds",
  "description": "Burns sandbox analysis time at startup via repeated temp-file I/O and CPU-bound prime calculation. Sandboxes with short analysis windows detonate the payload before meaningful behaviour is observed.",
  "mitre": [
    "T1497.003"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1497/003/"
  ],
  "parameters": [],
  "cargo_deps": {
    "rand": "0.8"
  }
}
export { manifest }
