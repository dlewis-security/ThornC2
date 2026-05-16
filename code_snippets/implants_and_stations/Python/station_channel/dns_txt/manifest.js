const manifest = {
  "title": "DNS TXT Station Channel",
  "component_type": "station_channel",
  "author": "ph3eds",
  "description": "DNS TXT-based station channel. Mirrors the Rust dns_txt implant channel. Listens on UDP/53 and handles three query types: c.<rat_hex>.<domain> (check-in), s.<seq>.<chunk>.<sess>.<domain> (output chunk), e.<total>.<sess>.<domain> (end marker / forward to Thorn). Requires dnslib: pip install dnslib. Must run as root or with CAP_NET_BIND_SERVICE for port 53.",
  "mitre": [
    "T1071.004"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1071/004/"
  ],
  "parameters": [
    {
      "name": "c2_server",
      "placeholder": "{{C2_SERVER}}",
      "type": "",
      "description": "Thorn API base URL (e.g. http://127.0.0.1:1337)",
      "default": ""
    },
    {
      "name": "dns_domain",
      "placeholder": "{{DNS_DOMAIN}}",
      "type": "",
      "description": "Authoritative DNS domain this station handles (e.g. c2.example.com). Must match the domain set in the implant build config URL field.",
      "default": ""
    }
  ]
}
export { manifest }
