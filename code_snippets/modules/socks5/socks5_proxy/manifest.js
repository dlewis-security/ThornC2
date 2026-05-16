const manifest = {
  "title": "SOCKS5 Proxy",
  "task_type": "socks5_proxy",
  "author": "ph3eds",
  "description": "Tunnel TCP traffic through the implant via SOCKS5. The station runs a SOCKS5 listener; proxychains or similar tools connect to it. Data is multiplexed through the HTTP beacon channel.",
  "parameters": [
    {
      "name": "port",
      "placeholder": "{{PORT}}",
      "type": "string",
      "description": "Local SOCKS5 listener port on the station",
      "default": "1080"
    }
  ]
}
export { manifest }
