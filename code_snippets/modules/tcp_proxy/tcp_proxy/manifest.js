 const manifest = {
  "title": "TCP Port Forwarding Proxy",
  "task_type": "tcp_proxy",
  "author": "ph3eds",
  "description": "Binds a local port on the C2 server, and directs traffic on that port to a designated destination host and port. Similar to ssh -L.",
  "parameters":[
   {
      "name": "lport",
      "placeholder": "{{LPORT}}",
      "type": "",
      "description": "Local proxy port to bind",
      "default": "1080"
    },
   {
      "name": "rhost",
      "placeholder": "{{RHOST}}",
      "type": "",
      "description": "Remote host to target",
      "default": ""
    },
   {
      "name": "rport",
      "placeholder": "{{RPORT}}",
      "type": "",
      "description": "Remote port to target",
      "default": ""
    }
  ]
}
export {manifest}
