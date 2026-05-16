// DNS TXT Station Channel — ComponentHandler
import fs from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'
const __dirname = dirname(fileURLToPath(import.meta.url))

export class ComponentHandler {
  constructor(component) {
    this.component = component
  }
  generateComponent = async function (req, res) {
    let c2_server  = this.component.parameters.c2_server
    let dns_domain = this.component.parameters.dns_domain
    fs.readFile(__dirname + '/dns.py', 'utf8', function (err, code) {
      code = code.replace(/{{C2_SERVER}}/g,  c2_server)
      code = code.replace(/{{DNS_DOMAIN}}/g, dns_domain)
      res.send(code)
    })
  }
}
