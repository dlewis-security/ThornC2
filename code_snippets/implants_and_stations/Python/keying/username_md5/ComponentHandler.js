//HTTP Demo Channel Component Handler
import fs from 'fs'
import crypto from 'crypto'
import { dirname } from 'path';
import { fileURLToPath } from 'url';
const __dirname = dirname(fileURLToPath(import.meta.url));
console.log(__dirname)
export class ComponentHandler {
  constructor(component) {
    this.component = component
  }
  generateComponent = async function (req, res) {
    let username = this.component.parameters.username
    username = crypto.createHash('md5').update(username).digest("hex")
    let station = this.component.parameters.station
    fs.readFile(__dirname + '/username_md5.py', 'utf8',  function(err, code){
      code = code.replace('{{USERNAME}}', username)
      code = code.replace('{{STATION}}', Buffer.from(station).toString('base64'))
      res.send(code)
    })
  }
}

