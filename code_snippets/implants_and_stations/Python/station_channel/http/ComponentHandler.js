//HTTP Demo Channel Component Handler
import fs from 'fs'
import { dirname } from 'path';
import { fileURLToPath } from 'url';
const __dirname = dirname(fileURLToPath(import.meta.url));
export class ComponentHandler {
  constructor(component) {
    this.component = component
  }
  generateComponent = async function (req, res) {
    let c2_server = this.component.parameters.c2_server
    fs.readFile(__dirname + '/http.py', 'utf8',  function(err, code){
      code = code.replace(/{{C2_SERVER}}/g, c2_server)
      res.send(code)
    })
  }
}

