//Base64 'crypto' demo stub  Component Handler
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
    fs.readFile(__dirname + '/python_shell.py', 'utf8',  function(err, code){
      res.send(code)
    })
  }
}

