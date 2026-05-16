//AES-256 crypto stub Component Handler
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
    let key = this.component.parameters.key
    let iv = this.component.parameters.iv
    fs.readFile(__dirname + '/aes-256.ps1', 'utf8',  function(err, code){
		code = code.replace(/{{KEY}}/g, key)
		code = code.replace(/{{IV}}/g, iv)
		res.send(code)
    })
  }
}

