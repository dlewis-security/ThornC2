// Evasive Sleep — ComponentHandler
import fs from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'
const __dirname = dirname(fileURLToPath(import.meta.url))

export class ComponentHandler {
  constructor(component) {
    this.component = component
  }
  generateComponent = async function (req, res) {
    fs.readFile(__dirname + '/sleep.rs', 'utf8', function (err, code) {
      res.send(code)
    })
  }
}
