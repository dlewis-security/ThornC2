// Rust PE Stager — StagerHandler
// The compiled stager is produced by the builder tool (builder/build-a-backdoor.py).
// This handler serves the main.rs source for reference.
import fs from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'
const __dirname = dirname(fileURLToPath(import.meta.url))

export class StagerHandler {
  constructor(stager) {
    this.stager = stager
  }
  generateStager = async function (req, res) {
    fs.readFile(__dirname + '/main.rs', 'utf8', function (err, code) {
      res.send(code)
    })
  }
}
