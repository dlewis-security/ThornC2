// logger.js — ThornC2 engagement event logger
//
// Events:
//   RAT_NEW       — first time an implant checks in
//   TASK_QUEUED   — operator dispatched a task to a rat
//   TASK_COMPLETE — implant returned output for a task
//   RAT_KILLED    — operator deleted a rat record

export function init_logger() {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS logs (
      id     TEXT PRIMARY KEY,
      ts     INTEGER,
      event  TEXT,
      msg    TEXT,
      rat_id TEXT,
      imp_id TEXT,
      detail TEXT
    )
  `).run()
  // Migrate existing installs that pre-date the imp_id column
  try { db.prepare(`ALTER TABLE logs ADD COLUMN imp_id TEXT`).run() } catch (_) {}
  db.prepare(`CREATE INDEX IF NOT EXISTS logs_ts     ON logs(ts)`).run()
  db.prepare(`CREATE INDEX IF NOT EXISTS logs_rat_id ON logs(rat_id)`).run()
  db.prepare(`CREATE INDEX IF NOT EXISTS logs_imp_id ON logs(imp_id)`).run()
}

export function log_event(event, msg, rat_id = null, imp_id = null, detail = {}) {
  const id = Math.random().toString(36).slice(2).substring(0, 8)
  db.prepare(`
    INSERT INTO logs (id, ts, event, msg, rat_id, imp_id, detail)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, Date.now(), event, msg, rat_id ?? null, imp_id ?? null, JSON.stringify(detail))
}
