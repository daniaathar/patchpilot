/**
 * server/routes.js
 * All API route handlers for PatchPilot.
 * Owner: Rida
 *
 * Mounted at /api in app.js.
 */

'use strict';

const express = require('express');
const bcrypt  = require('bcrypt');
const multer  = require('multer');
const path    = require('path');

const { getDb, loadConfig, nextFindingId } = require('./db');
const { audit }                            = require('./audit');
const { requireAuth, requireRole }         = require('./auth');
const engine                               = require('./engine');

const router = express.Router();

// ── Multer configuration: memory storage, .csv/.json only, max 1 MB ──────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 1 * 1024 * 1024 }, // 1 MB
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext === '.csv' || ext === '.json') {
      cb(null, true);
    } else {
      const err = new Error(`Only .csv and .json files are allowed (got '${ext}').`);
      err.code = 'E_VALIDATION';
      cb(err, false);
    }
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/login
router.post('/login', async (req, res, next) => {
  const db = getDb();
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'E_VALIDATION', message: 'Username and password are required.' });
  }

  try {
    const user = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);

    // Always run bcrypt compare (even on miss) to prevent timing attacks
    const hash   = user ? user.password_hash : '$2b$12$invalidhashfortimingattackprevention';
    const match  = await bcrypt.compare(password, hash);

    if (!user || !match) {
      audit('login', username, 'failure', { reason: 'Invalid credentials' }, db);
      return res.status(401).json({ error: 'E_AUTH', message: 'Invalid username or password.' });
    }

    // Regenerate session to prevent session fixation
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.user = { id: user.id, username: user.username, role: user.role };
      audit('login', user.username, 'success', { role: user.role }, db);
      res.json({ message: 'Logged in.', role: user.role, username: user.username });
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/logout
router.post('/logout', requireAuth, (req, res, next) => {
  const db   = getDb();
  const user = req.session.user;

  audit('logout', user.username, 'success', {}, db);

  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('patchpilot.sid');
    res.json({ message: 'Logged out.' });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// IMPORT
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/import
router.post('/import', requireAuth, requireRole('analyst', 'admin'),
  upload.single('file'),
  (req, res, next) => {
    const db   = getDb();
    const user = req.session.user;

    if (!req.file) {
      return res.status(400).json({ error: 'E_VALIDATION', message: 'No file uploaded.' });
    }

    const ext  = path.extname(req.file.originalname).toLowerCase().slice(1); // 'csv' or 'json'
    const text = req.file.buffer.toString('utf8');

    // Parse and validate with Hareem's engine
    const { valid, errors } = engine.parseImport(text, ext);

    if (valid.length === 0 && errors.length > 0) {
      audit('import', user.username, 'failure',
        { file: req.file.originalname, errorCount: errors.length, firstError: errors[0] }, db);
      return res.status(400).json({ error: 'E_VALIDATION', message: 'File rejected.', errors });
    }

    // Deduplication against existing findings
    const existing = db.prepare(`SELECT * FROM findings`).all().map(dbRowToFinding);
    const originalFirstSeen = new Map(existing.map(f => [f.id, f.firstSeen]));
    const { unique, duplicates } = engine.dedupe(valid, existing);

    const config = loadConfig(db);
    const now    = new Date().toISOString();

    // dedupe() keeps the OLDEST firstSeen on the existing record (FR-2).
    // Persist that change (and the matching new deadline) to the database.
    for (const f of existing) {
      if (f.firstSeen !== originalFirstSeen.get(f.id)) {
        f.dueDate = engine.calcSla(f, config, now).dueDate;
        db.prepare(`UPDATE findings SET firstSeen = ?, dueDate = ? WHERE id = ?`)
          .run(f.firstSeen, f.dueDate, f.id);
      }
    }

    // Score + SLA + owner for each unique finding, then insert
    const inserted = [];
    const insertStmt = db.prepare(`
      INSERT INTO findings
        (id, title, cve, cvss, asset, assetCriticality, internetFacing,
         scanner, firstSeen, status, priorityScore, priority, dueDate,
         owner, reasons, history)
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const scoreConfig = engine.buildScoreConfig(config);

    const insertMany = db.transaction((findings) => {
      for (const f of findings) {
        const scored  = engine.scoreFinding(f, scoreConfig);
        f.priorityScore = scored.score;
        f.priority      = scored.priority;
        f.reasons       = scored.reasons;

        const sla = engine.calcSla(f, config, now);
        f.dueDate = sla.dueDate;

        const ownership = engine.assignOwner(f, null);
        f.owner = ownership.owner;

        f.id = nextFindingId(db);

        insertStmt.run(
          f.id, f.title, f.cve, f.cvss, f.asset, f.assetCriticality,
          f.internetFacing ? 1 : 0, f.scanner, f.firstSeen, f.status,
          f.priorityScore, f.priority, f.dueDate, f.owner,
          JSON.stringify(f.reasons), JSON.stringify(f.history)
        );
        inserted.push(f.id);
      }
    });

    insertMany(unique);

    audit('import', user.username, 'success',
      { file: req.file.originalname, inserted: inserted.length, duplicates: duplicates.length, errors: errors.length }, db);

    res.json({
      message:    `Import complete.`,
      inserted:   inserted.length,
      duplicates: duplicates.length,
      errors:     errors.length,
      errorList:  errors
    });
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// FINDINGS
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/findings
router.get('/findings', requireAuth, (req, res) => {
  const db   = getDb();
  const user = req.session.user;
  const rows = db.prepare(`SELECT * FROM findings ORDER BY priorityScore DESC`).all();
  const findings = rows.map(r => toFindingView(dbRowToFinding(r), user.role));
  res.json(findings);
});

// GET /api/findings/:id
router.get('/findings/:id', requireAuth, (req, res) => {
  const db   = getDb();
  const user = req.session.user;
  const row  = db.prepare(`SELECT * FROM findings WHERE id = ?`).get(req.params.id);
  if (!row) {
    return res.status(404).json({ error: 'E_VALIDATION', message: `Finding '${req.params.id}' not found.` });
  }
  res.json(toFindingView(dbRowToFinding(row), user.role));
});

// POST /api/findings/:id/status
router.post('/findings/:id/status', requireAuth, requireRole('analyst', 'admin'), (req, res) => {
  const db     = getDb();
  const user   = req.session.user;
  const row    = db.prepare(`SELECT * FROM findings WHERE id = ?`).get(req.params.id);

  if (!row) {
    return res.status(404).json({ error: 'E_VALIDATION', message: `Finding '${req.params.id}' not found.` });
  }

  const finding = dbRowToFinding(row);
  const { action, reason, endDate } = req.body || {};

  const result = engine.changeStatus(
    finding, action,
    { reason, endDate, user: user.username },
    user.role
  );

  if (result.error) {
    return res.status(result.error === 'E_FORBIDDEN' ? 403 : 400).json({
      error:   result.error,
      message: result.message
    });
  }

  // Append event to history
  const history = finding.history || [];
  history.push(result.event);

  db.prepare(`
    UPDATE findings SET status = ?, history = ? WHERE id = ?
  `).run(result.finding.status, JSON.stringify(history), req.params.id);

  audit('status_change', user.username, 'success',
    { findingId: req.params.id, action, newStatus: result.finding.status }, db);

  res.json({ message: 'Status updated.', finding: result.finding, event: result.event });
});

// POST /api/findings/:id/retest
router.post('/findings/:id/retest', requireAuth, requireRole('analyst', 'admin'), (req, res) => {
  const db    = getDb();
  const user  = req.session.user;
  const row   = db.prepare(`SELECT * FROM findings WHERE id = ?`).get(req.params.id);

  if (!row) {
    return res.status(404).json({ error: 'E_VALIDATION', message: `Finding '${req.params.id}' not found.` });
  }

  const finding  = dbRowToFinding(row);
  const { result, evidence } = req.body || {};

  if (!result || !evidence) {
    return res.status(400).json({ error: 'E_VALIDATION', message: 'result (pass/fail) and evidence are required.' });
  }

  const retestResult = engine.handleRetest(finding, result, evidence);

  if (retestResult.error) {
    return res.status(400).json({ error: retestResult.error, message: retestResult.message });
  }

  // Update finding in DB
  const history = finding.history || [];
  history.push({
    action:   `retest_${result}`,
    user:     user.username,
    time:     new Date().toISOString(),
    note:     retestResult.reason
  });

  db.prepare(`
    UPDATE findings SET status = ?, dueDate = ?, history = ? WHERE id = ?
  `).run(retestResult.status, retestResult.newDueDate || finding.dueDate,
         JSON.stringify(history), req.params.id);

  audit('retest', user.username, 'success',
    { findingId: req.params.id, result, newStatus: retestResult.status }, db);

  res.json({ message: 'Retest recorded.', status: retestResult.status, reason: retestResult.reason });
});

// ─────────────────────────────────────────────────────────────────────────────
// METRICS
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/metrics
router.get('/metrics', requireAuth, (req, res) => {
  const db       = getDb();
  const findings = db.prepare(`SELECT * FROM findings`).all().map(dbRowToFinding);
  const metrics  = engine.computeMetrics(findings, new Date().toISOString());
  res.json(metrics);
});

// ─────────────────────────────────────────────────────────────────────────────
// AUDIT LOG (admin only)
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/audit
router.get('/audit', requireAuth, requireRole('admin'), (req, res) => {
  const db   = getDb();
  const rows = db.prepare(`SELECT * FROM audit_log ORDER BY id DESC LIMIT 500`).all();
  res.json(rows.map(r => ({
    id:      r.id,
    time:    r.time,
    user:    r.user,
    action:  r.action,
    result:  r.result,
    details: safeParseJson(r.details)
  })));
});

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG (admin only)
// ─────────────────────────────────────────────────────────────────────────────

// PUT /api/config
router.put('/config', requireAuth, requireRole('admin'), (req, res) => {
  const db   = getDb();
  const user = req.session.user;
  const body = req.body || {};

  const ALLOWED_KEYS = [
    'cvssMultiplier', 'assetPoints_low', 'assetPoints_medium',
    'assetPoints_high', 'assetPoints_critical', 'internetFacingBonus',
    'sla_critical', 'sla_high', 'sla_medium', 'sla_low'
  ];

  // Validate EVERYTHING first so a bad value never causes a partial update
  const toWrite = [];
  for (const key of ALLOWED_KEYS) {
    if (body[key] === undefined) continue;
    const val = String(body[key]).trim();
    const num = Number(val);
    if (val === '' || !Number.isFinite(num) || num < 0) {
      return res.status(400).json({ error: 'E_VALIDATION', message: `Config value for '${key}' must be a number that is 0 or more.` });
    }
    if (key.startsWith('sla_') && (!Number.isInteger(num) || num < 1)) {
      return res.status(400).json({ error: 'E_VALIDATION', message: `Config value for '${key}' must be a whole number of days (1 or more).` });
    }
    toWrite.push([key, val]);
  }

  const stmt = db.prepare(`UPDATE config SET value = ? WHERE key = ?`);
  const updated = [];
  for (const [key, val] of toWrite) {
    stmt.run(val, key);
    updated.push(key);
  }

  // Re-run scoring + deadlines on existing active findings so the new rules
  // take effect immediately (demo step: change Critical SLA 7 -> 5 days).
  const recalculated = recalculateFindings(db);

  audit('config_change', user.username, 'success', { updated, newValues: body, recalculated }, db);
  res.json({ message: 'Config updated.', updated, recalculated });
});

// ─────────────────────────────────────────────────────────────────────────────
// EXPORT
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/export
router.get('/export', requireAuth, requireRole('analyst', 'admin'), (req, res) => {
  const db   = getDb();
  const user = req.session.user;
  const rows = db.prepare(`SELECT * FROM findings ORDER BY priorityScore DESC`).all();

  // Build CSV – sanitise each cell to prevent formula injection
  const headers = ['id','title','cve','cvss','asset','assetCriticality',
                   'internetFacing','scanner','firstSeen','status',
                   'priorityScore','priority','dueDate','owner'];

  function csvCell(val) {
    const s = String(val == null ? '' : val);
    // Strip leading formula chars
    const clean = s.replace(/^[=+\-@]+/, '');
    // Wrap in quotes if it contains commas/quotes/newlines
    if (/[,"\n\r]/.test(clean)) return `"${clean.replace(/"/g, '""')}"`;
    return clean;
  }

  const lines = [headers.join(',')];
  for (const row of rows) {
    lines.push(headers.map(h => csvCell(row[h])).join(','));
  }

  audit('export', user.username, 'success', { rowCount: rows.length }, db);

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="patchpilot-export.csv"');
  res.send(lines.join('\n'));
});

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Re-applies the current config to existing findings.
 *  - open / in_progress / reopened: score, priority and reasons are recomputed.
 *  - open / in_progress: deadline is recomputed (reopened keeps its retest deadline).
 *  - fixed / accepted_risk / false_positive: left untouched.
 * Returns the number of findings updated.
 */
function recalculateFindings(db) {
  const config      = loadConfig(db);
  const scoreConfig = engine.buildScoreConfig(config);
  const now         = new Date().toISOString();
  const rows        = db.prepare(
    `SELECT * FROM findings WHERE status IN ('open','in_progress','reopened')`
  ).all();

  const update = db.prepare(
    `UPDATE findings SET priorityScore = ?, priority = ?, reasons = ?, dueDate = ? WHERE id = ?`
  );

  const run = db.transaction(() => {
    for (const row of rows) {
      const f      = dbRowToFinding(row);
      const scored = engine.scoreFinding(f, scoreConfig);
      f.priorityScore = scored.score;
      f.priority      = scored.priority;
      f.reasons       = scored.reasons;
      let due = f.dueDate;
      if (f.status !== 'reopened') due = engine.calcSla(f, config, now).dueDate;
      update.run(f.priorityScore, f.priority, JSON.stringify(f.reasons), due, f.id);
    }
  });
  run();
  return rows.length;
}

/** Converts a raw SQLite row to a Finding object. */
function dbRowToFinding(row) {
  return {
    id:              row.id,
    title:           row.title,
    cve:             row.cve,
    cvss:            row.cvss,
    asset:           row.asset,
    assetCriticality:row.assetCriticality,
    internetFacing:  row.internetFacing === 1 || row.internetFacing === true,
    scanner:         row.scanner,
    firstSeen:       row.firstSeen,
    status:          row.status,
    priorityScore:   row.priorityScore,
    priority:        row.priority,
    dueDate:         row.dueDate,
    owner:           row.owner,
    reasons:         safeParseJson(row.reasons, []),
    history:         safeParseJson(row.history, [])
  };
}

/**
 * Returns a viewer-safe version of a finding.
 * Viewer role cannot see reasons or history.
 */
function toFindingView(finding, role) {
  if (role === 'viewer') {
    const { reasons, history, ...limited } = finding; // eslint-disable-line no-unused-vars
    return limited;
  }
  return finding;
}

function safeParseJson(str, fallback) {
  try { return JSON.parse(str); }
  catch (_) { return fallback !== undefined ? fallback : null; }
}

module.exports = router;
