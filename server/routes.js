'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');

const {
  getDb,
  loadConfig,
  nextFindingId
} = require('./db');

const { audit } = require('./audit');
const { requireAuth, requireRole } = require('./auth');
const engine = require('./engine');

const router = express.Router();

router.use((req, res, next) => {
  if (!req.session?.user) return next();
  const db = getDb();
  const today = new Date().toISOString().slice(0,10);
  const expire = db.transaction(() => {
    for (const row of db.prepare("SELECT * FROM findings WHERE status='accepted_risk' AND (endDate IS NULL OR endDate <= ?)").all(today)) {
      const history = safeParseJson(row.history, []);
      history.push({action:'risk_expired', user:'system', time:new Date().toISOString(), note:'Risk acceptance expired or legacy expiry was not recorded.'});
      db.prepare("UPDATE findings SET status='reopened',endDate=NULL,history=? WHERE id=?").run(JSON.stringify(history), row.id);
      audit('risk_expired','system','success',{findingId:row.id},db);
    }
  });
  try { expire(); next(); } catch(err) { next(err); }
});

/* ================= FILE UPLOAD ================= */

const upload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 1024 * 1024
  },

  fileFilter: (req, file, cb) => {
    const ext = path.extname(
      file.originalname
    ).toLowerCase();

    if (ext === '.csv' || ext === '.json') {
      cb(null, true);
    } else {
      const err = new Error(
        'Only CSV and JSON files are allowed.'
      );

      err.code = 'E_VALIDATION';

      cb(err, false);
    }
  }
});

/* ================= AUTHENTICATION ================= */

// POST /api/login

router.post('/login', async (req, res, next) => {
  const db = getDb();

  const { username, password } = req.body || {};

  if (
    typeof username !== 'string' ||
    typeof password !== 'string' ||
    !username ||
    !password
  ) {
    return res.status(400).json({
      error: 'E_VALIDATION',
      message: 'Username and password are required.'
    });
  }

  try {
    const user = db.prepare(`
      SELECT * FROM users
      WHERE username = ?
    `).get(username);

    const hash = user
      ? user.password_hash
      : '$2b$12$invalidhashfortimingattackprevention';

    const match = await bcrypt.compare(
      password,
      hash
    );

    if (!user || !match) {
      audit(
        'login',
        username,
        'failure',
        {
          reason: 'Invalid credentials'
        },
        db
      );

      return res.status(401).json({
        error: 'E_AUTH',
        message: 'Invalid username or password.'
      });
    }

    req.session.regenerate(err => {
      if (err) return next(err);

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };

      audit(
        'login',
        user.username,
        'success',
        {
          role: user.role
        },
        db
      );

      res.json({
        message: 'Logged in.',
        role: user.role,
        username: user.username
      });
    });

  } catch (err) {
    next(err);
  }
});

// POST /api/logout

router.post(
  '/logout',
  requireAuth,
  (req, res, next) => {
    const db = getDb();
    const user = req.session.user;

    audit(
      'logout',
      user.username,
      'success',
      {},
      db
    );

    req.session.destroy(err => {
      if (err) return next(err);

      res.clearCookie('patchpilot.sid');

      res.json({
        message: 'Logged out.'
      });
    });
  }
);

/* ================= IMPORT ================= */

// POST /api/import

router.post(
  '/import',
  requireAuth,
  requireRole('analyst', 'admin'),
  upload.single('file'),

  (req, res, next) => {
    const db = getDb();
    const user = req.session.user;

    try {
      if (!req.file) {
        return res.status(400).json({
          error: 'E_VALIDATION',
          message: 'No file uploaded.'
        });
      }

      const ext = path
        .extname(req.file.originalname)
        .toLowerCase()
        .slice(1);

      const text = req.file.buffer.toString('utf8');

      const { valid, errors } =
        engine.parseImport(text, ext);

      if (errors.length > 0) {
        audit(
          'import',
          user.username,
          'failure',
          {
            file: req.file.originalname,
            errorCount: errors.length,
            firstError: errors[0]
          },
          db
        );

        return res.status(400).json({
          error: 'E_VALIDATION',
          message: 'File rejected.',
          errors
        });
      }

      const existing = db.prepare(`
        SELECT * FROM findings
      `).all().map(dbRowToFinding);

      const originalFirstSeen = new Map(
        existing.map(f => [
          f.id,
          f.firstSeen
        ])
      );

      const { unique, duplicates } =
        engine.dedupe(valid, existing);

      const config = loadConfig(db);
      const now = new Date().toISOString();

      for (const f of existing) {
        if (
          f.firstSeen !==
          originalFirstSeen.get(f.id)
        ) {
          if (['open','in_progress','reopened','awaiting_retest'].includes(f.status) && !f.slaStart) f.dueDate = engine.calcSla(f, config, now).dueDate;

          db.prepare(`
            UPDATE findings
            SET firstSeen = ?, dueDate = ?
            WHERE id = ?
          `).run(
            f.firstSeen,
            f.dueDate,
            f.id
          );
        }
      }

      const inserted = [];

      const insertStmt = db.prepare(`
        INSERT INTO findings (
          id,
          title,
          cve,
          cvss,
          asset,
          assetCriticality,
          internetFacing,
          scanner,
          firstSeen,
          status,
          priorityScore,
          priority,
          dueDate,
          owner,
          reasons,
          history, scoreConfig
        )
        VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
      `);

      const scoreConfig =
        engine.buildScoreConfig(config);

      const insertMany = db.transaction(findings => {
        for (const f of findings) {

          const scored = engine.scoreFinding(
            f,
            scoreConfig
          );

          f.priorityScore = scored.score;
          f.priority = scored.priority;
          f.reasons = scored.reasons;

          const sla = engine.calcSla(
            f,
            config,
            now
          );

          f.dueDate = sla.dueDate;

          const ownership = engine.assignOwner(f);

          f.owner = ownership.owner;

          f.id = nextFindingId(db);

          insertStmt.run(
            f.id,
            f.title,
            f.cve,
            f.cvss,
            f.asset,
            f.assetCriticality,
            f.internetFacing ? 1 : 0,
            f.scanner,
            f.firstSeen,
            f.status,
            f.priorityScore,
            f.priority,
            f.dueDate,
            f.owner,
            JSON.stringify(f.reasons),
            JSON.stringify(f.history || []),
            JSON.stringify(scoreConfig)
          );

          inserted.push(f.id);
        }
      });

      insertMany(unique);

      audit(
        'import',
        user.username,
        'success',
        {
          file: req.file.originalname,
          inserted: inserted.length,
          duplicates: duplicates.length,
          errors: errors.length
        },
        db
      );

      res.json({
        message: 'Import complete.',
        inserted: inserted.length,
        duplicates: duplicates.length,
        duplicateDetails: duplicates.map(d => ({ finding: {cve:d.finding.cve, asset:d.finding.asset}, matchedId:d.matchedId, reason:d.reason })),
        errors: errors.length,
        errorList: errors
      });

    } catch (err) {
      next(err);
    }
  }
);

/* ================= FINDINGS ================= */

// GET /api/findings

router.get(
  '/findings',
  requireAuth,
  (req, res) => {
    const db = getDb();
    const user = req.session.user;

    const rows = db.prepare(`
      SELECT * FROM findings
      ORDER BY priorityScore DESC
    `).all();

    const findings = rows.map(row =>
      toFindingView(
        dbRowToFinding(row),
        user.role
      )
    );

    res.json(findings);
  }
);

// GET /api/findings/:id

router.get(
  '/findings/:id',
  requireAuth,

  (req, res) => {
    const db = getDb();
    const user = req.session.user;

    const row = db.prepare(`
      SELECT * FROM findings
      WHERE id = ?
    `).get(req.params.id);

    if (!row) {
      return res.status(404).json({
        error: 'E_VALIDATION',
        message: 'Finding not found.'
      });
    }

    res.json(
      toFindingView(
        dbRowToFinding(row),
        user.role
      )
    );
  }
);

/* ================= STATUS UPDATES ================= */

// POST /api/findings/:id/status

router.post(
  '/findings/:id/status',

  requireAuth,

  requireRole('analyst', 'admin'),

  (req, res) => {
    const db = getDb();
    const user = req.session.user;

    const row = db.prepare(`
      SELECT * FROM findings
      WHERE id = ?
    `).get(req.params.id);

    if (!row) {
      return res.status(404).json({
        error: 'E_VALIDATION',
        message: 'Finding not found.'
      });
    }

    const finding = dbRowToFinding(row);

    const {
      action,
      reason,
      endDate
    } = req.body || {};

    const updated = engine.changeStatus(
      toEngineFinding(finding),
      action,
      {
        reason,
        endDate
      },
      user.role,
      {
        actorId: String(user.id)
      }
    );

    if (updated.error) {
      audit(updated.error === 'E_FORBIDDEN' ? 'access_denied' : 'status_change', user.username, 'denied', {findingId:req.params.id, reason:updated.error}, db);
      return res.status(
        updated.error === 'E_FORBIDDEN'
          ? 403
          : 400
      ).json({
        error: updated.error,
        message: updated.message
      });
    }

    const events = updated.events || [];

    const event = events[events.length - 1];

    db.prepare(`
      UPDATE findings
      SET status = ?, history = ?, fixedAt = ?, endDate = ?
      WHERE id = ?
    `).run(
      updated.status,
      JSON.stringify(events),
      updated.fixedAt || null,
      updated.endDate || null,
      req.params.id
    );

    audit(
      'status_change',
      user.username,
      'success',
      {
        findingId: req.params.id,
        action,
        newStatus: updated.status
      },
      db
    );

    res.json({
      message: 'Status updated.',
      finding: fromEngineFinding(updated),
      event
    });
  }
);

/* ================= RETEST ================= */

// POST /api/findings/:id/retest

router.post(
  '/findings/:id/retest',

  requireAuth,

  requireRole('analyst', 'admin'),

  (req, res) => {
    const db = getDb();
    const user = req.session.user;

    const row = db.prepare(`
      SELECT * FROM findings
      WHERE id = ?
    `).get(req.params.id);

    if (!row) {
      return res.status(404).json({
        error: 'E_VALIDATION',
        message: 'Finding not found.'
      });
    }

    const finding = dbRowToFinding(row);

    const {
      result,
      evidence
    } = req.body || {};

    if (
      !['pass', 'fail'].includes(result) ||
      typeof evidence !== 'string' ||
      !evidence.trim() ||
      evidence.trim().length > 500
    ) {
      return res.status(400).json({
        error: 'E_VALIDATION',
        message: 'Valid retest result and evidence are required.'
      });
    }

    const updated = engine.handleRetest(
      toEngineFinding(finding),
      result,
      evidence.trim(),
      new Date(),
      loadConfig(db)
    );

    if (updated.error) {
      audit('retest',user.username,'failure',{findingId:req.params.id,reason:updated.error},db);
      return res.status(400).json({
        error: updated.error,
        message: updated.message
      });
    }

    const events = updated.events || [];

    const event = events[events.length - 1];
    if (event) event.user = String(user.id);

    db.prepare(`
      UPDATE findings
      SET status = ?, dueDate = ?, history = ?, fixedAt = ?, slaStart = ?
      WHERE id = ?
    `).run(
      updated.status,
      updated.dueDate || finding.dueDate,
      JSON.stringify(events),
      updated.fixedAt || null,
      updated.slaStart || null,
      req.params.id
    );

    audit(
      'retest',
      user.username,
      'success',
      {
        findingId: req.params.id,
        result,
        newStatus: updated.status
      },
      db
    );

    res.json({
      message: 'Retest recorded.',
      status: updated.status,
      reason: event ? event.note : undefined,
      finding: fromEngineFinding(updated),
      event
    });
  }
);

/* ================= METRICS ================= */

// GET /api/metrics

router.get(
  '/metrics',
  requireAuth,

  (req, res) => {
    const db = getDb();

    const findings = db.prepare(`
      SELECT * FROM findings
    `).all().map(dbRowToFinding);

    const metrics = engine.computeMetrics(
      findings,
      new Date().toISOString()
    );

    res.json(metrics);
  }
);

/* ================= AUDIT LOG ================= */

// GET /api/audit

router.get(
  '/audit',

  requireAuth,

  requireRole('admin'),

  (req, res) => {
    const db = getDb();

    const rows = db.prepare(`
      SELECT * FROM audit_log
      ORDER BY id DESC
      LIMIT 500
    `).all();

    res.json(
      rows.map(r => ({
        id: r.id,
        time: r.time,
        user: r.user,
        action: r.action,
        result: r.result,
        details: safeParseJson(r.details)
      }))
    );
  }
);

/* ================= CONFIGURATION ================= */

const ALLOWED_CONFIG_KEYS = [
  'cvssMultiplier',
  'assetPoints_low',
  'assetPoints_medium',
  'assetPoints_high',
  'assetPoints_critical',
  'internetFacingBonus',
  'sla_critical',
  'sla_high',
  'sla_medium',
  'sla_low'
];

// GET /api/config
// Retrieve actual saved configuration from SQLite.

router.get(
  '/config',

  requireAuth,

  requireRole('admin'),

  (req, res) => {
    const db = getDb();

    const rows = db.prepare(`
      SELECT key, value FROM config
    `).all();

    const config = Object.fromEntries(
      rows.map(row => [
        row.key,
        Number(row.value)
      ])
    );

    res.json({
      slaDays: {
        Critical: config.sla_critical ?? 7,
        High: config.sla_high ?? 14,
        Medium: config.sla_medium ?? 30,
        Low: config.sla_low ?? 90
      },

      weights: {
        cvss: config.cvssMultiplier ?? 6,

        internetFacing:
          config.internetFacingBonus ?? 10,

        assetPoints: {
          low: config.assetPoints_low ?? 0,
          medium: config.assetPoints_medium ?? 10,
          high: config.assetPoints_high ?? 20,
          critical: config.assetPoints_critical ?? 30
        }
      }
    });
  }
);

// PUT /api/config

router.put(
  '/config',

  requireAuth,

  requireRole('admin'),

  (req, res, next) => {
    const db = getDb();
    const user = req.session.user;
    const body = req.body || {};

    try {
      if (
        typeof body !== 'object' ||
        Array.isArray(body)
      ) {
        return res.status(400).json({
          error: 'E_VALIDATION',
          message: 'Invalid configuration format.'
        });
      }

      const keys = Object.keys(body);

      if (!keys.length) {
        return res.status(400).json({
          error: 'E_VALIDATION',
          message: 'No configuration values supplied.'
        });
      }

      const unsupported = keys.filter(
        key => !ALLOWED_CONFIG_KEYS.includes(key)
      );

      if (unsupported.length) {
        return res.status(400).json({
          error: 'E_VALIDATION',
          message: 'Unsupported configuration keys.'
        });
      }

      const toWrite = [];

      for (const key of ALLOWED_CONFIG_KEYS) {
        if (body[key] === undefined) continue;

        if (
          typeof body[key] !== 'number' &&
          typeof body[key] !== 'string'
        ) {
          return res.status(400).json({
            error: 'E_VALIDATION',
            message: `Invalid value for '${key}'.`
          });
        }

        const val = String(body[key]).trim();

        const num = Number(val);

        if (
          val === '' ||
          !Number.isFinite(num) ||
          num < 0
        ) {
          return res.status(400).json({
            error: 'E_VALIDATION',
            message:
              `Config value for '${key}' must be a non-negative number.`
          });
        }

        if (!key.startsWith('sla_') && num > 100) return res.status(400).json({error:'E_VALIDATION',message:'Score weights must be between 0 and 100.'});

        if (
          key.startsWith('sla_') &&
          (
            !Number.isInteger(num) ||
            num < 1 ||
            num > 365
          )
        ) {
          return res.status(400).json({
            error: 'E_VALIDATION',
            message:
              `Config value for '${key}' must be between 1 and 365 whole days.`
          });
        }

        toWrite.push([
          key,
          String(num)
        ]);
      }

      if (!toWrite.length) {
        return res.status(400).json({
          error: 'E_VALIDATION',
          message: 'No valid configuration supplied.'
        });
      }

      const saveConfig = db.transaction(() => {

        const stmt = db.prepare(`
          UPDATE config
          SET value = ?
          WHERE key = ?
        `);

        const updated = [];

        for (const [key, val] of toWrite) {
          const result = stmt.run(val, key);

          if (result.changes !== 1) {
            throw new Error(
              `Configuration key not found: ${key}`
            );
          }

          updated.push(key);
        }

        const recalculated = recalculateFindings(db);

        audit(
          'config_change',
          user.username,
          'success',
          {
            updated,
            newValues: body,
            recalculated
          },
          db
        );

        return {
          updated,
          recalculated
        };
      });

      const result = saveConfig();

      res.json({
        message: 'Config updated.',
        updated: result.updated,
        recalculated: result.recalculated
      });

    } catch (err) {
      next(err);
    }
  }
);

/* ================= CSV EXPORT ================= */

// GET /api/export

router.get(
  '/export',

  requireAuth,

  requireRole('analyst', 'admin'),

  (req, res) => {
    const db = getDb();
    const user = req.session.user;

    const rows = db.prepare(`
      SELECT * FROM findings
      ORDER BY priorityScore DESC
    `).all();

    const headers = [
      'id',
      'title',
      'cve',
      'cvss',
      'asset',
      'assetCriticality',
      'internetFacing',
      'scanner',
      'firstSeen',
      'status',
      'priorityScore',
      'priority',
      'dueDate',
      'owner'
    ];

    function csvCell(val) {
      const s = String(
        val == null ? '' : val
      );

      const clean = s.replace(
        /^[\s]*[=+\-@]+/,
        ''
      );

      if (/[,"\n\r]/.test(clean)) {
        return '"' +
          clean.replace(/"/g, '""') +
          '"';
      }

      return clean;
    }

    const lines = [
      headers.join(',')
    ];

    for (const row of rows) {
      lines.push(
        headers.map(
          h => csvCell(row[h])
        ).join(',')
      );
    }

    audit(
      'export',
      user.username,
      'success',
      {
        rowCount: rows.length
      },
      db
    );

    res.setHeader(
      'Content-Type',
      'text/csv'
    );

    res.setHeader(
      'Content-Disposition',
      'attachment; filename="patchpilot-export.csv"'
    );

    res.send(lines.join('\n'));
  }
);

/* ================= HELPER FUNCTIONS ================= */

function recalculateFindings(db) {
  const config = loadConfig(db);

  const scoreConfig =
    engine.buildScoreConfig(config);

  const now = new Date().toISOString();

  const rows = db.prepare(`
    SELECT * FROM findings
    WHERE status IN (
      'open',
      'in_progress',
      'reopened', 'awaiting_retest'
    )
  `).all();

  const update = db.prepare(`
    UPDATE findings
    SET
      priorityScore = ?,
      priority = ?,
      reasons = ?,
      dueDate = ?, scoreConfig = ?, history = ?
    WHERE id = ?
  `);

  const run = db.transaction(() => {
    for (const row of rows) {
      const f = dbRowToFinding(row);

      const scored = engine.scoreFinding(
        f,
        scoreConfig
      );

      f.priorityScore = scored.score;
      f.priority = scored.priority;
      f.reasons = scored.reasons;

      let due = f.dueDate;

      {
        due = engine.calcSla(
          f,
          config,
          now
        ).dueDate;
      }

      update.run(
        f.priorityScore,
        f.priority,
        JSON.stringify(f.reasons),
        due,
        JSON.stringify(scoreConfig),
        JSON.stringify([...f.history, {action:'score_recalculated',user:'system',time:now,note:`Score ${row.priorityScore} → ${f.priorityScore}; configuration saved.`,previousScore:row.priorityScore,previousPriority:row.priority,previousReasons:safeParseJson(row.reasons,[]),previousConfig:f.scoreConfig,newConfig:scoreConfig}]),
        f.id
      );
    }
  });

  run();

  return rows.length;
}

function dbRowToFinding(row) {
  return {
    id: row.id,
    title: row.title,
    cve: row.cve,
    cvss: row.cvss,
    asset: row.asset,
    assetCriticality: row.assetCriticality,

    internetFacing:
      row.internetFacing === 1 ||
      row.internetFacing === true,

    scanner: row.scanner,
    firstSeen: row.firstSeen,
    status: row.status,
    priorityScore: row.priorityScore,
    priority: row.priority,
    dueDate: row.dueDate,
    owner: row.owner,
    ownerReason: engine.assignOwner({asset:row.asset}).reason,
    fixedAt: row.fixedAt, endDate: row.endDate, slaStart: row.slaStart,
    scoreConfig: safeParseJson(row.scoreConfig, null),

    reasons: safeParseJson(
      row.reasons,
      []
    ),

    history: safeParseJson(
      row.history,
      []
    )
  };
}

function toEngineFinding(finding) {
  const {
    history,
    ...rest
  } = finding;

  return {
    ...rest,

    events: Array.isArray(history)
      ? history
      : []
  };
}

function fromEngineFinding(updated) {
  const {
    events,
    ...rest
  } = updated;

  return {
    ...rest,

    history: Array.isArray(events)
      ? events
      : []
  };
}

function toFindingView(finding, role) {
  if (role === 'viewer') {
    const {
      reasons,
      scoreConfig,
      ownerReason,
      history,
      ...limited
    } = finding;

    return limited;
  }

  return finding;
}

function safeParseJson(str, fallback) {
  try {
    return JSON.parse(str);

  } catch (_) {
    return fallback !== undefined
      ? fallback
      : null;
  }
}

/* ================= ACCOUNT REGISTRATION ================= */

const registrationRateLimit = require('express-rate-limit');

const registrationLimiter = registrationRateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,

  handler: (req, res) => {
    res.status(429).json({
      error: 'E_RATE',
      message: 'Too many registration attempts.'
    });
  }
});

router.post(
  '/register',
  registrationLimiter,

  async (req, res, next) => {
    const db = getDb();

    try {
      if (process.env.PATCHPILOT_ALLOW_REGISTRATION !== '1') {
        audit('register','anonymous','denied',{reason:'Self-registration disabled'},db);
        return res.status(403).json({error:'E_FORBIDDEN',message:'Self-registration is disabled. Ask the administrator.'});
      }
      const body = req.body || {};

      if (
        typeof body.username !== 'string' ||
        typeof body.password !== 'string'
      ) {
        return res.status(400).json({
          error: 'E_VALIDATION',
          message: 'Username and password are required.'
        });
      }

      const username = body.username
        .trim()
        .toLowerCase();

      const password = body.password;
      if (Object.hasOwn(body, 'role')) return res.status(400).json({error:'E_VALIDATION',message:'Role is assigned by the server.'});

      // Validate username

      if (!/^[a-z0-9_.-]{3,30}$/.test(username)) {
        return res.status(400).json({
          error: 'E_VALIDATION',
          message: 'Invalid username format.'
        });
      }

      // Validate password

      if (
        password.length < 12 ||
        Buffer.byteLength(password, 'utf8') > 72
      ) {
        return res.status(400).json({
          error: 'E_VALIDATION',
          message: 'Password must contain at least 12 characters and must not exceed 72 bytes.'
        });
      }

      // Check whether username already exists

      const existing = db.prepare(`
        SELECT id FROM users
        WHERE LOWER(username) = ?
      `).get(username);

      if (existing) {
        return res.status(409).json({
          error: 'E_VALIDATION',
          message: 'Unable to register with this username.'
        });
      }

      // Securely hash the password

      const passwordHash = await bcrypt.hash(
        password,
        12
      );

      // Prevent privilege escalation

      const role = 'viewer';

      // Create account

      const createAccount = db.transaction(() => {

        const duplicate = db.prepare(`
          SELECT id FROM users
          WHERE LOWER(username) = ?
        `).get(username);

        if (duplicate) {
          return false;
        }

        db.prepare(`
          INSERT INTO users (
            username,
            password_hash,
            role
          )
          VALUES (?, ?, ?)
        `).run(
          username,
          passwordHash,
          role
        );

        // Record registration in audit log

        audit(
          'register',
          username,
          'success',
          { role },
          db
        );

        return true;
      });

      const created = createAccount();

      if (!created) {
        return res.status(409).json({
          error: 'E_VALIDATION',
          message: 'Unable to register with this username.'
        });
      }

      return res.status(201).json({
        message: 'Account created successfully.',
        username,
        role
      });

    } catch (err) {
      next(err);
    }
  }
);
module.exports = router;