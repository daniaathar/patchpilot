/**
 * server/db.js
 * SQLite database initialisation, table creation and seeding.
 * Owner: Rida
 *
 * Tables:
 *   users      – id, username, password_hash, role
 *   findings   – all fields from the Finding object
 *   audit_log  – id, time, user, action, result, details
 *   config     – key, value
 */

'use strict';

const path     = require('path');
const bcrypt   = require('bcrypt');
const Database = require('better-sqlite3');

// Database file lives alongside this script
const DB_PATH = process.env.PATCHPILOT_DB || path.join(__dirname, 'patchpilot.db');
const BCRYPT_ROUNDS = 12;

let _db = null;

/**
 * Returns the singleton database connection.
 * Opens (or re-opens) it on first call, or if a previous close() was called.
 */
function getDb() {
  if (_db && _db.open) return _db;   // already open – reuse
  _db = new Database(DB_PATH);
  _db.pragma('journal_mode = WAL');
  _db.pragma('foreign_keys = ON');
  return _db;
}

/**
 * Creates all required tables and seeds default users + config.
 * Safe to call on every startup (uses IF NOT EXISTS / INSERT OR IGNORE).
 */
function initDb() {
  const db = getDb();

  // ── users ──────────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      username       TEXT    NOT NULL UNIQUE,
      password_hash  TEXT    NOT NULL,
      role           TEXT    NOT NULL CHECK(role IN ('admin','analyst','viewer'))
    );
  `);

  // ── findings ───────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS findings (
      id               TEXT    PRIMARY KEY,
      title            TEXT    NOT NULL,
      cve              TEXT    NOT NULL,
      cvss             REAL    NOT NULL,
      asset            TEXT    NOT NULL,
      assetCriticality TEXT    NOT NULL,
      internetFacing   INTEGER NOT NULL DEFAULT 0,
      scanner          TEXT    NOT NULL,
      firstSeen        TEXT    NOT NULL,
      status           TEXT    NOT NULL DEFAULT 'open',
      priorityScore    REAL,
      priority         TEXT,
      dueDate          TEXT,
      owner            TEXT,
      reasons          TEXT    DEFAULT '[]',
      history          TEXT    DEFAULT '[]'
    );
  `);

  // ── audit_log ──────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      time     TEXT    NOT NULL,
      user     TEXT    NOT NULL,
      action   TEXT    NOT NULL,
      result   TEXT    NOT NULL,
      details  TEXT
    );
  `);

  // ── config ─────────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS config (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  // Insert default config values (silently skip if already present)
  const insertConfig = db.prepare(
    `INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)`
  );
  insertConfig.run('cvssMultiplier',      '6');
  insertConfig.run('assetPoints_low',     '0');
  insertConfig.run('assetPoints_medium',  '10');
  insertConfig.run('assetPoints_high',    '20');
  insertConfig.run('assetPoints_critical','30');
  insertConfig.run('internetFacingBonus', '10');
  insertConfig.run('sla_critical',        '7');
  insertConfig.run('sla_high',            '14');
  insertConfig.run('sla_medium',          '30');
  insertConfig.run('sla_low',             '90');

  // ── seed users ─────────────────────────────────────────────────────────────
  seedUsers(db);

  return db;
}

/**
 * Seeds the three default users if they do not already exist.
 * Passwords are stored as bcrypt hashes — never plain text.
 */
function seedUsers(db) {
  const exists = db.prepare(`SELECT id FROM users WHERE username = ?`);
  const insert = db.prepare(
    `INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`
  );

  const defaults = [
    { username: 'admin',   password: 'Admin@1234',   role: 'admin'   },
    { username: 'analyst', password: 'Analyst@1234', role: 'analyst' },
    { username: 'viewer',  password: 'Viewer@1234',  role: 'viewer'  }
  ];

  for (const u of defaults) {
    if (!exists.get(u.username)) {
      const hash = bcrypt.hashSync(u.password, BCRYPT_ROUNDS);
      insert.run(u.username, hash, u.role);
      console.log(`[DB] Seeded user: ${u.username} (${u.role})`);
    }
  }
}

/**
 * Reads the current config from the database as a plain object.
 */
function loadConfig(db) {
  const rows = db.prepare(`SELECT key, value FROM config`).all();
  const cfg  = {};
  for (const row of rows) cfg[row.key] = row.value;
  return cfg;
}

/**
 * Generates a sequential finding ID like F-0001.
 * Uses COUNT(*) so it always reflects the live row count.
 */
function nextFindingId(db) {
  const row = db.prepare(`SELECT COUNT(*) AS cnt FROM findings`).get();
  const n   = (row ? row.cnt : 0) + 1;
  return `F-${String(n).padStart(4, '0')}`;
}

module.exports = { getDb, initDb, loadConfig, nextFindingId, DB_PATH };

// Allow direct execution to re-seed: node server/db.js
if (require.main === module) {
  initDb();
  console.log('[DB] Database initialised at', DB_PATH);
}