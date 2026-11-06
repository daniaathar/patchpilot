/**
 * T-final – Robustness Tests
 * Owner: Rida
 *
 * PDF requirement (page 4, Day 3 step 3):
 *   malformed file, oversized file, unauthorized request,
 *   same file uploaded twice, safe error message,
 *   and restart the server to confirm data is still there.
 *
 * These tests run against the REAL Express app (via supertest) and a
 * temporary SQLite file, so the real patchpilot.db is never touched.
 *
 * Run:  npm run test:tfinal
 *
 * Evidence format: ID | input | expected | actual | pass/fail
 */

'use strict';

const path = require('path');
const os   = require('os');
const fs   = require('fs');

// Use a throw-away database BEFORE loading the app
const TMP_DB = path.join(os.tmpdir(), `patchpilot-tfinal-${process.pid}.db`);
process.env.PATCHPILOT_DB = TMP_DB;

const { test, before, after } = require('node:test');
const assert  = require('node:assert/strict');
const request = require('supertest');

const app    = require('../server/app');
const { getDb } = require('../server/db');

const GOOD_CSV = path.join(__dirname, '../../Hareem/fixtures/sample_good.csv');
const BAD_CSV  = path.join(__dirname, '../../Hareem/fixtures/sample_bad.csv');

let analyst, viewer, admin;          // logged-in supertest agents
let analystCsrf, viewerCsrf, adminCsrf;

async function loginAs(username, password) {
  const agent = request.agent(app);
  const res = await agent.post('/api/login').send({ username, password });
  assert.equal(res.status, 200, `login as ${username} must succeed`);
  const t = await agent.get('/api/csrf-token');
  return { agent, csrf: t.body.csrfToken };
}

function countFindings() {
  return getDb().prepare('SELECT COUNT(*) AS c FROM findings').get().c;
}

function assertSafeError(body) {
  const s = JSON.stringify(body);
  assert.ok(body.error,   'must have an error code');
  assert.ok(body.message, 'must have a short message');
  assert.ok(/^E_[A-Z_]+$/.test(body.error), 'error code must look like E_XXX');
  assert.ok(!/stack/i.test(s),       'no stack trace');
  assert.ok(!/at \S+ \(/.test(s),    'no stack frame');
  assert.ok(!/node_modules/.test(s), 'no file paths');
  assert.ok(!/SQLITE/i.test(s),      'no database internals');
}

before(async () => {
  ({ agent: analyst, csrf: analystCsrf } = await loginAs('analyst', 'Analyst@1234'));
  ({ agent: viewer,  csrf: viewerCsrf  } = await loginAs('viewer',  'Viewer@1234'));
  ({ agent: admin,   csrf: adminCsrf   } = await loginAs('admin',   'Admin@1234'));
});

after(() => {
  try { getDb().close(); } catch (_) { /* ignore */ }
  for (const ext of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(TMP_DB + ext); } catch (_) { /* ignore */ }
  }
});

// ── TF-1: malformed file ─────────────────────────────────────────────────────
test('TF-1 – malformed file is rejected with clear row errors', async () => {
  const before = countFindings();
  const res = await analyst.post('/api/import')
    .set('X-CSRF-Token', analystCsrf)
    .attach('file', BAD_CSV);

  console.log('TF-1 Evidence:');
  console.log('  Input    : sample_bad.csv (missing title, cvss=99, bad criticality, formula)');
  console.log('  Expected : HTTP 400, E_VALIDATION, errors[] with row numbers, nothing inserted');
  console.log('  Actual   :', { status: res.status, error: res.body.error,
                               errorCount: (res.body.errors || []).length,
                               firstError: res.body.errors && res.body.errors[0] });

  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'E_VALIDATION');
  assert.ok(Array.isArray(res.body.errors) && res.body.errors.length > 0);
  assert.ok(res.body.errors.every(e => typeof e.row === 'number' && e.message));
  assert.equal(countFindings(), before, 'no rows may be inserted from a bad file');
  console.log('TF-1 RESULT: PASS');
});

// ── TF-2: oversized file ─────────────────────────────────────────────────────
test('TF-2 – file larger than 1 MB is rejected with E_TOO_BIG', async () => {
  const big = Buffer.alloc(1024 * 1024 + 2048, 'a');
  const res = await analyst.post('/api/import')
    .set('X-CSRF-Token', analystCsrf)
    .attach('file', big, 'huge.csv');

  console.log('TF-2 Evidence:');
  console.log('  Input    : 1 MB + 2 KB file named huge.csv');
  console.log('  Expected : HTTP 413, E_TOO_BIG');
  console.log('  Actual   :', { status: res.status, body: res.body });

  assert.equal(res.status, 413);
  assert.equal(res.body.error, 'E_TOO_BIG');
  assertSafeError(res.body);
  console.log('TF-2 RESULT: PASS');
});

// ── TF-3: unauthorized requests ──────────────────────────────────────────────
test('TF-3a – request with no login gets E_AUTH', async () => {
  const res = await request(app).get('/api/findings');

  console.log('TF-3a Evidence:', { input: 'GET /api/findings without session',
                                   expected: '401 E_AUTH', actual: { status: res.status, error: res.body.error } });

  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'E_AUTH');
  assertSafeError(res.body);
  console.log('TF-3a RESULT: PASS');
});

test('TF-3b – viewer cannot import (E_FORBIDDEN) and nothing is inserted', async () => {
  const before = countFindings();
  const res = await viewer.post('/api/import')
    .set('X-CSRF-Token', viewerCsrf)
    .attach('file', GOOD_CSV);

  console.log('TF-3b Evidence:', { input: 'viewer POST /api/import',
                                   expected: '403 E_FORBIDDEN', actual: { status: res.status, error: res.body.error } });

  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'E_FORBIDDEN');
  assertSafeError(res.body);
  assert.equal(countFindings(), before);
  console.log('TF-3b RESULT: PASS');
});

test('TF-3c – POST without CSRF token is blocked', async () => {
  const res = await analyst.post('/api/import').attach('file', GOOD_CSV); // no X-CSRF-Token

  console.log('TF-3c Evidence:', { input: 'analyst POST /api/import with no CSRF token',
                                   expected: '403 E_FORBIDDEN', actual: { status: res.status, error: res.body.error } });

  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'E_FORBIDDEN');
  console.log('TF-3c RESULT: PASS');
});

// ── TF-4: same file uploaded twice ───────────────────────────────────────────
test('TF-4 – uploading the same file twice creates no new rows', async () => {
  const first = await analyst.post('/api/import')
    .set('X-CSRF-Token', analystCsrf).attach('file', GOOD_CSV);
  const afterFirst = countFindings();

  const second = await analyst.post('/api/import')
    .set('X-CSRF-Token', analystCsrf).attach('file', GOOD_CSV);
  const afterSecond = countFindings();

  console.log('TF-4 Evidence:');
  console.log('  Input    : sample_good.csv uploaded twice');
  console.log('  Expected : 1st inserts 17 (3 dupes inside file); 2nd inserts 0, all duplicates');
  console.log('  Actual   :', { first: [first.status, first.body.inserted, first.body.duplicates],
                               second: [second.status, second.body.inserted, second.body.duplicates],
                               rowsAfterFirst: afterFirst, rowsAfterSecond: afterSecond });

  assert.equal(first.status, 200);
  assert.equal(first.body.inserted, 17);
  assert.equal(first.body.duplicates, 3);
  assert.equal(second.status, 200);
  assert.equal(second.body.inserted, 0);
  assert.equal(second.body.duplicates, 20);
  assert.equal(afterSecond, afterFirst, 'row count must not change on 2nd upload');
  console.log('TF-4 RESULT: PASS');
});

// ── TF-5: safe error messages ────────────────────────────────────────────────
test('TF-5a – wrong file type (.txt) gives a safe E_VALIDATION error', async () => {
  const res = await analyst.post('/api/import')
    .set('X-CSRF-Token', analystCsrf)
    .attach('file', Buffer.from('hello'), 'evil.txt');

  console.log('TF-5a Evidence:', { input: 'evil.txt upload', expected: '400 E_VALIDATION, no stack trace',
                                   actual: { status: res.status, body: res.body } });

  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'E_VALIDATION');
  assertSafeError(res.body);
  console.log('TF-5a RESULT: PASS');
});

test('TF-5b – broken JSON file never crashes the server or leaks a stack trace', async () => {
  const res = await analyst.post('/api/import')
    .set('X-CSRF-Token', analystCsrf)
    .attach('file', Buffer.from('{ this is not valid json'), 'broken.json');

  console.log('TF-5b Evidence:', { input: 'broken.json', expected: '4xx with safe E_ code',
                                   actual: { status: res.status, body: res.body } });

  assert.ok(res.status >= 400 && res.status < 500, `expected 4xx, got ${res.status}`);
  assertSafeError(res.body);
  console.log('TF-5b RESULT: PASS');
});

test('TF-5c – unknown route / bad id gives a safe error, not a stack trace', async () => {
  const res = await analyst.get('/api/findings/NOT-A-REAL-ID');

  console.log('TF-5c Evidence:', { input: 'GET /api/findings/NOT-A-REAL-ID', actual: { status: res.status, body: res.body } });

  assert.equal(res.status, 404);
  assertSafeError(res.body);
  console.log('TF-5c RESULT: PASS');
});

test('TF-5d – SQL injection in login is treated as plain text', async () => {
  const res = await request(app).post('/api/login')
    .send({ username: "admin' OR '1'='1", password: "x' OR '1'='1" });

  console.log('TF-5d Evidence:', { input: "username=admin' OR '1'='1", expected: '401 E_AUTH', actual: { status: res.status, error: res.body.error } });

  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'E_AUTH');
  console.log('TF-5d RESULT: PASS');
});

// ── TF-6: audit log is filled ────────────────────────────────────────────────
test('TF-6 – audit log recorded imports, denials and logins (and no passwords)', async () => {
  const res = await admin.get('/api/audit');
  const actions = new Set(res.body.map(r => r.action));

  console.log('TF-6 Evidence:', { input: 'admin GET /api/audit', expected: 'login, import, access_denied present',
                                  actual: { status: res.status, rows: res.body.length, actions: [...actions] } });

  assert.equal(res.status, 200);
  assert.ok(actions.has('login'));
  assert.ok(actions.has('import'));
  assert.ok(actions.has('access_denied'));
  const raw = JSON.stringify(res.body);
  assert.ok(!raw.includes('Analyst@1234') && !raw.includes('Admin@1234') && !raw.includes('Viewer@1234'),
    'no passwords may appear in the audit log');
  console.log('TF-6 RESULT: PASS');
});

// ── TF-8: invalid date in file never causes a 500 ───────────────────────────
test('TF-8 – invalid firstSeen date is rejected (E_VALIDATION), not a server crash', async () => {
  const bad = JSON.stringify([{ title: 'T', cve: 'CVE-2024-9001', cvss: 5, asset: 'web-09',
    assetCriticality: 'low', scanner: 'Nessus', firstSeen: 'not-a-date' }]);
  const res = await analyst.post('/api/import')
    .set('X-CSRF-Token', analystCsrf)
    .attach('file', Buffer.from(bad), 'baddate.json');

  console.log('TF-8 Evidence:', { input: 'JSON with firstSeen="not-a-date"', expected: '400 E_VALIDATION',
                                  actual: { status: res.status, error: res.body.error } });

  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'E_VALIDATION');
  console.log('TF-8 RESULT: PASS');
});

// ── TF-9: malformed JSON request body ────────────────────────────────────────
test('TF-9 – malformed JSON request body gives safe E_VALIDATION (not E_SERVER)', async () => {
  const res = await request(app).post('/api/login')
    .set('Content-Type', 'application/json').send('{bad json');

  console.log('TF-9 Evidence:', { input: 'POST /api/login body "{bad json"', expected: '400 E_VALIDATION',
                                  actual: { status: res.status, body: res.body } });

  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'E_VALIDATION');
  assertSafeError(res.body);
  console.log('TF-9 RESULT: PASS');
});

// ── TF-10: config change takes effect (demo step: Critical SLA 7 -> 5 days) ──
test('TF-10 – changing Critical SLA from 7 to 5 days updates existing findings and is audited', async () => {
  const q = "SELECT firstSeen, dueDate FROM findings WHERE priority = 'Critical' AND status = 'open' ORDER BY id LIMIT 1";
  const before = getDb().prepare(q).get();
  assert.ok(before, 'need at least one open Critical finding');

  const res = await admin.put('/api/config').set('X-CSRF-Token', adminCsrf).send({ sla_critical: 5 });
  const after = getDb().prepare(q).get();
  const expected = new Date(new Date(before.firstSeen).getTime() + 5 * 86400000).toISOString().slice(0, 10);

  const audit = await admin.get('/api/audit');
  const logged = audit.body.some(r => r.action === 'config_change');

  console.log('TF-10 Evidence:', { input: 'admin PUT /api/config {sla_critical:5}',
                                   expected: `dueDate = firstSeen + 5 days (${expected}) and config_change in audit log`,
                                   actual: { status: res.status, before: before.dueDate, after: after.dueDate, logged } });

  assert.equal(res.status, 200);
  assert.equal(after.dueDate, expected);
  assert.notEqual(after.dueDate, before.dueDate);
  assert.ok(logged, 'config_change must appear in the audit log');
  console.log('TF-10 RESULT: PASS');
});

test('TF-10b – invalid config values are rejected and nothing is partially saved', async () => {
  const res = await admin.put('/api/config').set('X-CSRF-Token', adminCsrf)
    .send({ sla_low: 45, sla_high: -3 });
  const low = getDb().prepare("SELECT value FROM config WHERE key = 'sla_low'").get().value;

  console.log('TF-10b Evidence:', { input: '{sla_low:45, sla_high:-3}', expected: '400 E_VALIDATION, sla_low still 90',
                                    actual: { status: res.status, error: res.body.error, sla_low: low } });

  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'E_VALIDATION');
  assert.equal(low, '90');
  console.log('TF-10b RESULT: PASS');
});

// ── TF-7: restart server, data must survive ──────────────────────────────────
test('TF-7 – data is still there after the database connection is closed and re-opened (restart)', () => {
  const beforeRestart = countFindings();
  const auditBefore   = getDb().prepare('SELECT COUNT(*) AS c FROM audit_log').get().c;

  // Simulate a server restart: close the connection, then open a new one from disk
  getDb().close();
  const Database = require('better-sqlite3');
  const fresh = new Database(TMP_DB);
  const afterRestart = fresh.prepare('SELECT COUNT(*) AS c FROM findings').get().c;
  const auditAfter   = fresh.prepare('SELECT COUNT(*) AS c FROM audit_log').get().c;
  const users        = fresh.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  fresh.close();

  console.log('TF-7 Evidence:');
  console.log('  Input    : close DB connection and reopen the same file');
  console.log('  Expected : same findings, audit rows and 3 users');
  console.log('  Actual   :', { findings: [beforeRestart, afterRestart], audit: [auditBefore, auditAfter], users });

  assert.ok(beforeRestart > 0, 'there must be data to persist');
  assert.equal(afterRestart, beforeRestart);
  assert.equal(auditAfter,   auditBefore);
  assert.equal(users, 3);
  console.log('TF-7 RESULT: PASS');
});