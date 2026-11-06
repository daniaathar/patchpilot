/**
 * T6 – Authorization Tests
 * Owner: Rida
 *
 * PDF requirement (page 4):
 *   "viewer tries admin pages and gets a generic denial,
 *    and the attempt appears in the audit log."
 *
 * These are pure unit tests — no real database or HTTP server needed.
 * A lightweight mock DB records INSERT calls so we can verify audit entries
 * without loading better-sqlite3.
 *
 * Tests:
 *   T6-1  requireRole blocks viewer → 403 E_FORBIDDEN, next NOT called
 *   T6-2  Denied attempt is written to the audit log (INSERT called)
 *   T6-3  Analyst blocked from admin-only route → 403 E_FORBIDDEN
 *   T6-4  Admin passes role check → next() IS called
 *   T6-5  Unauthenticated request → 401 E_AUTH
 *   T6-6  Response body never contains stack trace or internal details
 *
 * Evidence format: ID | input | expected | actual | pass/fail
 */

'use strict';

const { test }  = require('node:test');
const assert    = require('node:assert/strict');

const { requireAuth, makeRequireRole } = require('../server/auth');
const { audit }                        = require('../server/audit');

// ── Mock DB ───────────────────────────────────────────────────────────────────
// Simulates the subset of the better-sqlite3 API used by audit().
// Records every INSERT so tests can inspect what was logged.
function makeMockDb() {
  const rows = [];
  return {
    _rows: rows,
    prepare(sql) {
      return {
        run(...args) {
          // Parse the values from the INSERT (time, user, action, result, details)
          if (sql.includes('INSERT INTO audit_log')) {
            rows.push({
              time:    args[0],
              user:    args[1],
              action:  args[2],
              result:  args[3],
              details: args[4]
            });
          }
        }
      };
    }
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function fakeReq(role, path = '/api/audit', method = 'GET') {
  return {
    session: { user: { id: role === 'admin' ? 1 : role === 'analyst' ? 2 : 3, username: role, role } },
    path,
    method
  };
}

function fakeRes() {
  return {
    _status: null,
    _body:   null,
    status(c) { this._status = c; return this; },
    json(b)   { this._body   = b; return this; }
  };
}

// ── T6-1: viewer blocked from admin route ────────────────────────────────────
test('T6-1 – viewer gets 403 E_FORBIDDEN on admin-only route', () => {
  const mockDb     = makeMockDb();
  const requireRole = makeRequireRole(mockDb);

  const req = fakeReq('viewer', '/api/audit', 'GET');
  const res = fakeRes();
  let nextCalled = false;

  requireRole('admin')(req, res, () => { nextCalled = true; });

  console.log('T6-1 Evidence:');
  console.log('  Input    : role=viewer, route=/api/audit (admin only)');
  console.log('  Expected : HTTP 403, E_FORBIDDEN, next NOT called');
  console.log('  Actual   :', { status: res._status, error: res._body && res._body.error, nextCalled });

  assert.equal(res._status,        403,           'Must return HTTP 403');
  assert.equal(res._body.error,    'E_FORBIDDEN', 'Error code must be E_FORBIDDEN');
  assert.equal(nextCalled,         false,         'next() must NOT be called');

  console.log('T6-1 RESULT: PASS');
});

// ── T6-2: denied attempt written to audit log ─────────────────────────────────
test('T6-2 – denied access attempt is recorded in the audit log', () => {
  const mockDb     = makeMockDb();
  const requireRole = makeRequireRole(mockDb);

  const req = fakeReq('viewer', '/api/config', 'PUT');
  const res = fakeRes();
  requireRole('admin')(req, res, () => {});

  // Inspect what was written to the mock audit log
  const entry = mockDb._rows.find(r => r.action === 'access_denied');

  console.log('T6-2 Evidence:');
  console.log('  Input    : viewer PUT /api/config (admin only)');
  console.log('  Expected : audit_log entry with action=access_denied, result=denied, user=viewer');
  console.log('  Actual   :', entry || 'NOT FOUND');

  assert.ok(entry,                   'An access_denied entry must be written to the audit log');
  assert.equal(entry.user,   'viewer',  'Audit entry user must be viewer');
  assert.equal(entry.result, 'denied',  'Audit entry result must be denied');

  const details = JSON.parse(entry.details);
  assert.ok(details.requiredRoles || details.path,
    'Audit details must contain path or requiredRoles context');

  console.log('T6-2 RESULT: PASS');
});

// ── T6-3: analyst blocked from admin route ───────────────────────────────────
test('T6-3 – analyst gets 403 E_FORBIDDEN on admin-only route', () => {
  const mockDb     = makeMockDb();
  const requireRole = makeRequireRole(mockDb);

  const req = fakeReq('analyst', '/api/audit', 'GET');
  const res = fakeRes();
  let nextCalled = false;

  requireRole('admin')(req, res, () => { nextCalled = true; });

  console.log('T6-3 Evidence:', { status: res._status, error: res._body.error, nextCalled });

  assert.equal(res._status,     403,           'Analyst must get 403 on admin-only route');
  assert.equal(res._body.error, 'E_FORBIDDEN');
  assert.equal(nextCalled,      false);

  console.log('T6-3 RESULT: PASS');
});

// ── T6-4: admin passes role check ────────────────────────────────────────────
test('T6-4 – admin passes role check and next() is called', () => {
  const mockDb     = makeMockDb();
  const requireRole = makeRequireRole(mockDb);

  const req = fakeReq('admin', '/api/audit', 'GET');
  const res = fakeRes();
  let nextCalled = false;

  requireRole('admin')(req, res, () => { nextCalled = true; });

  console.log('T6-4 Evidence:', { status: res._status, nextCalled });

  assert.equal(nextCalled,   true,  'next() MUST be called for admin');
  assert.equal(res._status,  null,  'No error status should be set for admin');

  console.log('T6-4 RESULT: PASS');
});

// ── T6-5: unauthenticated request → 401 E_AUTH ───────────────────────────────
test('T6-5 – unauthenticated request returns 401 E_AUTH', () => {
  const req = { session: {} }; // no user in session at all
  const res = fakeRes();
  let nextCalled = false;

  requireAuth(req, res, () => { nextCalled = true; });

  console.log('T6-5 Evidence:', { status: res._status, error: res._body.error, nextCalled });

  assert.equal(res._status,     401,      'Must return 401 Unauthorized');
  assert.equal(res._body.error, 'E_AUTH', 'Error code must be E_AUTH');
  assert.equal(nextCalled,      false,    'next() must NOT be called');

  console.log('T6-5 RESULT: PASS');
});

// ── T6-6: denial response never leaks internals ──────────────────────────────
test('T6-6 – 403 response body never contains stack trace or internal details', () => {
  const mockDb     = makeMockDb();
  const requireRole = makeRequireRole(mockDb);

  const req = fakeReq('viewer', '/api/findings', 'GET');
  const res = fakeRes();

  requireRole('admin')(req, res, () => {});

  const bodyStr = JSON.stringify(res._body);

  console.log('T6-6 Evidence – response body:', res._body);

  assert.ok(!bodyStr.includes('stack'),     'No stack trace in response');
  assert.ok(!bodyStr.includes('Error:'),    'No raw Error object in response');
  assert.ok(!bodyStr.includes('at Object'), 'No stack frame in response');
  assert.ok(res._body.error,                'Must have a short error code');
  assert.ok(res._body.message,              'Must have a human-readable message');
  assert.ok(res._body.message.length < 200, 'Message must be short and generic');

  console.log('T6-6 RESULT: PASS');
});

// ── T6-7: audit sanitiseDetails removes passwords ────────────────────────────
// Tests the audit module directly without touching the DB driver.
test('T6-7 – audit sanitiseDetails redacts passwords before writing', () => {
  const mockDb  = makeMockDb();

  // Call audit directly with sensitive fields
  audit('login', 'analyst', 'failure', {
    username: 'analyst',
    password: 'hunter2',
    token:    'secret-token-abc'
  }, mockDb);

  const entry   = mockDb._rows.find(r => r.action === 'login');
  const details = JSON.parse(entry.details);

  console.log('T6-7 Evidence – logged details:', details);

  assert.equal(details.password, '[REDACTED]', 'Password must be redacted');
  assert.equal(details.token,    '[REDACTED]', 'Token must be redacted');
  assert.equal(details.username, 'analyst',    'Username (safe) must be preserved');

  console.log('T6-7 RESULT: PASS');
});
