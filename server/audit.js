/**
 * server/audit.js
 * Append-only audit log. Writes one row per significant action.
 * Owner: Rida
 *
 * audit(action, user, result, details, db)
 *
 * Rules:
 *   - Only INSERT, never UPDATE or DELETE.
 *   - Strips passwords and secrets from details before writing.
 *   - details must be a plain object or string; it is JSON-stringified.
 */

'use strict';

// Keys that must never appear in logged details
const SENSITIVE_KEYS = new Set([
  'password', 'password_hash', 'passwordHash', 'token',
  'secret', 'csrfToken', 'csrf', 'authorization'
]);

/**
 * Recursively removes sensitive keys from an object so they are never logged.
 */
function sanitiseDetails(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  if (Array.isArray(obj)) return obj.map(sanitiseDetails);

  const clean = {};
  for (const [k, v] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.has(k.toLowerCase())) {
      clean[k] = '[REDACTED]';
    } else {
      clean[k] = sanitiseDetails(v);
    }
  }
  return clean;
}

/**
 * audit(action, user, result, details, db)
 *
 * @param {string}        action  - Short action name, e.g. 'login', 'import'
 * @param {string}        user    - Username of the actor (or 'anonymous')
 * @param {string}        result  - 'success' | 'failure' | 'denied'
 * @param {object|string} details - Additional context (will be sanitised)
 * @param {Database}      db      - better-sqlite3 connection
 */
function audit(action, user, result, details, db) {
  const cleanDetails = sanitiseDetails(
    typeof details === 'string' ? { message: details } : (details || {})
  );
  const detailsJson = JSON.stringify(cleanDetails);
  const now = new Date().toISOString();

  try {
    db.prepare(
      `INSERT INTO audit_log (time, user, action, result, details)
       VALUES (?, ?, ?, ?, ?)`
    ).run(now, user || 'anonymous', action, result, detailsJson);
  } catch (err) {
    // Audit failures must never crash the application
    console.error('[AUDIT] Failed to write audit log:', err.message);
  }
}

module.exports = { audit };
