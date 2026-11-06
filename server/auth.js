/**
 * server/auth.js
 * Authentication and role-based authorisation middleware.
 * Owner: Rida
 *
 * Exports:
 *   requireAuth(req, res, next)              – user must be logged in
 *   requireRole(...roles)(req, res, next)    – user must have one of the given roles
 *   makeRequireRole(db)                      – factory used in tests with a mock DB
 */

'use strict';

const { audit } = require('./audit');
const { getDb } = require('./db');

/**
 * Middleware: rejects unauthenticated requests with E_AUTH.
 */
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      error:   'E_AUTH',
      message: 'You must be logged in to access this resource.'
    });
  }
  next();
}

/**
 * Factory that creates a requireRole middleware bound to a specific DB instance.
 * Used in tests so a mock DB can be injected instead of the real SQLite connection.
 *
 * @param {object} db - a better-sqlite3 connection OR a mock with .prepare()
 * @returns {function(...roles): middleware}
 */
function makeRequireRole(db) {
  return function requireRole(...allowedRoles) {
    return function (req, res, next) {
      // Must be authenticated first
      if (!req.session || !req.session.user) {
        return res.status(401).json({
          error:   'E_AUTH',
          message: 'You must be logged in to access this resource.'
        });
      }

      const user = req.session.user;

      if (!allowedRoles.includes(user.role)) {
        // Log the denied access attempt to the audit log
        audit(
          'access_denied',
          user.username,
          'denied',
          {
            path:          req.path,
            method:        req.method,
            requiredRoles: allowedRoles,
            userRole:      user.role
          },
          db
        );
        return res.status(403).json({
          error:   'E_FORBIDDEN',
          message: 'You do not have permission to perform this action.'
        });
      }

      next();
    };
  };
}

/**
 * requireRole(...roles) — convenience wrapper using the live DB singleton.
 * Usage: router.get('/admin', requireRole('admin'), handler)
 */
function requireRole(...allowedRoles) {
  return makeRequireRole(getDb())(...allowedRoles);
}

module.exports = { requireAuth, requireRole, makeRequireRole };
