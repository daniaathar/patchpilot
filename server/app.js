/**
 * server/app.js
 * PatchPilot – Express server entry point.
 * Starts on port 3000, serves the frontend folder, and mounts all API routes.
 * Owner: Rida
 */

'use strict';

const path    = require('path');
const express = require('express');
const helmet  = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const Tokens  = require('csrf');

const { initDb, getDb } = require('./db');
const { audit }         = require('./audit');
const apiRoutes         = require('./routes');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Initialise database on startup ───────────────────────────────────────────
initDb();

// ── Security headers (helmet) ────────────────────────────────────────────────
// Default helmet CSP only allows scripts from 'self'. The frontend loads Chart.js
// from a CDN, so we additionally allow cdn.jsdelivr.net and cdnjs.cloudflare.com.
// Inline scripts stay blocked (frontend must use external .js files).
// upgrade-insecure-requests is disabled so http://localhost works in all browsers.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      'script-src': ["'self'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com'],
      'upgrade-insecure-requests': null
    }
  }
}));

// ── Body parsers ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));

// ── Session configuration ────────────────────────────────────────────────────
// SESSION_SECRET must be set via the SESSION_SECRET environment variable in
// any real deployment. The fallback below is for local dev/testing only.
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.warn('[WARNING] SESSION_SECRET env var is not set. Using insecure dev default. Set it before deploying.');
}

app.use(session({
  name:   'patchpilot.sid',
  secret: SESSION_SECRET || 'dev-only-secret-change-before-deploy',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge:   30 * 60 * 1000 // 30 minutes
  }
}));

// ── CSRF token management ────────────────────────────────────────────────────
// We use the 'csrf' package manually so it works with our session-based auth.
// The client must:
//   1. GET /api/csrf-token to receive a token.
//   2. Send it back in the X-CSRF-Token header on all state-changing requests.
const tokens = new Tokens();

app.get('/api/csrf-token', (req, res) => {
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();
  }
  const token = tokens.create(req.session.csrfSecret);
  res.json({ csrfToken: token });
});

// CSRF verification middleware – applies to all POST/PUT/DELETE under /api
app.use('/api', (req, res, next) => {
  // Skip CSRF check for safe HTTP methods
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) return next();

  // When mounted on '/api', Express strips the prefix so req.path is e.g. '/login'
  const skipPaths = ['/login', '/csrf-token'];
  if (skipPaths.includes(req.path)) return next();

  const secret = req.session && req.session.csrfSecret;
  const token  = req.headers['x-csrf-token'] || (req.body && req.body._csrf);

  if (!secret || !token || !tokens.verify(secret, token)) {
    return res.status(403).json({
      error:   'E_FORBIDDEN',
      message: 'Invalid or missing CSRF token.'
    });
  }

  next();
});

// ── Rate limiters ─────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minute
  max:      5,
  message:  { error: 'E_RATE', message: 'Too many login attempts. Please wait 1 minute.' },
  standardHeaders: true,
  legacyHeaders:   false
});

const importLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      10,
  message:  { error: 'E_RATE', message: 'Too many import requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders:   false
});

// Attach rate limiters to specific routes
app.use('/api/login',  loginLimiter);
app.use('/api/import', importLimiter);

// ── API routes ────────────────────────────────────────────────────────────────
app.use('/api', apiRoutes);

// Any other /api path: safe JSON 404 instead of the HTML page
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'E_VALIDATION', message: 'Unknown API endpoint.' });
});

// ── Static frontend ───────────────────────────────────────────────────────────
const frontendDir = path.join(__dirname, '../../frontend');
app.use(express.static(frontendDir));

// Fall-through to index.html for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'), (err) => {
    if (err) res.status(200).send('<h1>PatchPilot API is running.</h1>');
  });
});

// ── Global error handler ──────────────────────────────────────────────────────
// MUST be the last app.use() call.
// Never exposes stack traces or internal error details.
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error('[ERROR]', err.message);

  // Multer file-size errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'E_TOO_BIG', message: 'Uploaded file exceeds the 1 MB size limit.' });
  }
  // Malformed JSON request body / body too large
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'E_VALIDATION', message: 'Request body is not valid JSON.' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'E_TOO_BIG', message: 'Request body is too large.' });
  }
  // Other multer errors (unexpected field, too many files, ...)
  if (err.name === 'MulterError') {
    return res.status(400).json({ error: 'E_VALIDATION', message: 'Invalid file upload.' });
  }
  // Multer file-type errors (set by fileFilter)
  if (err.code === 'E_VALIDATION') {
    return res.status(400).json({ error: 'E_VALIDATION', message: err.message });
  }

  res.status(500).json({ error: 'E_SERVER', message: 'An unexpected error occurred.' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[PatchPilot] Server running at http://localhost:${PORT}`);
  });
}

module.exports = app; // exported for tests
