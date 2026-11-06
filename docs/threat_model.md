# PatchPilot – Threat Model and Data-Flow Diagram
**Owner:** Rida | Class 2, Group 8

---

## Data-Flow Diagram

> **Formal diagram (PowerPoint, dashed trust boundaries): `docs/PatchPilot_Data_Flow_Diagram.pptx`** – use this one in the report. The text sketch below is a quick reference.

```
┌─────────────────────────────────────────────────────────────────┐
│                        TRUST BOUNDARY A                         │
│                     (User's Web Browser)                        │
│                                                                 │
│   [Browser]  ──── HTTP (dev) / HTTPS (production) ────►  [API Server / Express]          │
│      ▲                               │                          │
│      │  JSON responses               │  Session cookie          │
│      └───────────────────────────────┘  (HttpOnly, SameSite)    │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────▼───────────────┐
              │      TRUST BOUNDARY B         │
              │   (API + Engine – Server)     │
              │                               │
              │  [Express Routes]             │
              │       │  requireAuth          │
              │       │  requireRole          │
              │       ▼                       │
              │  [Engine Functions]           │
              │  (parseImport, dedupe,        │
              │   scoreFinding, calcSla,      │
              │   assignOwner, handleRetest,  │
              │   computeMetrics)             │
              │       │                       │
              │       ▼                       │
              │  [SQLite Database] ◄──────────┤
              │  [Audit Log]       │           │
              └───────────────────┼───────────┘
                                  │
              ┌───────────────────▼───────────┐
              │      TRUST BOUNDARY C         │
              │   (Filesystem – Data at Rest) │
              │                               │
              │  patchpilot.db                │
              │  (users, findings,            │
              │   audit_log, config)          │
              └───────────────────────────────┘
```

**Components:**
- **Browser** – The analyst or admin's web browser. Untrusted input origin.
- **API** – Express.js server on port 3000. Validates sessions, roles, input.
- **Engine** – Pure JavaScript functions (Hareem + Easha). No network access.
- **Database** – SQLite file. Accessed only by the server process, never directly.
- **Logs** – `audit_log` table inside SQLite. Append-only. No delete operations.

---

## Threat Table (8+ threats)

| # | Threat | Attack Scenario | Fix Applied |
|---|--------|----------------|-------------|
| 1 | **SQL Injection** | Attacker sends `' OR '1'='1` in a login field to dump the database or bypass auth. | All database queries use `better-sqlite3` prepared statements with `?` placeholders. String interpolation into SQL is never used anywhere in the codebase. |
| 2 | **Stolen / Weak Password** | Attacker brute-forces or reuses a leaked password to log in as admin. | Passwords are stored as bcrypt hashes (12 rounds). Login is rate-limited to 5 attempts per minute per IP (`express-rate-limit`); further attempts get `E_RATE` until the window resets. |
| 3 | **Cross-Site Request Forgery (CSRF)** | Attacker tricks a logged-in analyst into clicking a link that submits a malicious form to the API. | The `csrf` package generates a per-session CSRF secret. Every state-changing POST/PUT must include the matching `X-CSRF-Token` header. Requests without a valid token are rejected with `E_FORBIDDEN`. |
| 4 | **Oversized / Malicious File Upload** | Attacker uploads a 500 MB file or a disguised executable to crash the server or exploit a parser. | `multer` enforces a hard 1 MB file size limit and an extension whitelist (`.csv`, `.json` only). Oversized files return `E_TOO_BIG` (413). Wrong extensions return `E_VALIDATION` (400). |
| 5 | **CSV Formula Injection** | Attacker embeds `=cmd /c calc` in a CVE field so that an analyst exporting to Excel executes it. | The importer rejects any row whose title, cve, asset or scanner starts with `=`, `+`, `-` or `@` (clear row error), and `sanitizeText` in importer.js also strips those characters as a second layer. The export route sanitises every cell before writing the CSV response. |
| 6 | **Viewer Accessing Admin Pages** | A viewer-role user manually navigates to `/api/audit` or `/api/config` to read logs or change settings. | `requireRole('admin')` middleware checks the role from the server-side session on every request. Viewers and analysts receive a generic `E_FORBIDDEN` response. Every denied attempt is written to the audit log. |
| 7 | **Audit Log Leaking Secrets** | A developer accidentally logs a password or session token, exposing it to anyone who can read the audit table. | `audit.js` runs `sanitiseDetails()` on every entry before writing. Fields named `password`, `token`, `secret`, `csrfToken`, or `authorization` are replaced with `[REDACTED]`. |
| 8 | **Brute-Force Login** | Attacker runs an automated script attempting thousands of password guesses per minute. | `express-rate-limit` limits the `/api/login` endpoint to 5 requests per minute per IP. After the limit is reached the response is `E_RATE`. Every failed login attempt is written to the audit log with the username and timestamp. |
| 9 | **Session Fixation** | Attacker pre-plants a known session ID and tricks a user into authenticating with it, gaining access to the session. | `express-session` calls `req.session.regenerate()` immediately after a successful login, replacing the pre-auth session with a new one. The old session ID is invalidated. |
| 10 | **Information Disclosure via Stack Traces** | An unhandled exception returns a full stack trace in the HTTP response, exposing internal file paths and library versions. | The global error handler in `app.js` catches all unhandled errors and returns only `{ error: 'E_SERVER', message: 'An unexpected error occurred.' }`. Stack traces are written to `console.error` (server-side log) only, never to the client. |

---

## Trust Boundary Summary

| Boundary | Crossing Point | Protection |
|----------|---------------|-----------|
| A → B (Browser to API) | HTTP request (HTTPS in production via reverse proxy) | Session cookie (HttpOnly, SameSite=lax), CSRF token, rate limiting, helmet security headers |
| B → C (API to Database) | SQLite queries | Prepared statements only, principle of least privilege (one local process) |
| File upload (A → B) | `POST /api/import` | Multer size + extension filter, content validation in engine |
| Role escalation (within B) | Route handlers | `requireAuth` + `requireRole` middleware on every protected route |
