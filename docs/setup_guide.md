# PatchPilot – Setup Guide
**Owner:** Rida | Class 2, Group 8

---

## Prerequisites

- [Node.js](https://nodejs.org/) v18 or later (tested on v22)
- npm v9 or later (bundled with Node.js)
- VS Code (recommended) or any terminal

---

## Step-by-Step Installation

### 1. Clone or unzip the project

Place the project folder on your machine. The structure should look like:

```
patchpilot/
  Hareem/
  Rida/
  Easha/      (if integrated)
  Dania/      (if integrated)
```

### 2. Install Rida's backend dependencies

Open a terminal **inside the `Rida/` folder** and run:

```bash
npm install
```

This installs: express, better-sqlite3, bcrypt, express-session, helmet, express-rate-limit, multer, csrf.

### 3. Initialise the database

The database is created and seeded automatically when the server starts.
To seed it manually (useful after resetting):

```bash
node server/db.js
```

You should see:
```
[DB] Seeded user: admin (admin)
[DB] Seeded user: analyst (analyst)
[DB] Seeded user: viewer (viewer)
[DB] Database initialised at ...patchpilot.db
```

### 4. Start the server

From inside the `Rida/` folder:

```bash
npm start
```

Or directly:

```bash
node server/app.js
```

The server starts at: **http://localhost:3000**

You will see:
```
[PatchPilot] Server running at http://localhost:3000
[WARNING] SESSION_SECRET env var is not set. Using insecure dev default.
```

The SESSION_SECRET warning is expected in local dev. See the Security section below.

### 5. Open in VS Code (optional)

1. Open VS Code.
2. File → Open Folder → select the `Rida/` folder (or the root `patchpilot/` folder).
3. Open a new terminal in VS Code (`` Ctrl+` ``).
4. Run `npm start`.

---

## Default Login Credentials

| Role    | Username  | Password       |
|---------|-----------|----------------|
| Admin   | `admin`   | `Admin@1234`   |
| Analyst | `analyst` | `Analyst@1234` |
| Viewer  | `viewer`  | `Viewer@1234`  |

> **Important:** Change these passwords before any shared or production use.

---

## Running the Tests

From inside the `Rida/` folder:

```bash
npm test
```

This runs T6 (authorization tests) and T-final (robustness tests).
Expected output: **7/7 T6 PASS** and **16/16 T-final PASS**.

To run individual suites:
```bash
npm run test:t6       # Authorization tests only
npm run test:tfinal   # Robustness tests only
```

---

## Resetting the Database

To wipe all findings and audit entries and start fresh:

1. Stop the server.
2. Delete the database file:
   ```bash
   # Windows
   del Rida\server\patchpilot.db
   
   # macOS/Linux
   rm Rida/server/patchpilot.db
   ```
3. Restart the server — it will recreate and reseed automatically.

---

## Setting the Session Secret (Production)

In any shared or deployed environment, set the `SESSION_SECRET` environment variable to a long random string:

**Windows (PowerShell):**
```powershell
$env:SESSION_SECRET = "my-long-random-secret-here"
node server/app.js
```

**macOS/Linux:**
```bash
SESSION_SECRET="my-long-random-secret-here" node server/app.js
```

---

## Port Configuration

The server defaults to port **3000**. To use a different port:

```bash
# Windows
$env:PORT = 4000; node server/app.js

# macOS/Linux
PORT=4000 node server/app.js
```

---

## Project Structure Reference

```
Rida/
  server/
    app.js       Main Express server (start here)
    db.js        SQLite setup and seeding
    auth.js      Login/session/role middleware
    audit.js     Append-only audit logging
    routes.js    All API endpoints
    engine.js    Integration with Hareem's + Easha's engine functions
    stubs.js     Placeholder stubs (used during development only)
  tests/
    t6_auth.test.js    Authorization tests (T6)
    tfinal.test.js     Robustness tests (T-final)
  docs/
    setup_guide.md     This file
    threat_model.md    Security threat model and data-flow diagram
  package.json
```
