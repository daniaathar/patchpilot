# PatchPilot

Vulnerability Remediation Manager | Class 2, Group 8
Team: Rida (backend), Hareem (engine A), Easha (engine B), Dania (frontend + docs)

Flow: **Upload > Clean > Rank > Time > Owner > Check again > Count**

## Folder map

```
server/     Rida   (Express, SQLite, auth, API)
engine/     Hareem: importer, dedupe, score | Easha: sla, owner, workflow, retest, metrics
frontend/   Dania  (HTML, CSS, JS, Chart.js)
fixtures/   Hareem (safe sample CSV and JSON)
tests/      everyone adds their own tests
docs/       threat model, test plan, guides, demo script, report
```

## Run the frontend alone (mock mode)

No backend needed:

```
cd frontend
npx serve .        # or: python3 -m http.server 8080
```

Open `http://localhost:8080`. Mock logins: `admin`, `analyst`, `viewer` (any password).

To use the real API, set `const USE_MOCK = false;` at the top of `frontend/app.js`.

## Git workflow (short)

- Each person works only in their own folders (see map above).
- `git pull` before you start, `git add . && git commit -m "message" && git push` when done.
- Never commit `node_modules/` or database files.
