# PatchPilot — setup and recovery

Class 2, Group 8. This is a **local coursework demonstration with synthetic data only**. Do not expose it to other machines or use the sample credentials with real vulnerability data. The server binds to IPv4 loopback. Use Node.js 22 and npm; native SQLite/bcrypt dependencies are installed for the current operating system.

## Windows / VS Code

1. Extract the ZIP into a new folder; open the folder containing package.json in VS Code.
2. Run `npm ci` in PowerShell (internet access may be required for dependencies).
3. Run `npm start`. A fresh database is seeded automatically. Browse to `http://localhost:3000` (if localhost fails, use `http://127.0.0.1:3000`).
4. Existing demo credentials: `admin / Admin@1234`, `analyst / Analyst@1234`, `viewer / Viewer@1234`. These are deliberately public test credentials, not production secrets. Do not reuse elsewhere.
5. Import `fixtures/sample_good.csv` as Admin or Analyst. A fresh database gives 17 findings and 3 duplicates.

The public landing page, sign-in and registration UI retain the existing dark theme. Charts and the optional web font use remote CDN resources; connectivity is needed for the chart library. No live scanners or external targets are used.

## Account creation (optional local synthetic demo)

By default new self-registration is disabled. To explicitly enable it, stop the server and run in the same terminal:

```powershell
$env:PATCHPILOT_ALLOW_REGISTRATION = '1'
npm start
```

The endpoint requires a pre-auth session CSRF token, a valid unique username, a password of 12–72 UTF-8 bytes (minimum 12 characters), rate limits, and a server-assigned Viewer role. Registration provides access to the shared demo dataset; there is no organisation separation. Disable it again using `$env:PATCHPILOT_ALLOW_REGISTRATION = '0'` and restart. An administrator approval/user-management module is outside the brief.

## Session secret

When no environment variable is supplied, a cryptographically random 48-byte secret is generated for each server process. No fixed fallback is used. Sessions expire on restart because the session store is in memory. To set a secret explicitly, run `$env:SESSION_SECRET = node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` before starting the server. Never commit or print the value. Browser sessions use HttpOnly, SameSite=Lax cookies and a 30-minute cookie lifetime. Local HTTP only; deployment is outside scope.

## Existing database / safe recovery

Stop the old server before copying or backing up the database. Keep its `patchpilot.db`, `patchpilot.db-wal` and `patchpilot.db-shm` together if sidecars remain after clean shutdown. Never overwrite the only copy. The final ZIP contains no database or credentials derived from existing users. To retain old synthetic records, copy the backed-up files into the new server folder before first startup. Startup adds columns without dropping tables. A legacy fixed record without a successful retest becomes awaiting_retest; a successful historic retest can restore fixedAt. A legacy accepted risk without an expiry reopens on the next authenticated request. Historical scoring snapshots that were never recorded remain unknown. The old copy remains your rollback point.

To run a separate fresh demo, use `$env:PATCHPILOT_DB = "$PWD\server\demo.db"` and start; do not delete the original DB. Restart with the same path to verify persistence. Clear the variable using `Remove-Item Env:PATCHPILOT_DB` when finished.

## Tests and evaluation

```powershell
npm test
node evaluate_rules.js
node full_bench.js
```

Integration tests use temporary SQLite files, not the working DB. Use `npm run test:tfinal` for the original integration suite. Preserve output using `npm test 2>&1 | Tee-Object test-results.txt`. Node 22 supports `node --experimental-test-coverage --test tests/*.test.js` for optional code coverage. The rule evaluation reports coverage of priority classes and controlled false positives/negatives, not real-world scanner accuracy.
