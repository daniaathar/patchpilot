# PatchPilot Demo Script (10 to 15 minutes)

Dania leads, everyone speaks. Rehearse twice. Use the real API (`USE_MOCK = false`) with the server running and a fresh database.

## Before you start (5 minutes, not part of the demo)
- [ ] Server running on `http://localhost:3000`, database reset (see setup guide).
- [ ] Files ready on desktop: `fixtures/sample_good.csv`, `fixtures/sample_bad.csv`.
- [ ] Three browser windows or profiles: analyst, viewer, admin (or sign out between them).
- [ ] Zoom the browser to 110% so the room can read it.
- [ ] Screenshots saved as a backup in case the live demo fails.

## Script

| Time | Who | What to do and say |
|---|---|---|
| 1 min | **Dania** | Explain the project in one paragraph: "Security scanners give a big messy list. PatchPilot cleans it, ranks it, gives each problem a deadline and an owner, retests the fix, and counts the results." Show the 7-step line: Upload, Clean, Rank, Time, Owner, Check again, Count. |
| 2 min | **Rida** (login) and **Hareem** (explains) | Log in as **analyst**. Import `sample_good.csv`. Show the cleaned list, scores with reasons, owners and deadlines. Hareem points out the **3 duplicates** found and their reasons. |
| 2 min | **Hareem** / **Rida** | Import `sample_bad.csv`. The system rejects bad rows and names the exact problem (for example "row 4: cvss out of range"). Open the audit log (as admin, or show screenshot) to show the failed import was recorded. |
| 2 min | **Easha** | Filter **Overdue only**. Open an overdue finding. Mark one as **false positive** with a reason (it leaves the open count). Run a **retest that fails**: the finding becomes **reopened** with a new deadline. |
| 2 min | **Rida** / **Dania** | Log in as **viewer**. Click **Admin**. Show the generic "no permission" message. Then switch to **admin** and show that attempt in the audit log. |
| 2 min | **Dania** (admin) | Open **Admin**. Change Critical SLA from 7 to 5 days, confirm "Are you sure?". Show the new deadlines on the dashboard and the `config_change` entry in the audit log. |
| 1 min | **Dania** | Press **Export sanitized CSV**. Show the downloaded file. Show the metrics dashboard (charts and SLA %). |
| 1 to 2 min | **Easha** and **Rida** | Easha shows the test table (pass rate must be at least 80%). Rida shows the threat model diagram and the 8+ threats table. |

## If something breaks
- Say "Let me show the screenshot of this step" and open `docs/screenshots/`.
- Do not debug live. Move on to the next row.
- Keep the server console hidden (no stack traces on screen).

## Questions the teacher may ask (prepare short answers)
1. How does the score work? (CVSS x 6 + asset points + 10 if internet facing, max 100; every score has written reasons.)
2. How do you stop duplicates? (Same lowercase CVE + asset; keep the oldest first-seen date.)
3. Who can accept a risk? (Admin only, with a written reason and an end date.)
4. How is the app protected? (Roles checked on the server, bcrypt passwords, parameterized SQL, CSRF token, upload limits, rate limits, audit log, safe error messages.)
5. What are the limits? (Fake data only, simple scoring rule, no scanning or attacking, a human must review.)
