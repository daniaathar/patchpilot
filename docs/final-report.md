# PatchPilot: Vulnerability Remediation Manager

Class 2, Group 8 | Rida, Hareem, Easha, Dania

> Assembly note (Dania): every claim must link to a test (T1..T6, T-final) or a screenshot. Replace every `[PASTE ...]` line with the real material from the owner named in brackets.

## 1. Project overview

PatchPilot is a small website that helps a security team fix computer weaknesses in the right order. Security scanners give a big, messy list of problems (called findings). PatchPilot lets a user upload that list as a CSV or JSON file, cleans it by removing duplicates, ranks each problem with a score (how dangerous the problem is plus how important the computer is), gives it a deadline (SLA), picks an owner who must fix it, and later checks again (retest) to see if the fix worked. If the retest fails, the problem is reopened. A dashboard shows simple numbers and charts, every action is written in an audit log, and only allowed people (admin, analyst, viewer) can do things.

Seven steps: Upload > Clean > Rank > Time > Owner > Check again > Count.

| Step | Requirement | What it does | Evidence |
|---|---|---|---|
| Upload | FR-1 | Imports CSV/JSON, rejects bad files and rows | Screenshots 03, 04; test T1 |
| Clean | FR-2 | Removes duplicates (same CVE on same asset) | Screenshot 03; test T1 |
| Rank | FR-3 | Score from CVSS plus asset importance, with reasons | Screenshot 05 |
| Time | FR-4 | SLA deadline by priority, overdue flag | Screenshot 02; test T2 |
| Owner | FR-5 | Assigns each finding to a team | Screenshot 05 |
| Check again | FR-6 | Retest: pass = fixed, fail = reopened | Screenshot 05; test T5 |
| Count | FR-7 | Metrics, charts, SLA compliance | Screenshot 02 |

## 2. Architecture and security design (Rida)

[PASTE: data-flow diagram with Browser, API, Engine, Database, Logs and trust boundaries]

### Threat model (8 or more threats)
[PASTE: threats and fixes table from Rida. Suggested threats: SQL injection, stolen password, CSRF, huge file upload, CSV formula injection, viewer opening admin page, log leaking secrets, brute-force login]

## 3. User interface (Dania)

The frontend has five screens: Login, Dashboard, Import, Finding Detail and Admin. It is plain HTML, CSS and JavaScript with Chart.js for the charts.

Design choices that support security and usability:
- All text from the server is placed on the page with `textContent`, never `innerHTML`, so injected scripts cannot run.
- Friendly messages for every error code (E_AUTH, E_FORBIDDEN, E_VALIDATION, E_TOO_BIG, E_RATE, E_SERVER); raw server text is never shown.
- "Are you sure?" confirmation before accepting a risk and before saving rule changes.
- Client-side checks (file type and 1 MB limit) before upload, in addition to the server checks.
- Labels on all inputs, keyboard focus outlines, a "skip to content" link, good contrast, and a layout that works on phone-size screens.
- A `USE_MOCK` switch lets the screens run on sample JSON files when the backend is not available.

Screenshots: `docs/screenshots/01-login.png` to `08-viewer-denied.png`.

## 4. Test plan and results (Easha)

[PASTE: results table with columns ID, input, expected, actual, evidence, pass/fail for T1 to T6 and T-final, plus Hareem's 12+ extra tests]

Pass rate: [PASTE: x of y = z% (must be at least 80%)]
Decision speed: [PASTE: time to score + SLA + owner for 1000 findings]
Import measurements: [PASTE from Hareem: bad rows caught, false positives or misses, time for 1000 rows]

## 5. Guides

- User Guide: `docs/user-guide.md`
- Admin Guide: `docs/admin-guide.md`
- Setup guide: [PASTE: link to Rida's setup guide]

## 6. Limitations and ethics (Hareem)

[PASTE: half-page statement. Key points: data is fake; approved local use only; the tool does not scan or attack anything; scoring is a simple rule and not perfect; a human must review decisions.]

## 7. Final checklist

- [ ] App runs from VS Code using the setup guide on a fresh laptop; sample data is fake and sanitized
- [ ] FR-1 to FR-7 demonstrable
- [ ] T1 to T6 and T-final recorded with input, expected, actual, evidence, pass/fail
- [ ] At least 80% of automated tests pass; no open critical problem in authorization, injection, secret exposure or file upload
- [ ] Source code, setup guide, sample data, diagrams, threat model (8+), test plan and results, user and admin guide, limitations and ethics statement, final report, demo
