# PatchPilot Test Plan — T2 to T5

## 1. Purpose

This document describes the tests for the PatchPilot engine responsibilities assigned to this workstream:

- T2 — SLA calculation and ownership assignment
- T3 — Finding status workflow
- T4 — Retesting and remediation verification
- T5 — Metrics and reporting calculations

The objective is to verify the individual engine modules, including normal behaviour, validation, authorization, audit history, and protection against unintended mutation of input findings.

## 2. Scope and test files

| Test group | Feature | Test file |
|---|---|---|
| T2 | SLA calculation | `tests/sla.test.js` |
| T2 | Ownership assignment | `tests/owner.test.js` |
| T3 | Status workflow | `tests/workflow.test.js` |
| T4 | Retesting | `tests/retest.test.js` |
| T5 | Metrics | `tests/metrics.test.js` |

These are module-level automated tests. They do not, by themselves, establish that every route, database operation, or full application workflow has passed integration testing.

## 3. Test environment

Record the actual environment used when running the tests:

- Runtime: Node.js
- Test runner: Node.js built-in test runner (`node --test`)
- Project: PatchPilot
- Test data: test fixtures and synthetic finding objects defined by the test suites

For a reproducible record, capture the Node.js version with `node --version` and the package version/configuration from the checked-out project.

## 4. Test cases

### T2 — SLA calculation

**Module:** `engine/sla.js`  
**Tests:** `tests/sla.test.js`

Verify that:

1. Critical findings receive the default 7-day SLA.
2. Custom SLA configuration overrides the default.
3. A finding becomes overdue after its due date.
4. Accepted-risk findings are excluded from overdue status.
5. False-positive findings are excluded from overdue status.
6. Fixed findings are excluded from overdue status.
7. Missing `firstSeen` uses the current date.
8. Unknown priority falls back to the Low-priority SLA.

### T2 — Ownership assignment

**Module:** `engine/owner.js`  
**Tests:** `tests/owner.test.js`

Verify that:

1. Web assets are assigned to the Web Team.
2. Database assets are assigned to the Database Team.
3. App assets are assigned to the App Team.
4. Network assets are assigned to the Network Team.
5. Windows assets are assigned to the Windows Team.
6. API assets are assigned to the API Team.
7. File/storage assets are assigned to the Storage Team.
8. Prefix matching is case-insensitive.
9. Unknown or empty assets are assigned to Unassigned.
10. Custom ownership rules override defaults.
11. The assignment result includes an explanatory reason.

### T3 — Status workflow

**Module:** `engine/workflow.js`  
**Tests:** `tests/workflow.test.js`

Verify that:

1. Authorized analysts and admins can start work where permitted.
2. Admins can accept risk with a reason and a valid future end date.
3. Analysts cannot perform admin-only risk acceptance.
4. Accept-risk and false-positive actions require a reason.
5. A finding cannot be marked fixed directly from an invalid state.
6. Marking a finding fixed follows the awaiting-retest workflow.
7. Invalid actions and roles are rejected.
8. Successful transitions record audit events.
9. The authenticated actor identity and timestamp cannot be forged by client-supplied data.
10. Missing or blank authenticated actor identity is rejected.
11. Invalid dates, malformed event history, and overlong reasons are rejected.
12. Existing events are preserved and the original finding is not mutated.

### T4 — Retesting

**Module:** `engine/retest.js`  
**Tests:** `tests/retest.test.js`

Verify that:

1. A successful retest changes the finding status to fixed.
2. A failed retest reopens the finding.
3. A failed retest calculates a fresh SLA deadline.
4. A successful retest does not calculate a new SLA deadline.
5. Evidence is trimmed and stored.
6. Evidence longer than 500 characters is limited to the supported length.
7. Missing or non-string evidence is rejected.
8. Invalid retest results and invalid findings are rejected.
9. Retest events are added while existing event history is preserved.
10. The original `firstSeen` date is preserved after a failed retest.
11. Custom SLA configuration is respected.
12. Retesting cannot bypass remediation or repeat a verified fix.
13. The original finding object is not modified.

### T5 — Metrics

**Module:** `engine/metrics.js`  
**Tests:** `tests/metrics.test.js`

Verify that:

1. Total findings are counted correctly.
2. Open, reopened, and active findings are counted according to the metric definitions.
3. Fixed findings are counted correctly.
4. Findings are grouped by priority and owner.
5. Missing owners are grouped as Unassigned.
6. Overdue findings are counted correctly.
7. Fixed, accepted-risk, and false-positive findings are excluded from the SLA overdue calculation as appropriate.
8. SLA compliance percentage is calculated correctly.
9. Reopen rate is calculated correctly.
10. Average time to fix is calculated from valid dates.
11. Empty data and findings without valid fix dates produce safe zero values.
12. Invalid findings input and invalid current dates are rejected.

## 5. How to run

Run the five suites from the repository root:

```powershell
node --test tests/sla.test.js tests/owner.test.js tests/workflow.test.js tests/retest.test.js tests/metrics.test.js
```

Run the project's configured test command separately:

```powershell
npm test
```

## 6. Recorded results

On 28 November 2026, the five dedicated engine suites were run together:

- Tests: 81
- Passed: 81
- Failed: 0

A later `npm test` run after the `server/engine.js` integration changes did not pass completely:

- `tests/t6_auth.test.js`: 7 passed, 0 failed
- `tests/tfinal.test.js`: 12 passed, 4 failed
- Overall configured test run: 19 passed, 4 failed

The four failing cases were TF-3c (CSRF request aborted), TF-4 (CSV import returned HTTP 500), TF-10 (no open Critical finding available), and TF-7 (no findings available for persistence verification). The TF-10 and TF-7 failures may be downstream of the import failure; this has not yet been proven.

Therefore, the dedicated module test result is 81/81 passing, but the latest full configured test run is **not fully passing**. Do not describe the current branch as fully integration-tested or merge-ready until the failures are diagnosed, fixed, and rerun.

## 7. Limitations

- The 81 passing tests establish the behaviour covered by the five dedicated module suites only.
- They do not replace API, database persistence, frontend, or end-to-end verification.
- No performance benchmark result is included here because no verified benchmark output was provided for this run.
- Do not infer performance figures from test-suite execution duration.
