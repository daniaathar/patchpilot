# PatchPilot — Test Plan & Results (FR-4, FR-5, FR-6, FR-7)

Scope: the mandatory evaluation cases T2–T5 that belong to aap's functions (`calcSla`, `changeStatus`, `handleRetest`), run against the actual code in `engine/`. T1 (duplicates) and T6/T-final belong to Hareem and Rida respectively and aren't included here.

All results below were produced by actually running the code on 2026-11-07 (`node` v22.23.4), not written by hand. The automated unit test suite (79 tests, `node --test tests/*.test.js`) covers these same cases plus edge cases; this table is the human-readable record the report needs.

| ID | Scenario | Input | Expected | Actual | Evidence | Pass/Fail |
|---|---|---|---|---|---|---|
| T2 | Overdue SLA | Critical finding, `firstSeen: 2026-10-08`, `status: open`, checked `now = 2026-11-07` (Critical SLA = 7 days, so due 2026-10-15, 23 days in the past) | `overdue: true`, `dueDate: 2026-10-15` | `{"dueDate":"2026-10-15","daysLeft":-23,"overdue":true,"reason":"Critical finding SLA is 7 days from firstSeen. Due: 2026-10-15."}` | `calcSla()` output above, direct run | **Pass** |
| T3a | Accepted risk (admin, allowed) | `admin` calls `accept_risk` on an open finding with a reason and `endDate: 2026-12-31` | Status → `accepted_risk`, event logged with actor and reason, `endDate` stored | `{"status":"accepted_risk","events":[{"action":"accept_risk","user":"admin-01","time":"2026-11-07T12:51:24.678Z","note":"Compensating control in place; mitigated by WAF rule."}],"endDate":"2026-12-31"}` | `changeStatus()` output above, direct run | **Pass** |
| T3b | Accepted risk (analyst, denied) | `analyst` calls `accept_risk` on an open finding | Rejected with `E_FORBIDDEN`, no status change | `{"error":"E_FORBIDDEN","message":"Your role is not allowed to perform this action."}` | `changeStatus()` output above, direct run | **Pass** |
| T4 | False positive | `analyst` calls `mark_false_positive` with a reason on an open finding, then that finding is checked by `calcSla` | Status → `false_positive`, event logged; finding is excluded from the overdue count going forward | Status became `false_positive`; subsequent `calcSla` on it returned `"overdue":false` (excluded status) | `changeStatus()` + `calcSla()` output above, direct run | **Pass** |
| T5 | Reopen on failed retest | High-priority finding, `status: in_progress`, `firstSeen: 2026-10-01`, retested with `result: 'fail'` and evidence text, `now = 2026-11-07` | Status → `reopened`, retest event logged with evidence, fresh SLA deadline calculated (High = 14 days from the retest date) | `{"status":"reopened","events":[{"action":"retest_fail","user":"system","time":"2026-11-07T12:00:00.000Z","note":"Vulnerability still reproducible with curl against /api/v1/token."}],"retestEvidence":"Vulnerability still reproducible with curl against /api/v1/token.","dueDate":"2026-11-21"}` | `handleRetest()` output above, direct run | **Pass** |

## Automated unit test coverage (backs up the table above)

```
node --test tests/*.test.js
# tests 79
# pass 79
# fail 0
```

| File | Tests | Pass |
|---|---|---|
| sla.test.js | 8 | 8 |
| workflow.test.js | 22 | 22 |
| owner.test.js | 13 | 13 |
| retest.test.js | 15 | 15 |
| metrics.test.js | 16 | 16 (sanity-checks T2/T4-style scenarios via `computeMetrics`, e.g. overdue counting and SLA exclusion for `accepted_risk`/`false_positive`) |
| **Total** | **79** | **79** |

## Performance (Day 3 deliverable) — final number

Full pipeline — `scoreFinding` (Hareem) → `calcSla` → `assignOwner` → `computeMetrics` (Easha) — run end to end across 1000 synthetic findings, covering FR-3, FR-4, FR-5, FR-7 together:

**~20.3 ms for 1000 findings** (see `full_bench.js` in the engine zip; earlier partial run without scoring was ~9.4 ms, see `bench.js`).

Sanity-checked output on the same run: 70 Critical / 248 High / 332 Medium / 350 Low by priority, 650/1000 overdue, owners spread evenly across the 7 team prefixes plus Unassigned, 33.3% reopen rate on the synthetic mix — all internally consistent with the input data, confirming the three engine files compose correctly.

## Notes for the final report

- Pass rate on aap's functions: **100% (79/79)**, well above the 80% acceptance threshold.
- One bug was found and fixed during review: `retest.js` was rejecting evidence over 500 characters instead of truncating it (contradicted aap's own test). Now fixed — see the progress log.
- T3 is written here as two sub-cases (3a allowed, 3b denied) since the spec's "accepted risk" case implies the authorization boundary matters, not just the happy path.