# PatchPilot Testing Guide

## Prerequisites

- Node.js and npm installed
- Repository cloned locally
- PowerShell or another terminal opened at the repository root

Check the runtime:

```powershell
node --version
npm --version
```

Install project dependencies if they have not already been installed:

```powershell
npm install
```

## Run the T2–T5 engine tests

The T2–T5 workstream covers SLA, ownership, workflow, retesting, and metrics.

Run all five dedicated suites:

```powershell
node --test tests/sla.test.js tests/owner.test.js tests/workflow.test.js tests/retest.test.js tests/metrics.test.js
```

Run an individual suite when investigating a feature:

```powershell
node --test tests/sla.test.js
node --test tests/owner.test.js
node --test tests/workflow.test.js
node --test tests/retest.test.js
node --test tests/metrics.test.js
```

## Run the project's configured test command

```powershell
npm test
```

The current `npm test` script runs:

```text
node --test tests/t6_auth.test.js && node --test tests/tfinal.test.js
```

This command runs the configured authentication and final integration-oriented test files. It does not automatically run every standalone engine suite listed above.

## Save test output to a text file

To capture the dedicated engine suite output:

```powershell
node --test tests/sla.test.js tests/owner.test.js tests/workflow.test.js tests/retest.test.js tests/metrics.test.js 2>&1 | Tee-Object docs/final-test-output.txt
```

To capture the configured test rerun:

```powershell
npm test 2>&1 | Tee-Object docs/final-test-rerun.txt
```

Run these commands from the repository root. Ensure the `docs` directory exists first.

## Interpreting results

At the end of a Node.js test run, check:

- `ℹ tests` — total number of tests
- `ℹ pass` — passed tests
- `ℹ fail` — failed tests
- `ℹ duration_ms` — total test-run duration

A passing module test suite does not guarantee that server integration or database persistence is working. Investigate any failed test before treating the branch as ready to merge.

## Results recorded on 28 November 2026

- Dedicated T2–T5 engine suites: 81 passed, 0 failed.
- Earlier configured `npm test` baseline: 23 passed, 0 failed, before the subsequent engine integration edit.

 The 81/81 result applies only to the dedicated engine module suites.
