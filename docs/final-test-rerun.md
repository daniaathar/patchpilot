# PatchPilot — Final Test Rerun

**Date:** 28 November 2026

## Test command

```powershell
npm test
```

## Configured test files

- `tests/t6_auth.test.js`
- `tests/tfinal.test.js`

## Successful test evidence

### T6 — Authentication and access control

**Result:** 7 tests passed.

The suite verified:

- Viewer access to admin-only routes is denied.
- Denied access attempts are recorded in the audit log.
- Analyst access to admin-only routes is denied.
- Admin role checks allow authorized requests.
- Unauthenticated requests are rejected.
- Forbidden responses do not expose stack traces or internal details.
- Sensitive values such as passwords and tokens are redacted in audit details.

### TF — Final test checks

The following checks passed during the recorded run:

| Test | Verification |
|---|---|
| TF-1 | Malformed CSV file returns validation errors. |
| TF-2 | Oversized upload is rejected. |
| TF-3a | Unauthenticated request is rejected. |
| TF-3b | Viewer cannot import. |
| TF-5a | Unsupported file type is rejected safely. |
| TF-5b | Invalid JSON file is rejected safely. |
| TF-5c | Unknown finding ID returns a safe error. |
| TF-5d | SQL injection input is treated as plain text. |
| TF-6 | Audit log records relevant activity without passwords. |
| TF-8 | Invalid `firstSeen` date is rejected. |
| TF-9 | Malformed JSON request body returns a safe validation error. |
| TF-10b | Invalid configuration values are rejected without partial save. |

## Summary

This document summarizes the successful checks observed in the recorded `npm test` run. It is a selective record of passing test evidence, not a verbatim terminal transcript or a claim that every configured test passed.
