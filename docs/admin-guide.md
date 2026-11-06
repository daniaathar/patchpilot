# PatchPilot Admin Guide

One page. Admins can do everything analysts can, plus the actions below.

## 1. Change a rule (SLA days or score weights)
1. Sign in as **admin** and open **Admin** in the top bar.
2. In **Rules**, change a value, for example Critical SLA from `7` to `5` days.
3. Press **Save changes**. A confirmation box asks "Are you sure?". Press **Yes, continue**.
4. A green message confirms the save. New deadlines and scores use the new rule.
5. The change is written to the audit log (user, time, old and new value).

*Screenshot: 06-admin-rules.png*

Default rules: Score = CVSS x 6 + asset points (low 0, medium 10, high 20, critical 30) + 10 if internet facing, maximum 100. Priority: 80+ Critical, 60-79 High, 40-59 Medium, below 40 Low. SLA days: Critical 7, High 14, Medium 30, Low 90.

## 2. Read the audit log
1. Open **Admin** and scroll to **Audit log** (newest first).
2. Columns: time, user, action, result, details.
3. Look for these actions: `login` (including failures), `import`, `status_change`, `retest`, `config_change`, `export`, and `access_admin` with result `denied` (someone without permission tried an admin page).
4. The log can only be added to. Nobody can edit or delete rows. Passwords and secrets are never shown.

*Screenshot: 07-audit-log.png*

## 3. Accept a risk
1. Open a finding, press **Accept risk**.
2. Type the written reason and the end date, press **Save**, then confirm.
3. The deadline clock pauses and the finding is not counted as overdue.

## 4. Roles
| Role | Can do |
|---|---|
| admin | Everything: import, change status, accept risk, retest, change rules, read audit log, export |
| analyst | Import, start work, mark false positive, retest, export |
| viewer | Look at the dashboard and a limited finding view. Cannot import, change, export or open Admin |

If a viewer opens the Admin page they see a generic "no permission" message, and the attempt appears in the audit log.

*Screenshot: 08-viewer-denied.png*
