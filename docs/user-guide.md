# PatchPilot User Guide (Analyst)

One page. Screenshots go in `docs/screenshots/` (see the checklist in `screenshots-checklist.md`).

## 1. Sign in
1. Open the app (`http://localhost:3000`).
2. Enter your username and password, then press **Sign in**.
3. Your session ends after 30 minutes of inactivity. If that happens, sign in again.

*Screenshot: 01-login.png*

## 2. Import a scanner file
1. Click **Import** in the top bar.
2. Choose a `.csv` or `.json` file (maximum 1 MB).
3. Press **Import file**.
4. Read the result:
   - Green message: all rows were accepted. Duplicates (same CVE on the same asset) are removed and listed with a reason.
   - Red message: the table shows the **row number**, an error code and a plain explanation (for example "row 4: cvss out of range"). Fix the file and import again.

*Screenshots: 03-import-success.png, 04-import-error.png*

## 3. Review findings
1. Go to **Dashboard**. The top cards show total, open, overdue and SLA compliance.
2. Use the filters (status, priority, owner, search, "Overdue only") to narrow the list. The list is sorted by score, highest first.
3. Click a finding ID to open its details.

*Screenshot: 02-dashboard.png*

## 4. Read a finding
The detail page shows:
- **Why this score?** Every decision in plain words (CVSS points, asset points, internet facing, final priority, owner rule).
- **Deadline** (SLA). A red "overdue" label means the deadline passed and the finding is still open.
- **History**: who did what and when.

*Screenshot: 05-finding-detail.png*

## 5. Work on a finding
- **Start work**: moves open to in progress.
- **Mark fixed (send to retest)**: records that a fix was applied.
- **Mark false positive**: type a written reason. The finding leaves the open and overdue counts.
- **Accept risk**: admin only (needs a reason, an end date and a confirmation).

## 6. Retest
1. On the detail page, use the **Retest** box.
2. Choose **Pass** or **Fail**, type evidence (required, maximum 500 characters), press **Submit retest**.
3. Pass: status becomes **fixed**. Fail: status becomes **reopened** and gets a new deadline.

## 7. Export a report
On the Dashboard press **Export sanitized CSV**. Cells that start with `= + - @` are made safe so the file can be opened in a spreadsheet.

## What the error messages mean
| Message | What to do |
|---|---|
| Please sign in to continue | Sign in again |
| You do not have permission to do that | Ask an admin; your role cannot do this |
| Some of the information is not valid | Check the form or file and retry |
| That file is too large | Keep the file under 1 MB |
| Too many tries | Wait one minute |
| Something went wrong on our side | Retry later; tell the team if it continues |
