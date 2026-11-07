# Limitations and Ethics Statement

**PatchPilot – Security Engine Part A**
Author: Hareem | Class 2, Group 8

---

## Limitations

**1. Sample data is entirely fictitious.**
All findings used for testing and demonstration purposes contain made-up CVE identifiers,
fake asset names (e.g. web-01, db-02), and synthetic CVSS scores. No real systems,
real vulnerabilities, or real organisations are represented in any fixture file.

**2. The scoring formula is a simplified rule, not a certified standard.**
PatchPilot uses a straightforward weighted formula:
`Score = (CVSS × 6) + asset criticality points + internet-facing bonus`.
This does not replicate any formal risk-rating methodology such as CVSS temporal scoring,
EPSS, or DREAD. The numeric output should be treated as a relative ordering aid only.
A human security analyst must review and validate every finding before taking remediation action.

**3. The tool does not scan, probe, or attack anything.**
PatchPilot is a data management and prioritisation tool. It only processes files that are
manually uploaded by an authorised user. It has no capability to discover vulnerabilities
independently, connect to external networks, or execute code against target systems.

**4. Deduplication relies on CVE + asset matching.**
Two findings are considered duplicates only if they share the same CVE identifier and the
same asset name (case-insensitive). A vulnerability that is reported under a different CVE
alias, or whose asset name is spelled inconsistently, will not be recognised as a duplicate.
Organisations must normalise their scanner output before importing.

**5. Import validation cannot catch all bad data.**
The importer rejects rows with clearly invalid fields (CVSS out of range, missing required
fields, known formula-injection prefixes). However, it cannot detect factually wrong data
such as a real CVSS score assigned to the wrong vulnerability, or a made-up asset name.
Garbage-in, garbage-out still applies.

**6. Performance is measured on synthetic uniform data.**
The 1 000-row performance benchmarks use programmatically generated rows. Real-world CSV
exports from security scanners vary widely in size, encoding, and field complexity, and may
perform differently.

---

## Ethics Statement

**Approved use only.**
PatchPilot is designed for use by authorised security team members within an organisation
that has given permission for vulnerability data to be processed by this tool. Using
PatchPilot to process vulnerability data belonging to organisations or individuals who have
not given consent is prohibited.

**Data minimisation and local processing.**
The tool runs entirely on a local laptop or internal server. No finding data, asset names,
or CVSS scores are transmitted to any external service, cloud endpoint, or third party.

**Role-based access control.**
The system enforces three roles (admin, analyst, viewer) to ensure that sensitive
vulnerability details are accessible only to personnel who need them. Administrators are
responsible for keeping user credentials secure and removing access when team members leave.

**Human oversight is required.**
Automated scoring and prioritisation are decision-support tools, not decision-making tools.
A qualified security analyst must review every recommendation before committing to a
remediation deadline, risk acceptance, or false-positive classification.

**No offensive capability.**
PatchPilot contains no exploit code, no network scanning capability, and no mechanism to
interact with target systems. It is purely a data management and reporting application.

**Responsible disclosure.**
If a user discovers a vulnerability in PatchPilot itself, they should report it privately to
the project team rather than disclosing it publicly before a fix is available.
