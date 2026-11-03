# Auto Find Bug

A scope-first Bug Bounty research assistant with an interactive terminal UI.

## Current design

1. Boot sequence with millisecond timestamps.
2. Accept a public Bug Bounty program URL.
3. Fetch the public policy page and save its source snapshot.
4. Generate a scope-review workspace and candidate asset inventory.
5. Require the operator to confirm each in-scope asset and program rules.
6. Offer an interactive scope selector (arrow keys).
7. Run only explicitly enabled, policy-compliant checks.
8. Save logs, evidence metadata, findings and Markdown reports under `tools/outdata/`.

## Safety model

- Scope is never inferred as permission. Extracted domains are candidates until manually confirmed against the program's current policy.
- Excluded assets and wildcard scope are handled conservatively.
- No exploitation, credential attacks, destructive tests, denial-of-service, data extraction, or testing of third-party accounts.
- Automated checks are limited to passive analysis and low-impact requests to confirmed assets. Respect rate limits and program rules.
- Scanner output is a lead, not a confirmed vulnerability or severity rating.

## Install

Python 3.11+ recommended.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
auto-find-bug
```

## Workspace

Each program gets its own directory:

```text
tools/outdata/<program-slug>/
  project.md
  policy/
    policy-source.html
    policy-text.md
    scope-review.md
    scope.json
  reconnaissance/
  findings/
    findings.json
  evidence/
  logs/
  reports/
    preliminary-report.md
    final-report.md
```

## Status

Initial scaffold. Policy parsing and scope review are deliberately conservative; always verify scope in the live program policy before testing.
