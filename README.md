# Auto Find Bug

A scope-first Bug Bounty policy review assistant.

## Workflow

1. Enter one public policy URL.
2. Save a local policy snapshot.
3. Extract domain-like strings as unverified candidates.
4. Select only exact hosts manually checked against the live policy.
5. Confirm the program rules before any request.
6. Optionally make one HTTPS HEAD metadata request per selected host, with a one-second minimum delay and no redirect following.
7. Save evidence metadata and a preliminary Markdown report.

## Safety

- Extracted names are candidates, not authorization.
- Exclusions, wildcard semantics, program status and policy exceptions require human review.
- The current check is metadata-only. It does not crawl, authenticate, submit forms, or access application data.
- Do not use this tool unless the exact target is explicitly authorized by the current program policy.
- Metadata observations are not confirmed vulnerabilities and receive no automatic severity.

## Install

Run: `bash run.sh`

Manual setup: `python -m venv .venv`, activate it, then `pip install -e .` and run `auto-find-bug`.

Tests: `python -m unittest discover -s tests -v`

## Output

Each run creates a separate workspace under `tools/outdata/` with policy snapshots, candidate scope, operator-confirmed scope, evidence JSON and Markdown reports.

## Status

Initial safe workflow. Scope interpretation and any security finding require human review. Run the test suite locally before use.
