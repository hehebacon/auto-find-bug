# Auto Find Bug

A scope-first Bug Bounty policy review assistant.

## Workflow

1. Enter a public program policy URL.
2. Save a local policy snapshot.
3. For supported HackerOne URLs, automatically retrieve a read-only public structured-scope snapshot from the third-party Bastet Targets mirror when the canonical page is only a JavaScript shell.
4. Preserve asset type and the snapshot's submission/bounty eligibility flags in `policy/scope-inventory.json`.
5. For other providers, extract domain-like strings as unverified candidates or allow manual policy-text import.
6. Keep all policy interpretation and authorization decisions with the operator.

## HackerOne snapshot limitations

- The automatic inventory source is a third-party mirror, not HackerOne's canonical API.
- Snapshot freshness is publisher-dependent and may be stale.
- Separate scope exclusions may be absent.
- "Submission eligible" and "bounty eligible" are metadata fields, not permission to test.
- The importer does not run network checks against imported assets. It only saves a local inventory.
- Always verify the live HackerOne policy, exact scope, exclusions, and program status independently.

HackerOne's official Hacker API documents the structured-scopes endpoint, but API access uses an API username/token. See the official [Hacker API documentation](https://api.hackerone.com/hacker-resources/) and [authentication guide](https://api.hackerone.com/getting-started-hacker-api/).

## Safety

- Discovered assets are inventory records, not authorization.
- Do not test assets unless the current canonical policy explicitly permits the exact activity.
- Do not test accounts, data, or systems belonging to other users.
- The current metadata check (for non-import workflows) is limited and must be independently allowed by the program policy.
- No crawling, brute force, exploitation, destructive testing, or automatic severity assignment.

## Install

Run: `bash run.sh`

Manual setup: `python -m venv .venv`, activate it, then `pip install -e .` and run `auto-find-bug`.

Tests: `python -m unittest discover -s tests -v`

## Output

Each run creates a separate workspace under `tools/outdata/` with policy snapshots, scope inventory/candidates, and (where applicable) evidence metadata and preliminary reports.

## Status

Read-only HackerOne public-scope snapshot import is implemented. Scope interpretation and any security finding require human review. Run the test suite locally before use.
