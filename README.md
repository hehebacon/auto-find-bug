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
- The importer does not run network checks against imported assets. It only saves a local inventory and offline review reports.
- HackerOne workspaces are grouped under `tools/outdata/<program-handle>/<timestamp>/`.
- The offline scope review groups assets by type, parses eligibility flags conservatively (unknown values require manual review), ignores duplicate records, and maps asset types to relevant high-level review categories; it does not expand wildcards or probe hosts.
- A third-party `submission_eligible: no` flag is reported as **not submission eligible in the snapshot**, not as a verified live-policy exclusion. Only the current canonical policy can establish exclusions.
- The report distinguishes snapshot-eligible, bounty-ineligible, non-submission-eligible, and incomplete/unknown eligibility records.
- A high-level vulnerability-class checklist is generated for policy review and learning; it does not scan for or confirm vulnerabilities.
- `policy/policy-analysis.json` and `.md` contain heuristic policy excerpts, inclusion/exclusion candidates, conflicts, and identified program rules.
- `policy/scope-review.json` and `.md` group assets by type and preserve unknown flags for manual review.
- `reports/preliminary-report.md` is an offline review summary, not a vulnerability submission.
- Always verify the live HackerOne policy, exact scope, exclusions, and program status independently.

HackerOne's official Hacker API documents the structured-scopes endpoint, but API access uses an API username/token. See the official [Hacker API documentation](https://api.hackerone.com/hacker-resources/) and [authentication guide](https://api.hackerone.com/getting-started-hacker-api/).

## Online connection and privacy mode

Public policy-page and third-party public-scope HTTP requests use the shared privacy-aware client in `auto_find_bug.network`.

- Privacy mode is enabled by default. Without an explicit `AFB_HTTPS_PROXY`, online HTTP requests are blocked rather than silently sent directly.
- Configure an HTTP or HTTPS proxy with `AFB_HTTPS_PROXY` in the shell environment before launching the CLI.
- `AFB_PRIVACY_MODE=0` explicitly disables the fail-closed requirement; use this only when you understand that requests may connect directly.
- The client ignores ambient proxy environment variables (`trust_env=False`), so only the explicitly configured proxy is used.
- This is not anonymity protection: the proxy provider can see the connecting IP, and local hostname validation currently performs DNS lookups from the device. DNS metadata may therefore be visible to the configured resolver.
- No proxy setup can establish authorization or make testing a target permissible.

The online feature fetches only the exact public policy URL supplied by the operator and the documented public snapshot URL for supported HackerOne programs. Redirects are refused; no target assets are crawled, probed, or scanned.

## Safety

- Discovered assets are inventory records, not authorization.
- Do not test assets unless the current canonical policy explicitly permits the exact activity.
- Do not test accounts, data, or systems belonging to other users.
- Active target requests are disabled in this build. No target crawling, probing, scanning, authentication, or automated vulnerability checks are performed.
- The tool does not establish authorization, confirm vulnerabilities, or assign severity.

## Install

Run: `bash run.sh`

Manual setup: `python -m venv .venv`, activate it, then `pip install -e .` and run `auto-find-bug`.

Tests: `python -m unittest discover -s tests -v`

## Output

Each run creates a separate workspace under `tools/outdata/<program-handle>/<timestamp>/` with policy snapshots, policy analysis, scope inventory/candidates, exclusions/conflicts for manual review, vulnerability taxonomy, findings placeholders, and reports.

## Status

Implemented: policy extraction/manual import, read-only HackerOne public-scope snapshot import, heuristic inclusion/exclusion analysis, conflict blocking, asset classification, offline review packs, and report templates. Automated vulnerability discovery is intentionally not part of this build. Policy completeness and authorization always require human review.
