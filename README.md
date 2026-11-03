# Auto Find Bug

A scope-first Bug Bounty assistant with local static source review, single-page passive web posture checks, and public vulnerability intelligence.

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

## Network behavior

Online requests use the machine's normal network configuration through HTTPX.

- No project-specific IP-hiding, privacy mode, or mandatory proxy is enabled.
- The client uses HTTPX's standard environment handling, so normal system proxy variables (if configured on the machine) are respected.
- If no proxy is configured by the operating system or shell, requests connect through the normal network route.
- Public services may see the public IP address used by the connection. This tool does not provide anonymity or IP masking.

The online feature fetches only the exact public policy URL supplied by the operator and the documented public snapshot URL for supported HackerOne programs. Redirects are refused; no target assets are crawled, probed, or scanned.

## Passive public advisory research (MVP)

The `research` CLI searches and stores public vulnerability records. It does not interact with target assets.

### Sources

- **NVD CVE API 2.0** — keyword search, CVE identifiers, English descriptions, CVSS metadata when published, CWE identifiers, publication/modification dates, and public references.
- **CISA Known Exploited Vulnerabilities (KEV) catalog** — imports CISA's public catalog and marks records as listed in that catalog.

These sources are deliberately narrow and attributable. The tool does not scrape arbitrary websites, search private bug-bounty reports, collect exploit code, or claim to discover unknown/zero-day vulnerabilities.

### Commands

```bash
# Search public NVD records by keyword (maximum 100 per request)
auto-find-bug research search "SQL injection" --limit 25

# Import/update the public CISA KEV catalog
auto-find-bug research sync-kev

# View local records
auto-find-bug research list --limit 25
auto-find-bug research list --source "CISA KEV"
auto-find-bug research list --category "Authorization"

# Inspect database and standard network mode without making a network request
auto-find-bug research status

# Export a Markdown or JSON digest
auto-find-bug research export --format md --output reports/public-vulnerability-digest.md
auto-find-bug research export --format json --output reports/public-vulnerability-digest.json
```

### Storage and classification

- Default SQLite database: `tools/outdata/public-research/research.sqlite3`.
- Override the path with `AFB_RESEARCH_DB=/path/to/research.sqlite3`.
- CVE IDs are primary keys; importing the same record updates it instead of creating duplicates.
- Each record retains source, dates, severity/CVSS if supplied, CWE identifiers, references, raw source JSON, and import timestamp.
- Heuristic multi-label taxonomy: Authentication; Authorization/access control; Session management; Input handling; Sensitive-data exposure; Business logic; Mobile application security; Configuration and transport. Unmatched records are marked for manual review.
- CISA KEV membership is represented as catalog metadata, not a claim that a system you use is affected.

### Network and limitations

Online requests use the standard HTTPX client and the machine's normal network configuration. NVD rate limits and temporary upstream failures may delay imports; retry later rather than repeatedly issuing requests.

## Local static source review

The `code-audit` command inspects source files locally across 20+ language and configuration formats: C, C++, C#, Java, Python, JavaScript, TypeScript, Rust, Solidity, Pascal, PHP, HTML, CSS, SQL, Shell, Batch, JSON, JSONC, YAML, and XML (plus common header/module extensions). It uses Python AST checks, JSON/XML syntax validation, and language-specific heuristic rules. It skips common dependency/build directories and files larger than 1 MB. It does not execute source, install dependencies, or make network requests. Coverage is not equivalent to a full compiler-aware SAST engine; findings can be false positives or false negatives.

```bash
# Review a source tree and write Markdown (default)
auto-find-bug code-audit ./my-project

# Write machine-readable JSON
auto-find-bug code-audit ./my-project --format json --output reports/code-review.json
```

## Workspace source review and finding triage

The policy-import workflow deliberately creates an empty `findings/findings.json`; importing a scope inventory is not vulnerability discovery. To attach local static-analysis review leads to an existing workspace, run:

```bash
auto-find-bug review-source \
  ~/Documents/findbug/auto-find-bug/tools/outdata/tiktok/<workspace-timestamp> \
  /path/to/a-local-source-project
```

This reads source files from the local path only. It does not contact the program assets or execute the source. New records are assigned stable IDs and begin as `potential`. Existing human triage notes and statuses are preserved when the same finding is seen again. Reports are refreshed at `reports/preliminary-report.md` and `reports/final-report.md`.

Inspect `findings/findings.json` to get each `finding_id`, then record a human disposition:

```bash
# Keep it open for further review
auto-find-bug triage <workspace> <finding-id> --status needs_review --note "Reason it needs manual review"

# Record a false positive with rationale
auto-find-bug triage <workspace> <finding-id> --status false_positive --note "Why this pattern is not a security issue in this context"

# Record independent human validation (requires an evidence file inside workspace/evidence/)
auto-find-bug triage <workspace> <finding-id> --status validated \
  --note "Describe the independently reviewed impact and reproduction context" \
  --evidence-ref evidence/review-notes.md
```

The tool checks that the evidence reference exists inside the workspace, but does not inspect it or establish exploitability. A `validated` label means only that a human reviewer recorded a decision and evidence reference. It does not guarantee program acceptance or submission eligibility. Keep evidence free of credentials, tokens, personal data, and information belonging to other users.

## One-page passive web review

The `web-audit` command makes exactly one bounded HTTPS GET request to one supplied page after the operator confirms ownership or explicit permission. It checks response security headers, cookie attributes, insecure form actions, and external scripts without Subresource Integrity. It refuses redirects, non-HTTPS URLs, non-public DNS results, non-standard ports, and HTML bodies over 1 MB. It does not crawl, enumerate endpoints, log in, submit forms, send test payloads, or attempt exploitation. Missing headers are hardening observations, not proof of a vulnerability.

```bash
# Only run for a site you own or are explicitly authorized to review
auto-find-bug web-audit https://your-authorized-site.example/ --confirm-authorized

# JSON output
auto-find-bug web-audit https://your-authorized-site.example/ --confirm-authorized --format json --output reports/web-review.json
```

## Safety and interpretation

- Discovered assets are inventory records, not authorization.
- Only review websites you own or are explicitly authorized to assess.
- The web review is deliberately limited to one read-only page request; it is not an active vulnerability scanner.
- Never test accounts, data, or systems belonging to other users.
- Neither static findings nor missing security headers establish exploitability, severity, or a valid Bug Bounty submission.

## Install

Run: `bash run.sh`

Manual setup: `python -m venv .venv`, activate it, then `pip install -e .` and run `auto-find-bug`.

Tests: `python -m unittest discover -s tests -v`

## Output

Each run creates a separate workspace under `tools/outdata/<program-handle>/<timestamp>/` with policy snapshots, policy analysis, scope inventory/candidates, exclusions/conflicts for manual review, vulnerability taxonomy, findings placeholders, and reports.

## Status

Implemented: policy extraction/manual import, read-only HackerOne public-scope snapshot import, heuristic inclusion/exclusion analysis, conflict blocking, asset classification, offline review packs, and report templates. Automated vulnerability discovery is intentionally not part of this build. Policy completeness and authorization always require human review.
