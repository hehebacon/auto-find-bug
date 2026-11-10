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

Policy import automatically creates or reuses the matching workspace and starts its continuous five-brain watcher without asking for a source path. The default source drop-folder is `<workspace>/source/`; set `AFB_SOURCE_ROOT` to a fixed local source directory if desired. If the folder is empty, the watcher remains in `waiting_for_source` and does not claim a clean result. To attach local static-analysis review leads to an existing workspace manually, run:

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

The `web-audit` command makes exactly one bounded HTTPS GET request to one supplied page after the operator confirms ownership or explicit permission. It checks response security headers, cookie attributes, insecure form actions, and external scripts without Subresource Integrity. It refuses redirects, non-HTTPS URLs, non-public DNS results, non-standard ports, and bodies over 1 MB. It records 403/429/503 and common anti-bot challenge signals, then stops without solving challenges, retrying, changing identity, or evading access controls. It does not crawl, enumerate endpoints, log in, submit forms, send test payloads, or attempt exploitation. Missing headers are hardening observations, not proof of a vulnerability.

```bash
# Only run for a site you own or are explicitly authorized to review
auto-find-bug web-audit https://your-authorized-site.example/ --confirm-authorized

# JSON output
auto-find-bug web-audit https://your-authorized-site.example/ --confirm-authorized --format json --output reports/web-review.json
```

## Source Intelligence

Version 0.8.2 adds end-to-end APK and live OSV verification plus a full OWASP Benchmark Java scorecard across Python, JavaScript/TypeScript, Java, and PHP; same-file Python authorization helper tracing; bounded Androguard DEX call-graph summaries; and anti-bot/access-gate detection that stops without evasion.

Commands:

```bash
auto-find-bug source scan ./project
auto-find-bug source scan ./project --online
# Optional deeper multi-language taint checks (after installing the [sast] extra)
pip install -e ".[sast]"
auto-find-bug source scan ./project
auto-find-bug source dependencies ./project
auto-find-bug apk analyze ./application.apk
auto-find-bug analyze ./project --workspace ./existing-workspace --online
```

Source checks reuse the local analyzer and add path-sensitive Python and Java data-flow engines plus an optional Semgrep engine. The Python engine evaluates supported constant branch conditions, conservatively joins unknown branches, tracks literal List/Tuple/Set/Dictionary values and selected mutations/overwrites, and resolves uniquely named same-project helper functions with bounded call depth. The Java AST engine evaluates a bounded subset of constant branch conditions, tracks literal array/List/Map values and selected add/put/get/remove/clear/set operations, follows variable overwrites, and resolves same-class helper methods (or uniquely named project methods) with bounded call depth. When the Java AST engine is available, broad Semgrep Java taint matches are suppressed so they cannot become unsupported warnings. Parsed Java files use source-to-propagation-to-sink findings from the AST engine; unparsed files are listed as coverage gaps rather than receiving weak fallback alerts. The Java engine is measured separately against the same pinned OWASP Benchmark Java v1.2 corpus by CI; no accuracy improvement is claimed until the scorecard completes. Install the optional engines with `pip install -e ".[sast]"` (Semgrep and javalang). Semgrep runs only the rule file bundled with this package, disables metrics, and does not query a remote rule registry. Bundled Semgrep taint rules also cover selected request-to-sink patterns in JavaScript/TypeScript and PHP. Neither engine is a full compiler-aware analysis: aliases, dynamic dispatch, framework semantics, advanced container aliasing, and complex path constraints remain incomplete. Findings still require source-context review.

Python route review now resolves a bounded set of direct same-file helper calls and records project-wide middleware/framework signals. This reduces some false positives but does not prove a middleware protects a route. Aliases, cross-file calls, dynamic dispatch, and full framework policy evaluation remain outside this engine.

Each flow lead records source and sink file/line, function, evidence, rule, recommendation, confidence, and mapped CWE where available. Reports also state validation status, impact assessment, and reproducibility as not yet established. Dependency correlation sends only exact package versions from supported lockfiles to the public OSV API.

APK analysis validates and inventories the local archive, records its hash, manifest metadata when readable, declared permissions, DEX names, and native library paths. With the optional Androguard extra, it can also summarize DEX class/method counts and a bounded sample of call-graph edges. Call-graph analysis is skipped above configured size/method limits. These are method-level DEX references, not original source code or reliable original source line numbers. Text-XML manifests receive configuration checks; binary manifests can be decoded with the optional extra.

Results are saved under source-intelligence/, online-intelligence/, findings/findings.json, and reports/source-intelligence-report.md. New records start as potential; existing reviewer notes and triage statuses are preserved. Static findings and public advisory matches require human review and do not establish impact or applicability.

## Parallel five-brain scope scan

Run five independent local analysis engines concurrently against a source tree, then write the consolidated review leads inside the selected scope workspace:

```bash
auto-find-bug multi-scan /path/to/local-source /path/to/existing-scope-workspace
```

The five brains are:
1. Local multi-language heuristic/static checks (`code-audit`).
2. Path-sensitive Python source-to-sink analysis.
3. Java AST source-to-sink analysis.
4. Semgrep using only the rules bundled with this package.
5. Public vulnerability intelligence: exact-version OSV dependency correlation, enriched by matching CVE aliases against the CISA KEV catalog.

Results are written only inside the supplied scope workspace:
- `bugs/findings.json` — deduplicated findings, per-brain execution status, and coverage notes.
- `bugs/report.md` — readable report and final scan status.

The terminal prints `NO BUGS APPEARED / FOUND ON THIS SCOPE` only if all five brains completed and returned no findings. If any brain is missing, unavailable, or fails, the run is marked `incomplete`; it must not be interpreted as a clean scope. A finding is a review lead, not a confirmed vulnerability. Exact-version OSV matches and CISA KEV membership do not prove that the application is exploitable or affected at runtime. Public feeds cannot enumerate unpublished vulnerabilities or unknown zero-days.

The five brains analyze local source files in parallel. The only network requests in this mode are to public OSV and CISA KEV advisory services. No scope host is contacted, no payload is sent, and project code is never executed. Java AST and Semgrep engines must be installed for complete five-engine coverage (`pip install -e ".[sast]"`).

## Automatic continuous five-brain scanning

After a policy import, AFB automatically creates or reuses the workspace for that exact policy URL and starts the five-brain watcher without asking for a source path:
- The default local source drop-folder is `<workspace>/source/`; put the authorized source tree there.
- Set `AFB_SOURCE_ROOT=/absolute/path/to/source` to use a fixed local source folder instead. AFB saves the selected path in `bugs/scan-config.json`.
- Re-importing the same policy URL reuses its latest workspace and saved source path, then starts the watcher again automatically.
- The first five-brain scan starts as soon as at least one non-empty source file is present; an empty source folder stays in `waiting_for_source`.
- Local source changes trigger another scan cycle.
- Public advisory correlation refreshes every 15 minutes by default.
- Each cycle refreshes `bugs/findings.json` and `bugs/report.md`; append-only history is stored in `bugs/scan-history.jsonl`, with full per-cycle report snapshots under `bugs/history/<cycle-id>/`.
- Public advisory results are cached for the refresh interval to avoid repeated upstream requests during rapid local edits; a changed dependency-manifest signature invalidates that cache immediately.
- Stop the watcher with Ctrl+C. The last results and history remain on disk.

The watcher starts even when the drop-folder is empty; the results must remain incomplete until actual source files are present. The workspace is not a substitute for the target application's source code.

Optional watcher intervals:

```bash
auto-find-bug watch-scan /path/to/local-source /path/to/existing-scope-workspace --poll-seconds 5 --refresh-seconds 900
```

The watcher monitors local files only. Its five analysis brains run in parallel for each cycle; they do not run five CPU-heavy scans continuously in a tight loop. It never probes HackerOne assets, sends payloads, logs in, or executes project code. Policy scope data is not source code: without a local source tree, code-analysis brains cannot run and the workspace must remain marked as waiting/incomplete rather than clean.

## Safety and interpretation

- Discovered assets are inventory records, not authorization.
- Only review websites you own or are explicitly authorized to assess.
- The web review is deliberately limited to one read-only page request; it is not an active vulnerability scanner.
- Never test accounts, data, or systems belonging to other users.
- Neither static findings nor missing security headers establish exploitability, severity, or a valid Bug Bounty submission.

## Install

Run: `bash run.sh`

Manual setup: `python -m venv .venv`, activate it, then `pip install -e .` and run `auto-find-bug`. For optional binary AndroidManifest.xml decoding and DEX call-graph inventory, install `pip install -e ".[apk]"` (Androguard 4.x compatibility range). For the optional local Semgrep engine, install `pip install -e ".[sast]"`; install both with `pip install -e ".[apk,sast]"`.

Tests: `python -m unittest discover -s tests -v`

CI runs the core suite on Python 3.11 and 3.12, installs the optional APK/Semgrep engines, validates the bundled rules, analyzes a pinned real APK with Androguard, queries the live OSV API for a known affected exact package version, runs the labeled four-language regression corpus, and verifies the built wheel includes the rule pack. The OWASP Benchmark scorecard currently measures only the two Java injection CWEs covered by bundled rules. The latest recorded result and its poor recall are published in `benchmarks/README.md`; CI passing means the analysis and scoring pipeline ran successfully, not that the detector achieved production-grade accuracy.

## Output

The first import creates a workspace; subsequent imports of the same policy URL reuse the latest workspace so saved scan configuration and history remain connected. Each new program creates a separate workspace under `tools/outdata/<program-handle>/<timestamp>/` with policy snapshots, policy analysis, scope inventory/candidates, exclusions/conflicts for manual review, vulnerability taxonomy, findings placeholders, and reports.

## Status

Implemented: policy extraction/manual import, read-only HackerOne public-scope snapshot import, heuristic policy analysis, local static source review, Python intraprocedural data-flow tracing, optional multi-language Semgrep taint rules, bounded Python helper-call authorization review, APK archive/manifest and optional DEX call-graph inventory, dependency lockfile inventory, OSV advisory correlation for exact versions, anti-bot/access-gate detection with safe stop behavior, evidence-rich report generation, workspace finding integration, and human triage. APK archives are bounded by compressed, per-entry, total-uncompressed, and manifest-size limits. Source and dependency crawlers skip symlinked files. The tool does not perform active target checks or claim to discover unknown vulnerabilities. Policy completeness, authorization, and finding validation require human review.
