from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def write_reports(workspace: Path, assets: list[str], observations: list[dict]) -> None:
    (workspace / "findings" / "findings.json").write_text(json.dumps({
        "findings": [],
        "status": "no_confirmed_vulnerabilities",
        "note": "Metadata observations are not validated vulnerabilities. Manual review is required.",
    }, indent=2) + "\n", encoding="utf-8")

    rows = []
    for item in observations:
        status = item.get("status_code", "request-error")
        headers = ", ".join(sorted(item.get("headers", {}).keys())) or "none observed"
        rows.append(f"| {item['asset']} | {status} | {headers} |")
    table = "\n".join(rows) if rows else "| — | — | — |"
    timestamp = datetime.now(timezone.utc).isoformat()
    report = (
        "# Preliminary assessment\n\n"
        f"- Generated: {timestamp}\n"
        "- Assessment: informational metadata only\n"
        "- Confirmed vulnerabilities: 0 (none manually validated)\n"
        "- Severity: not assigned\n\n"
        "## Operator-confirmed assets\n\n"
        + "\n".join(f"- {asset}" for asset in assets)
        + "\n\n## HTTP metadata observations\n\n"
        "| Asset | HTTP status | Security-related headers observed |\n"
        "|---|---:|---|\n"
        + table
        + "\n\n## Limitations\n\n"
        "This run sent at most one HTTPS HEAD request per selected hostname. "
        "It did not crawl, fuzz, authenticate, submit forms, follow redirects, "
        "exploit issues, or access application data. Missing headers and server "
        "responses are not proof of a vulnerability. Review the current program "
        "policy and manually validate any lead within its rules.\n"
    )
    (workspace / "reports" / "preliminary-report.md").write_text(report, encoding="utf-8")
    (workspace / "reports" / "final-report.md").write_text(
        "# Final Bug Bounty Report\n\n"
        "Pending manual validation. Do not submit this preliminary metadata report "
        "as a vulnerability report.\n", encoding="utf-8"
    )
