from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def write_reports(workspace: Path, assets: list[str], observations: list[dict] | None = None) -> None:
    """Create offline review reports; observations are retained only for backwards compatibility."""
    (workspace / "findings" / "findings.json").write_text(
        json.dumps({
            "findings": [],
            "status": "no_validated_findings",
            "network_activity": "none",
            "note": "This tool prepares policy and review material. No vulnerability is inferred from asset names or policy text.",
        }, indent=2) + "\n",
        encoding="utf-8",
    )
    timestamp = datetime.now(timezone.utc).isoformat()
    report = [
        "# Offline Bug Bounty Review Pack",
        "",
        f"- Generated: {timestamp}",
        "- Network activity against listed assets: none",
        "- Confirmed vulnerabilities: 0",
        "- Severity: not assigned",
        "",
        "## Operator-attested asset list",
        "",
        *([f"- {asset}" for asset in assets] or ["- No assets recorded."]),
        "",
        "## Included review material",
        "",
        "- policy/policy-text.md — supplied policy text",
        "- policy/policy-analysis.md — heuristic inclusion, exclusion, and requirement extraction",
        "- policy/scope-review.md — scope snapshot classification and manual review notes",
        "- reconnaissance/vulnerability-class-checklist.md — high-level review taxonomy",
        "- findings/findings.json — empty until a finding is independently validated",
        "",
        "## Important limitations",
        "",
        "This report does not claim that any asset is authorized or that a vulnerability exists.",
        "Keyword extraction can miss exclusions or misread context. Compare every asset and rule with the current canonical policy.",
        "No crawling, scanning, login attempts, data access, or automated vulnerability tests were performed.",
        "Do not submit this template as a vulnerability report.",
        "",
    ]
    (workspace / "reports" / "preliminary-report.md").write_text("\n".join(report), encoding="utf-8")
    (workspace / "reports" / "final-report.md").write_text(
        "# Final Bug Bounty Report\n\nPending independent validation under the current program policy.\n",
        encoding="utf-8",
    )
