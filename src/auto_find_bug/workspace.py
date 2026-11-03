from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[2]
OUTDATA = ROOT / "tools" / "outdata"


def slugify(value: str) -> str:
    value = re.sub(r"^https?://", "", value.strip(), flags=re.I)
    value = re.sub(r"[^a-zA-Z0-9.-]+", "-", value).strip("-._")
    return (value or "bug-bounty-program")[:72].lower()


def create_workspace(program_url: str, program_name: str | None = None) -> Path:
    host = urlparse(program_url).hostname or "program"
    label = slugify(program_name or host)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = OUTDATA / label / stamp
    for name in ("policy", "reconnaissance", "findings", "evidence", "logs", "reports"):
        (path / name).mkdir(parents=True, exist_ok=True)

    (path / "findings" / "findings.json").write_text(
        json.dumps({"findings": [], "status": "no_validated_findings", "network_activity": "none", "note": "Offline review workspace; no target checks are performed."}, indent=2),
        encoding="utf-8",
    )
    (path / "reports" / "preliminary-report.md").write_text(
        "# Offline Bug Bounty Review Pack\n\nNo target checks were performed. No findings have been validated.\n",
        encoding="utf-8",
    )
    (path / "reports" / "final-report.md").write_text(
        "# Final Bug Bounty Report\n\nPending independent review under the current program policy.\n",
        encoding="utf-8",
    )
    (path / "project.md").write_text(
        f"# Program workspace\n\n- Program: {label}\n- Program URL: {program_url}\n"
        f"- Policy host: {host}\n- Scope status: pending manual verification\n",
        encoding="utf-8",
    )
    (path / "policy" / "scope.json").write_text(
        json.dumps({"program_url": program_url, "assets": [], "excluded_assets": [], "confirmed_by_operator": False}, indent=2),
        encoding="utf-8",
    )
    (path / "policy" / "scope-review.md").write_text(
        "# Scope review\n\nReview the live policy. Add only assets explicitly listed as in scope. "
        "Record exclusions, wildcard rules, rate limits, prohibited tests, and disclosure requirements.\n",
        encoding="utf-8",
    )
    return path
