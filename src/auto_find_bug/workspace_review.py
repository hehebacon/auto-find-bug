from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from . import code_audit


ALLOWED_STATUSES = {"potential", "needs_review", "validated", "false_positive"}


def _read_findings(path: Path) -> dict:
    if not path.exists():
        return {"findings": [], "status": "no_findings", "network_activity": "none"}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read findings file: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError("findings.json has an unsupported structure.")
    return data


def _finding_id(item: dict) -> str:
    material = "|".join(str(item.get(key, "")) for key in ("rule_id", "file", "line", "evidence"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _refresh_status(data: dict) -> None:
    findings = data["findings"]
    validated = sum(item.get("status") == "validated" for item in findings)
    open_items = sum(item.get("status") in {"potential", "needs_review"} for item in findings)
    false_positives = sum(item.get("status") == "false_positive" for item in findings)
    if validated:
        status = "validated_findings_present_manual_review"
    elif open_items:
        status = "needs_manual_review"
    elif false_positives:
        status = "no_open_findings"
    else:
        status = "no_findings"
    data["status"] = status
    data["counts"] = {
        "total": len(findings),
        "potential": sum(item.get("status") == "potential" for item in findings),
        "needs_review": sum(item.get("status") == "needs_review" for item in findings),
        "validated": validated,
        "false_positive": false_positives,
    }
    data["network_activity"] = "none"


def _write_reports(workspace: Path, data: dict, source_result: dict | None = None) -> None:
    reports = workspace / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    counts = data.get("counts", {})
    lines = [
        "# Preliminary Source Review",
        "",
        f"- Updated: {data.get('updated_at', 'unknown')}",
        f"- Status: {data.get('status', 'unknown')}",
        f"- Local source root: {data.get('source_root', 'not recorded')}",
        f"- Files scanned: {(source_result or {}).get('files_scanned', data.get('files_scanned', 0))}",
        f"- Network activity: {data.get('network_activity', 'none')}",
        "",
        "## Triage summary",
        "",
        "| Status | Count |",
        "|---|---:|",
        *[f"| {name} | {counts.get(key, 0)} |" for name, key in (
            ("Potential", "potential"), ("Needs review", "needs_review"),
            ("Validated by reviewer", "validated"), ("False positive", "false_positive")
        )],
        "",
        "## Findings",
        "",
    ]
    if not data["findings"]:
        lines.append("No static-analysis review leads were recorded.")
    for item in data["findings"]:
        lines.extend([
            f"### {item.get('finding_id')} — {item.get('title')}",
            "",
            f"- Status: **{item.get('status')}**",
            f"- Rule: {item.get('rule_id')} ({item.get('severity')})",
            f"- Location: `{item.get('file')}:{item.get('line')}`",
            f"- Confidence: {item.get('confidence', 'unknown')}",
            f"- Evidence: `{item.get('evidence', '')}`",
            f"- Recommendation: {item.get('recommendation', '')}",
            f"- Reviewer note: {item.get('reviewer_note') or 'Not reviewed'}",
            f"- Evidence reference: {item.get('evidence_ref') or 'None'}",
            "",
        ])
    lines.extend([
        "## Interpretation",
        "",
        "Static-analysis results are review leads, not proof of a vulnerability. A 'validated' status means a human reviewer recorded independent evidence; this tool does not verify exploitability or program eligibility.",
        "No target was contacted. No exploit, payload, authentication attempt, or active test was performed.",
        "",
    ])
    (reports / "preliminary-report.md").write_text("\n".join(lines), encoding="utf-8")
    final = [
        "# Final Bug Bounty Report",
        "",
        "This report is not submission-ready unless a human reviewer has independently established impact, authorization, reproducibility, and compliance with the current program policy.",
        "",
        f"- Workspace status: {data.get('status', 'unknown')}",
        f"- Manually validated review leads: {counts.get('validated', 0)}",
        f"- Findings requiring review: {counts.get('potential', 0) + counts.get('needs_review', 0)}",
        f"- False positives: {counts.get('false_positive', 0)}",
        "",
        "## Reviewer disposition",
        "",
    ]
    validated = [item for item in data["findings"] if item.get("status") == "validated"]
    if not validated:
        final.append("No finding has been manually marked validated with an evidence reference.")
    else:
        for item in validated:
            final.extend([
                f"### {item.get('finding_id')} — {item.get('title')}",
                "",
                f"- Location: `{item.get('file')}:{item.get('line')}`",
                f"- Rule: {item.get('rule_id')}",
                f"- Reviewer note: {item.get('reviewer_note')}",
                f"- Evidence reference: {item.get('evidence_ref')}",
                "",
            ])
    final.extend([
        "## Required before any submission",
        "",
        "- Re-check the live program policy, exact asset scope, exclusions, and testing rules.",
        "- Independently reproduce and document the security impact using only authorized, non-destructive methods.",
        "- Ensure evidence contains no other person's private data or secrets.",
        "- Follow the program's disclosure and report format.",
        "",
        "A human-entered validated status is not a guarantee that the program will accept the report.",
        "",
    ])
    (reports / "final-report.md").write_text("\n".join(final), encoding="utf-8")


def review_source(workspace_path: str | Path, source_path: str | Path) -> dict:
    workspace = Path(workspace_path).expanduser().resolve()
    if not workspace.is_dir():
        raise ValueError(f"Workspace directory does not exist: {workspace}")
    source = Path(source_path).expanduser().resolve()
    result = code_audit.analyze_source(source)
    findings_path = workspace / "findings" / "findings.json"
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    data = _read_findings(findings_path)
    existing = {item.get("finding_id"): item for item in data["findings"] if item.get("finding_id")}
    now = datetime.now(timezone.utc).isoformat()
    for raw in result["findings"]:
        item = dict(raw)
        item["finding_id"] = _finding_id(item)
        previous = existing.get(item["finding_id"], {})
        item["status"] = previous.get("status", "potential")
        item["reviewer_note"] = previous.get("reviewer_note")
        item["evidence_ref"] = previous.get("evidence_ref")
        item["first_seen_at"] = previous.get("first_seen_at", now)
        item["last_seen_at"] = now
        item["source_hash"] = hashlib.sha256(
            (str(source) + "|" + item["file"] + "|" + item["evidence"]).encode("utf-8")
        ).hexdigest()
        existing[item["finding_id"]] = item
    data["findings"] = sorted(existing.values(), key=lambda item: (item.get("file", ""), item.get("line", 0), item.get("rule_id", "")))
    data["source_root"] = str(source)
    data["files_scanned"] = result["files_scanned"]
    data["updated_at"] = now
    data["scanner"] = result["scanner"]
    data["limitations"] = result["limitations"]
    _refresh_status(data)
    findings_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _write_reports(workspace, data, result)
    return {"workspace": str(workspace), "findings_path": str(findings_path), "finding_count": len(result["findings"]), "files_scanned": result["files_scanned"], "counts": data["counts"], "status": data["status"], "network_activity": "none"}


def triage_finding(
    workspace_path: str | Path,
    finding_id: str,
    status: str,
    reviewer_note: str,
    evidence_ref: str | None = None,
) -> dict:
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"Status must be one of: {', '.join(sorted(ALLOWED_STATUSES))}")
    if not reviewer_note.strip():
        raise ValueError("A non-empty reviewer note is required.")
    workspace = Path(workspace_path).expanduser().resolve()
    findings_path = workspace / "findings" / "findings.json"
    data = _read_findings(findings_path)
    item = next((entry for entry in data["findings"] if entry.get("finding_id") == finding_id), None)
    if item is None:
        raise ValueError(f"Finding ID not found: {finding_id}")
    if status == "validated":
        if not evidence_ref:
            raise ValueError("Validated status requires --evidence-ref pointing to a file under workspace/evidence/.")
        evidence_root = (workspace / "evidence").resolve()
        evidence_path = (workspace / evidence_ref).resolve()
        if evidence_root not in evidence_path.parents or not evidence_path.is_file():
            raise ValueError("Evidence reference must be an existing file inside workspace/evidence/.")
    item["status"] = status
    item["reviewer_note"] = reviewer_note.strip()
    item["evidence_ref"] = evidence_ref if status == "validated" else None
    item["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    data["updated_at"] = item["reviewed_at"]
    _refresh_status(data)
    findings_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _write_reports(workspace, data)
    return {"finding_id": finding_id, "status": status, "counts": data["counts"], "workspace_status": data["status"]}
