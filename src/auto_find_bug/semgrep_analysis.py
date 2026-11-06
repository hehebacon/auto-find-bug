from __future__ import annotations

"""Optional, local-only Semgrep adapter using rules bundled with this package."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

MAX_OUTPUT_CHARS = 8_000_000
SCAN_TIMEOUT_SECONDS = 180


def analyze_with_semgrep(path: str | Path) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise ValueError(f"Source path does not exist: {target}")
    executable = shutil.which("semgrep")
    if not executable:
        return {
            "available": False,
            "engine": "semgrep-local-rules",
            "files_analyzed": 0,
            "finding_count": 0,
            "findings": [],
            "note": 'Optional engine not installed. Install with: pip install -e ".[sast]"',
        }

    rules = Path(__file__).parent / "rules" / "security.yml"
    if not rules.is_file():
        return {
            "available": False, "engine": "semgrep-local-rules",
            "files_analyzed": 0, "finding_count": 0, "findings": [],
            "note": "Bundled Semgrep rule file is missing from this installation.",
        }

    command = [
        executable, "scan", "--config", str(rules), "--json",
        "--metrics=off", "--quiet", "--jobs", "1", str(target),
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=SCAN_TIMEOUT_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "available": True, "engine": "semgrep-local-rules",
            "files_analyzed": 0, "finding_count": 0, "findings": [],
            "note": f"Semgrep exceeded the {SCAN_TIMEOUT_SECONDS}-second local scan limit.",
        }
    except OSError as exc:
        return {
            "available": False, "engine": "semgrep-local-rules",
            "files_analyzed": 0, "finding_count": 0, "findings": [],
            "note": f"Could not start Semgrep: {type(exc).__name__}.",
        }

    if len(completed.stdout) > MAX_OUTPUT_CHARS:
        return {
            "available": True, "engine": "semgrep-local-rules",
            "files_analyzed": 0, "finding_count": 0, "findings": [],
            "note": "Semgrep JSON output exceeded the configured size limit.",
        }
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return {
            "available": True, "engine": "semgrep-local-rules",
            "files_analyzed": 0, "finding_count": 0, "findings": [],
            "note": f"Semgrep returned unreadable output (exit {completed.returncode}).",
        }

    findings = []
    for match in payload.get("results", []):
        extra = match.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = match.get("start") or {}
        severity = str(extra.get("severity") or "WARNING").upper()
        severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(severity, "MEDIUM")
        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            cwe = ", ".join(str(item) for item in cwe)
        findings.append({
            "rule_id": str(match.get("check_id", "SEMGREP-UNKNOWN")).rsplit(".", 1)[-1],
            "engine_rule_id": match.get("check_id"),
            "severity": severity,
            "title": str(extra.get("message") or "Static taint-analysis candidate").splitlines()[0][:220],
            "file": match.get("path"),
            "line": start.get("line"),
            "evidence": str(extra.get("lines") or "").strip()[:220],
            "recommendation": "Review the source-to-sink path, input control, sanitization, framework context, and safe parameterization before assigning impact.",
            "confidence": str(metadata.get("confidence") or "MEDIUM").lower(),
            "cwe": cwe,
            "validation_status": "not_validated",
            "impact_assessment": "requires_manual_review",
            "reproducibility": "not_attempted",
        })

    errors = payload.get("errors") or []
    note = None
    if completed.returncode not in (0, 1) or errors:
        note = f"Semgrep completed with exit code {completed.returncode} and {len(errors)} diagnostic message(s); review tool output before relying on coverage."
    return {
        "available": True,
        "engine": "semgrep-local-rules",
        "files_analyzed": payload.get("paths", {}).get("scanned", 0),
        "finding_count": len(findings),
        "findings": findings,
        "note": note or "Only bundled local rules were used; metrics are disabled and no remote rule registry is queried.",
    }
