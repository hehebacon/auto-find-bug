from __future__ import annotations

"""Optional, local-only Semgrep adapter using rules bundled with this package."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

MAX_OUTPUT_CHARS = 8_000_000
MAX_FINDINGS = 5_000
SCAN_TIMEOUT_SECONDS = 180
MAX_TARGET_BYTES = 1_000_000


def _scanned_count(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return max(0, value)
    return 0


def _unavailable(note: str, *, available: bool = False) -> dict[str, Any]:
    return {
        "available": available,
        "engine": "semgrep-local-rules",
        "files_analyzed": 0,
        "finding_count": 0,
        "findings": [],
        "diagnostics": [],
        "exit_code": None,
        "truncated_findings": False,
        "note": note,
    }


def analyze_with_semgrep(path: str | Path) -> dict[str, Any]:
    """Run only the package's local rules; never download remote rule packs."""
    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise ValueError(f"Source path does not exist: {target}")
    executable = shutil.which("semgrep")
    if not executable:
        return _unavailable('Optional engine not installed. Install with: pip install -e ".[sast]"')

    rules = Path(__file__).parent / "rules" / "security.yml"
    if not rules.is_file():
        return _unavailable("Bundled Semgrep rule file is missing from this installation.")

    command = [
        executable, "scan", "--config", str(rules), "--json",
        "--metrics=off", "--quiet", "--jobs", "1",
        "--max-target-bytes", str(MAX_TARGET_BYTES), str(target),
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=SCAN_TIMEOUT_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired:
        return _unavailable(
            f"Semgrep exceeded the {SCAN_TIMEOUT_SECONDS}-second local scan limit.",
            available=True,
        )
    except OSError as exc:
        return _unavailable(f"Could not start Semgrep: {type(exc).__name__}.")

    stdout = completed.stdout or ""
    if len(stdout) > MAX_OUTPUT_CHARS:
        return _unavailable(
            "Semgrep JSON output exceeded the configured size limit; findings were not parsed.",
            available=True,
        )
    try:
        payload = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return {
            **_unavailable(
                f"Semgrep returned unreadable output (exit {completed.returncode}).",
                available=True,
            ),
            "exit_code": completed.returncode,
        }

    findings = []
    raw_results = payload.get("results") or []
    for match in raw_results[:MAX_FINDINGS]:
        if not isinstance(match, dict):
            continue
        extra = match.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = match.get("start") or {}
        severity = str(extra.get("severity") or "WARNING").upper()
        severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(severity, "MEDIUM")
        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            cwe = ", ".join(str(item) for item in cwe)
        check_id = str(match.get("check_id") or "SEMGREP-UNKNOWN")
        message = str(extra.get("message") or "Static taint-analysis candidate")
        findings.append({
            # Keep the full ID: truncating it to the last segment caused
            # collisions between languages and rule families.
            "rule_id": check_id,
            "engine_rule_id": check_id,
            "severity": severity,
            "title": message.splitlines()[0][:220],
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
    diagnostics = [
        str(item.get("message") or item)[:500] if isinstance(item, dict) else str(item)[:500]
        for item in errors[:50]
    ]
    truncated = len(raw_results) > MAX_FINDINGS
    note = None
    if completed.returncode not in (0, 1) or errors:
        note = (
            f"Semgrep completed with exit code {completed.returncode} and "
            f"{len(errors)} diagnostic message(s); review diagnostics before relying on coverage."
        )
    elif truncated:
        note = f"Semgrep emitted more than {MAX_FINDINGS} findings; only the first {MAX_FINDINGS} were retained."
    return {
        "available": True,
        "engine": "semgrep-local-rules",
        "files_analyzed": _scanned_count((payload.get("paths") or {}).get("scanned")),
        "finding_count": len(findings),
        "findings": findings,
        "diagnostics": diagnostics,
        "exit_code": completed.returncode,
        "truncated_findings": truncated,
        "note": note or "Only bundled local rules were used; metrics are disabled and no remote rule registry is queried.",
    }
