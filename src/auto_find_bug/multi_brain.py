from __future__ import annotations

"""Run five independent local analysis engines concurrently for one scope workspace.

The engines are read-only: source is parsed, never executed, and online requests are
limited to public vulnerability advisory services (OSV and CISA KEV).
"""

import argparse
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import code_audit, research
from .flow_analysis_advanced import analyze_python_flows
from .java_flow_analysis import analyze_java_flows
from .online_intelligence import correlate_dependencies
from .semgrep_analysis import analyze_with_semgrep
from .source_intelligence import discover_dependencies


def _brain_result(name: str, result: dict[str, Any], *, available: bool = True, complete: bool = True) -> dict[str, Any]:
    findings = result.get("findings") or []
    status = "unavailable" if not available else ("complete" if complete else "incomplete")
    return {
        "brain": name,
        "status": status,
        "available": available,
        "files_analyzed": result.get("files_analyzed", 0),
        "finding_count": len(findings),
        "findings": [dict(item, brain=name) for item in findings],
        "note": result.get("note") or "",
        "limitations": result.get("limitations") or [],
    }


def _brain_code_audit(source: Path) -> dict[str, Any]:
    result = code_audit.analyze_source(source)
    return _brain_result("code-audit", result, complete=result.get("files_skipped_large", 0) == 0)


def _brain_python_flow(source: Path) -> dict[str, Any]:
    result = analyze_python_flows(source)
    return _brain_result("python-flow", result, available=bool(result.get("available", True)))


def _brain_java_flow(source: Path) -> dict[str, Any]:
    result = analyze_java_flows(source)
    return _brain_result(
        "java-flow", result,
        available=bool(result.get("available", False)),
        complete=not bool(result.get("unparsed_files")),
    )


def _brain_semgrep(source: Path) -> dict[str, Any]:
    result = analyze_with_semgrep(source)
    return _brain_result(
        "semgrep-local-rules", result,
        available=bool(result.get("available", False)),
        complete=not bool(result.get("diagnostics")) and not bool(result.get("truncated_findings"))
        and result.get("exit_code") in (0, 1),
    )


def _brain_public_intel(source: Path) -> dict[str, Any]:
    dependencies = discover_dependencies(source)
    osv = correlate_dependencies(dependencies["dependencies"])
    kev_sync = research.sync_cisa_kev()
    # Read every imported KEV ID; the public catalog is larger than the CLI list limit.
    with research._connect() as db:
        kev_ids = {str(row["id"]).upper() for row in db.execute("SELECT id FROM advisories WHERE source = ?", ("CISA KEV",)).fetchall()}
    kev_by_id = {item: True for item in kev_ids}
    findings: list[dict[str, Any]] = []
    for match in osv.get("results", []):
        for advisory in match.get("advisories", []):
            aliases = {str(value).upper() for value in advisory.get("aliases", [])}
            aliases.add(str(advisory.get("id", "")).upper())
            kev_ids = sorted(value for value in aliases if value in kev_by_id)
            findings.append({
                "rule_id": "INTEL-OSV-001",
                "severity": "UNKNOWN",
                "title": f"Public advisory matches exact dependency version: {advisory.get('id')}",
                "file": ", ".join(match.get("manifests", [])),
                "line": None,
                "component": f"{match.get('ecosystem')}:{match.get('name')}@{match.get('version')}",
                "evidence": f"OSV returned {advisory.get('id')} for this exact package version.",
                "recommendation": "Review the advisory's affected ranges, package identity, runtime reachability, and fixed version.",
                "confidence": "medium",
                "advisory_id": advisory.get("id"),
                "advisory_url": advisory.get("url"),
                "advisory_aliases": sorted(aliases),
                "known_exploited_cve_ids": kev_ids,
                "known_exploited_in_wild": bool(kev_ids),
                "brain": "public-vulnerability-intel",
            })
    return {
        "brain": "public-vulnerability-intel",
        "status": "complete" if dependencies["manifests"] and not osv.get("skipped_without_exact_version") and not osv.get("skipped_batch_limit") else "incomplete",
        "available": True,
        "files_analyzed": 0,
        "finding_count": len(findings),
        "findings": findings,
        "dependency_count": dependencies["dependency_count"],
        "exact_versions_queried": osv.get("queried", 0),
        "dependencies_without_exact_version": osv.get("skipped_without_exact_version", 0),
        "kev_records_synced": kev_sync.get("saved_or_updated", 0),
        "note": "OSV exact-version matches are correlated with CISA KEV CVE IDs. Public advisory matches are leads, not proof of runtime exposure.",
        "limitations": [
            "Only supported dependency manifests and exact versions are correlated.",
            "CISA KEV membership means a CVE is known exploited in the wild; it does not prove this scope is affected.",
            "Unpublished vulnerabilities and unknown zero-days cannot be enumerated by public advisory feeds.",
        ],
    }



def _brain_public_intel_with_cache(
    source: Path, cache_path: Path, ttl_seconds: int
) -> dict[str, Any]:
    dependencies = discover_dependencies(source)
    dependency_signature = hashlib.sha256(
        json.dumps(dependencies.get("dependencies", []), sort_keys=True).encode("utf-8")
    ).hexdigest()
    if ttl_seconds > 0 and cache_path.is_file():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            age = time.time() - float(cached["cached_at"])
            if (
                cached.get("source") == str(source)
                and cached.get("dependency_signature") == dependency_signature
                and 0 <= age < ttl_seconds
            ):
                result = dict(cached["result"])
                result["note"] = (result.get("note", "") + " Public advisory result reused from cache to respect the refresh interval; dependency manifest signature is unchanged.").strip()
                return result
        except (OSError, ValueError, KeyError, TypeError):
            pass

    result = _brain_public_intel(source)
    if ttl_seconds > 0:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        _write_json(cache_path, {
            "cached_at": time.time(),
            "source": str(source),
            "dependency_signature": dependency_signature,
            "result": result,
        })
    return result


def _finding_id(item: dict[str, Any]) -> str:
    identity = "|".join(str(item.get(key, "")) for key in (
        "rule_id", "file", "line", "component", "evidence", "advisory_id"
    ))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _write_report(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# Five-Brain Scope Scan",
        "",
        f"- Completed: {payload['completed_at']}",
        f"- Scope workspace: `{payload['workspace']}`",
        f"- Source: `{payload['source']}`",
        f"- Overall status: **{payload['status']}**",
        f"- Findings: **{len(payload['findings'])}**",
        "",
        "## Brain execution",
        "",
        "| Brain | Status | Findings | Files |",
        "|---|---|---:|---:|",
    ]
    for brain in payload["brains"]:
        lines.append(
            f"| {brain['brain']} | {brain['status']} | {brain['finding_count']} | {brain.get('files_analyzed', 0)} |"
        )
    lines.extend(["", "## Findings", ""])
    if payload["findings"]:
        for item in payload["findings"]:
            lines.extend([
                f"### {item['finding_id']} — {item.get('title', item.get('rule_id', 'Finding'))}",
                "",
                f"- Brain: {item.get('brain', 'unknown')}",
                f"- Severity: {item.get('severity', 'UNKNOWN')}",
                f"- Rule: {item.get('rule_id', 'unknown')}",
                f"- Location: `{item.get('file', 'n/a')}:{item.get('line') or 'n/a'}`",
                f"- Component: `{item.get('component', 'n/a')}`",
                f"- Evidence: {item.get('evidence', 'n/a')}",
                f"- Known exploited CVE IDs: {', '.join(item.get('known_exploited_cve_ids', [])) or 'none matched'}",
                f"- Recommendation: {item.get('recommendation', 'Manual review required.')}",
                "",
            ])
    elif payload["status"] == "clean":
        lines.append("NO BUGS APPEARED / FOUND ON THIS SCOPE (within the completed engines and recorded coverage).")
    else:
        lines.append("No findings were returned, but scan coverage is incomplete; this is not a clean-scope result.")
    lines.extend(["", "## Coverage and limitations", ""])
    for brain in payload["brains"]:
        if brain.get("note"):
            lines.append(f"- **{brain['brain']}:** {brain['note']}")
        for limitation in brain.get("limitations", []):
            lines.append(f"  - {limitation}")
    lines.extend([
        "",
        "A zero-finding result is limited to the engines, languages, files, dependency manifests, and advisory feeds listed above. It does not prove the absence of vulnerabilities.",
        "No target assets were contacted, no payloads were sent, and no project source was executed.",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def run_five_brain_scan(
    source_path: str | Path,
    workspace_path: str | Path,
    *,
    public_intel_cache_ttl_seconds: int = 0,
) -> dict[str, Any]:
    source = Path(source_path).expanduser().resolve()
    workspace = Path(workspace_path).expanduser().resolve()
    if not source.exists() or not (source.is_file() or source.is_dir()):
        raise ValueError(f"Source path does not exist: {source}")
    if not workspace.is_dir():
        raise ValueError(f"Scope workspace directory does not exist: {workspace}")
    if source.is_file() and source.suffix.lower() == ".apk":
        raise ValueError("Five-brain mode currently accepts source-code project paths; use 'analyze' for APKs.")

    jobs: dict[str, Callable[[], dict[str, Any]]] = {
        "code-audit": lambda: _brain_code_audit(source),
        "python-flow": lambda: _brain_python_flow(source),
        "java-flow": lambda: _brain_java_flow(source),
        "semgrep-local-rules": lambda: _brain_semgrep(source),
        "public-vulnerability-intel": lambda: _brain_public_intel_with_cache(
            source, workspace / "bugs" / "public-intel-cache.json", public_intel_cache_ttl_seconds
        ),
    }
    results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="afb-brain") as pool:
        future_map = {pool.submit(job): name for name, job in jobs.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                results[name] = {
                    "brain": name,
                    "status": "failed",
                    "available": False,
                    "files_analyzed": 0,
                    "finding_count": 0,
                    "findings": [],
                    "note": f"{type(exc).__name__}: {exc}",
                    "limitations": ["This engine did not complete; a zero-finding conclusion is not allowed."],
                }

    ordered = [results[name] for name in jobs]
    unique: dict[str, dict[str, Any]] = {}
    for brain in ordered:
        for raw in brain["findings"]:
            item = dict(raw)
            item["finding_id"] = _finding_id(item)
            item.setdefault("validation_status", "not_validated")
            item.setdefault("status", "potential")
            unique.setdefault(item["finding_id"], item)

    findings = sorted(unique.values(), key=lambda item: (
        str(item.get("file", "")), item.get("line") or 0, str(item.get("rule_id", ""))
    ))
    incomplete = any(brain["status"] != "complete" for brain in ordered)
    status = "incomplete" if incomplete else ("findings_present" if findings else "clean")
    completed_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "schema_version": 1,
        "completed_at": completed_at,
        "workspace": str(workspace),
        "source": str(source),
        "status": status,
        "brain_count": 5,
        "brains": ordered,
        "finding_count": len(findings),
        "findings": findings,
        "network_activity": "public_osv_and_cisa_kev_only",
        "scope_authorization": "operator_must_verify_current_program_policy",
    }

    bugs_dir = workspace / "bugs"
    bugs_dir.mkdir(parents=True, exist_ok=True)
    _write_json(bugs_dir / "findings.json", payload)
    _write_report(bugs_dir / "report.md", payload)
    return {
        "workspace": str(workspace),
        "bugs_directory": str(bugs_dir),
        "findings_path": str(bugs_dir / "findings.json"),
        "report_path": str(bugs_dir / "report.md"),
        "status": status,
        "finding_count": len(findings),
        "brain_statuses": {item["brain"]: item["status"] for item in ordered},
        "files_scanned": sum(item.get("files_analyzed", 0) for item in ordered),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run five parallel local analysis brains for one Bug Bounty scope workspace.")
    parser.add_argument("source", help="Local source project directory to analyze.")
    parser.add_argument("workspace", help="Existing scope workspace; results are saved under workspace/bugs/.")
    args = parser.parse_args()
    result = run_five_brain_scan(args.source, args.workspace)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result["status"] == "clean":
        print("NO BUGS APPEARED / FOUND ON THIS SCOPE")
    elif result["status"] == "incomplete":
        print("SCAN INCOMPLETE — DO NOT INTERPRET THIS AS A CLEAN SCOPE")
    else:
        print(f"FINDINGS FOUND: {result['finding_count']} — review workspace/bugs/")


if __name__ == "__main__":
    main()
