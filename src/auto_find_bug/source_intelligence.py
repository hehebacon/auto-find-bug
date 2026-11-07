from __future__ import annotations

"""Local source/APK inventory and passive advisory correlation."""

import hashlib
import json
import re
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
import xml.etree.ElementTree as ET

from . import code_audit

MAX_APK_BYTES = 200 * 1024 * 1024
MAX_APK_MEMBER_BYTES = 128 * 1024 * 1024
MAX_APK_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_dependencies(root: str | Path) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.exists():
        raise ValueError(f"Input path does not exist: {base}")
    if base.is_file():
        base = base.parent
    dependencies: dict[tuple[str, str], dict[str, Any]] = {}
    manifests: list[str] = []
    ignored = {".git", ".venv", "venv", "node_modules", "vendor", "target", "dist", "build", "__pycache__"}

    def add(ecosystem: str, name: str, version: str | None, rel: Path) -> None:
        key = (ecosystem, name.casefold())
        item = dependencies.setdefault(key, {"ecosystem": ecosystem, "name": name, "version": version, "version_is_exact": bool(version), "manifests": []})
        if rel.as_posix() not in item["manifests"]:
            item["manifests"].append(rel.as_posix())
        if item["version"] is None and version:
            item["version"] = version
            item["version_is_exact"] = True

    for path in base.rglob("*"):
        if path.is_symlink() or not path.is_file() or any(part in ignored for part in path.parts) or path.stat().st_size > 2_000_000:
            continue
        rel = path.relative_to(base)
        if path.name == "requirements.txt":
            manifests.append(rel.as_posix())
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                match = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+!-]+)", line.strip())
                if match:
                    add("PyPI", match.group(1), match.group(2), rel)
                else:
                    match = re.match(r"^([A-Za-z0-9_.-]+)", line.strip())
                    if match and not line.strip().startswith(("#", "-")):
                        add("PyPI", match.group(1), None, rel)
        elif path.name == "package-lock.json":
            manifests.append(rel.as_posix())
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for key, value in (data.get("packages") or {}).items():
                    if key.startswith("node_modules/") and isinstance(value, dict):
                        add("npm", key.rsplit("node_modules/", 1)[-1], value.get("version"), rel)
            except (OSError, json.JSONDecodeError):
                continue
        elif path.name == "Cargo.lock":
            manifests.append(rel.as_posix())
            try:
                import tomllib
                data = tomllib.loads(path.read_text(encoding="utf-8"))
                for item in data.get("package", []):
                    if item.get("name") and item.get("version"):
                        add("crates.io", item["name"], item["version"], rel)
            except (OSError, ValueError):
                continue
    items = sorted(dependencies.values(), key=lambda item: (item["ecosystem"], item["name"].casefold()))
    return {"root": str(base), "manifests": sorted(set(manifests)), "dependency_count": len(items), "dependencies": items}


def _manifest_findings(xml_text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings
    android = "{http://schemas.android.com/apk/res/android}"
    app = root.find("application")
    if app is None:
        return findings
    if app.attrib.get(android + "debuggable", "").lower() == "true":
        findings.append({"rule_id": "APK-CONFIG-001", "severity": "MEDIUM", "title": "Debuggable application flag is enabled", "file": "AndroidManifest.xml", "line": None, "component": "application", "evidence": 'android:debuggable="true"', "recommendation": "Confirm this is not a release build and disable debugging in production.", "confidence": "high"})
    if app.attrib.get(android + "usesCleartextTraffic", "").lower() == "true":
        findings.append({"rule_id": "APK-NET-001", "severity": "MEDIUM", "title": "Cleartext network traffic is permitted", "file": "AndroidManifest.xml", "line": None, "component": "application", "evidence": 'android:usesCleartextTraffic="true"', "recommendation": "Prefer HTTPS and review required exceptions.", "confidence": "high"})
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for component in app.findall(tag):
            if component.attrib.get(android + "exported", "").lower() == "true" and not component.attrib.get(android + "permission"):
                name = component.attrib.get(android + "name", "unnamed")
                findings.append({"rule_id": "APK-COMP-001", "severity": "LOW", "title": "Exported component has no declared component permission", "file": "AndroidManifest.xml", "line": None, "component": f"{tag}:{name}", "evidence": f"exported=true; component={name}", "recommendation": "Review whether external applications require access and apply an appropriate permission when needed.", "confidence": "medium"})
    return findings


def _analyze_apk_dex(path: Path, dex_names: list[str], dex_bytes: int) -> dict[str, Any]:
    if not dex_names:
        return {"status": "no_dex", "class_count": 0, "method_count": 0, "call_graph_edges": 0, "call_graph_sample": []}
    if dex_bytes > 64 * 1024 * 1024:
        return {"status": "skipped_size_limit", "class_count": None, "method_count": None, "call_graph_edges": None, "call_graph_sample": []}
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError:
        return {"status": "optional_androguard_not_installed", "class_count": None, "method_count": None, "call_graph_edges": None, "call_graph_sample": []}
    try:
        _apk, _dex_objects, analysis = AnalyzeAPK(str(path))
        classes = list(analysis.get_classes())
        methods = list(analysis.get_methods())
        summary = {
            "status": "analyzed",
            "class_count": len(classes),
            "method_count": len(methods),
            "call_graph_edges": None,
            "call_graph_sample": [],
            "note": "DEX symbols and cross-reference graph are metadata, not original source code or original line numbers.",
        }
        if len(methods) > 15000:
            summary["status"] = "analyzed_call_graph_skipped_method_limit"
            return summary
        graph = analysis.get_call_graph(no_isolated=True)
        edges = list(graph.edges(data=True))
        summary["call_graph_edges"] = len(edges)
        summary["call_graph_sample"] = [
            {"caller": str(source)[:240], "callee": str(target)[:240], "offset": attributes.get("offset")}
            for source, target, attributes in edges[:100]
        ]
        return summary
    except Exception as exc:
        return {
            "status": "dex_analysis_error",
            "class_count": None,
            "method_count": None,
            "call_graph_edges": None,
            "call_graph_sample": [],
            "note": type(exc).__name__,
        }


def analyze_apk(apk_path: str | Path) -> dict[str, Any]:
    path = Path(apk_path).expanduser().resolve()
    if not path.is_file() or path.suffix.lower() != ".apk":
        raise ValueError("APK input must be an existing .apk file.")
    size = path.stat().st_size
    if size <= 0 or size > MAX_APK_BYTES:
        raise ValueError(f"APK size must be between 1 and {MAX_APK_BYTES} bytes.")
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("Input is not a readable APK archive.") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > 20000:
            raise ValueError("APK contains too many archive entries.")
        total_uncompressed = sum(item.file_size for item in infos)
        if total_uncompressed > MAX_APK_UNCOMPRESSED_BYTES:
            raise ValueError("APK exceeds the total uncompressed archive size limit.")
        for info in infos:
            member = PurePosixPath(info.filename)
            if member.is_absolute() or ".." in member.parts or info.file_size > MAX_APK_MEMBER_BYTES:
                raise ValueError("APK contains an unsafe or oversized archive entry.")
        names = [item.filename for item in infos]
        manifest_status = "missing"
        manifest_text = ""
        permissions: list[str] = []
        package = None
        sdk = {}
        if "AndroidManifest.xml" in names:
            manifest_info = archive.getinfo("AndroidManifest.xml")
            if manifest_info.file_size > MAX_MANIFEST_BYTES:
                raise ValueError("APK AndroidManifest.xml exceeds the 8 MiB decoding limit.")
            raw = archive.read("AndroidManifest.xml")
            try:
                manifest_text = raw.decode("utf-8")
                ET.fromstring(manifest_text)
                manifest_status = "text_xml"
            except (UnicodeDecodeError, ET.ParseError):
                manifest_status = "binary_xml_requires_optional_decoder"
                try:
                    from androguard.core.apk import APK
                    from lxml import etree
                    decoded = APK(str(path))
                    manifest_obj = decoded.get_android_manifest_xml()
                    manifest_text = etree.tostring(manifest_obj, encoding="unicode") if manifest_obj is not None else ""
                    package = decoded.get_package()
                    permissions = sorted(set(decoded.get_permissions() or []))
                    sdk = {"min": decoded.get_min_sdk_version(), "target": decoded.get_target_sdk_version()}
                    manifest_status = "decoded_with_androguard"
                except ImportError:
                    pass
                except Exception as exc:
                    manifest_status = "binary_xml_decode_error:" + type(exc).__name__
        dex = [name for name in names if re.fullmatch(r"classes(?:\d+)?\.dex", PurePosixPath(name).name)]
        dex_bytes = sum(item.file_size for item in infos if item.filename in dex)
        native = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
        if manifest_text:
            try:
                root = ET.fromstring(manifest_text)
                package = root.attrib.get("package")
                android = "{http://schemas.android.com/apk/res/android}"
                permissions = sorted({node.attrib.get(android + "name", "") for node in root.findall("uses-permission") if node.attrib.get(android + "name")})
                sdk_node = root.find("uses-sdk")
                if sdk_node is not None:
                    sdk = {"min": sdk_node.attrib.get(android + "minSdkVersion"), "target": sdk_node.attrib.get(android + "targetSdkVersion")}
            except ET.ParseError:
                pass
        dex_analysis = _analyze_apk_dex(path, dex, dex_bytes)
        return {"source_type": "apk", "path": str(path), "sha256": _sha256(path), "size_bytes": size, "package": package, "manifest_status": manifest_status, "permissions": permissions, "sdk": sdk, "dex_files": dex, "dex_analysis": dex_analysis, "native_libraries": native, "archive_entry_count": len(infos), "findings": _manifest_findings(manifest_text), "limitations": ["APK is analyzed statically and is never executed.", "DEX analysis can inventory class/method symbols and call references, but cannot reliably recover original source code or original source line numbers.", "DEX call-graph analysis is skipped when the total DEX payload exceeds 64 MiB or the method count exceeds 15,000.", "Binary AndroidManifest.xml decoding and DEX cross-reference analysis use the optional androguard extra."]}


def analyze_source(path: str | Path) -> dict[str, Any]:
    from .flow_analysis_advanced import analyze_python_flows
    from .java_flow_analysis import analyze_java_flows
    from .semgrep_analysis import analyze_with_semgrep

    result = code_audit.analyze_source(path)
    flows = analyze_python_flows(path)
    java = analyze_java_flows(path)
    semgrep = analyze_with_semgrep(path)

    # When the Java AST engine is available, it replaces broad Java taint
    # matches. This keeps Java findings tied to a modeled source-to-sink path.
    semgrep_findings = semgrep["findings"]
    if java["available"]:
        parsed_java = set(java.get("analyzed_files", []))
        semgrep_findings = [
            item for item in semgrep_findings
            if not (
                str(item.get("rule_id", "")).startswith("auto-find-bug.java.")
                and str(item.get("file", "")).replace("\\", "/") in parsed_java
            )
        ]

    result["findings"].extend(flows["findings"])
    result["findings"].extend(java["findings"])
    result["findings"].extend(semgrep_findings)
    result["finding_count"] = len(result["findings"])
    result["flow_analysis"] = {
        "python": {
            "engine": flows["engine"],
            "files_analyzed": flows["files_analyzed"],
            "finding_count": flows["finding_count"],
            "limitations": flows["limitations"],
        },
        "java": {
            "engine": java["engine"],
            "available": java["available"],
            "files_analyzed": java["files_analyzed"],
            "finding_count": java["finding_count"],
            "analyzed_files": java.get("analyzed_files", []),
            "note": java["note"],
            "limitations": java["limitations"],
        },
        "semgrep": {
            "engine": semgrep["engine"],
            "available": semgrep["available"],
            "files_analyzed": semgrep["files_analyzed"],
            "finding_count": len(semgrep_findings),
            "note": semgrep["note"],
        },
    }
    result["limitations"].extend(flows["limitations"])
    result["limitations"].extend(java["limitations"])
    if not java["available"]:
        result["limitations"].append(java["note"])
    if not semgrep["available"]:
        result["limitations"].append(semgrep["note"])
    elif semgrep["note"] and "Only bundled local rules" not in semgrep["note"]:
        result["limitations"].append(semgrep["note"])
    result["source_type"] = "source_code"
    return result


def _merge_findings(workspace: Path, incoming: list[dict[str, Any]]) -> dict[str, Any]:
    path = workspace / "findings" / "findings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot read workspace findings: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            raise ValueError("Workspace findings file has an unsupported structure.")
    else:
        data = {"findings": []}
    existing = {item.get("finding_id"): item for item in data["findings"] if item.get("finding_id")}
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    for raw in incoming:
        item = dict(raw)
        item.setdefault("validation_status", "not_validated")
        item.setdefault("impact_assessment", "requires_manual_review")
        item.setdefault("reproducibility", "not_attempted")
        rule_context = {
            "FLOW-PY-001": ("CWE-95", "Request-controlled data reaches dynamic code execution.", "If the input is attacker-controlled and reachable without a strict allowlist, code execution in the application context may be possible.", "Confirm input control, route reachability, and whether a safe parser or strict allowlist constrains the value."),
            "FLOW-PY-002": ("CWE-78", "Request-controlled data reaches an operating-system command sink.", "If interpreted by a shell, command injection and unintended process actions may be possible.", "Confirm the subprocess API, shell mode, argument boundaries, and external controllability."),
            "FLOW-PY-003": ("CWE-89", "Request-controlled data reaches a database query string.", "If the driver interprets the value as query syntax rather than a bound parameter, query manipulation or unauthorized data access may be possible.", "Confirm the database driver, query construction, parameter binding, and whether user input influences query text."),
            "FLOW-PY-004": ("CWE-79", "Request-controlled data reaches a raw HTML rendering sink.", "If emitted into a browser context without contextual escaping, script injection may be possible.", "Confirm the rendered context, escaping behavior, content policy, and user control of the value."),
            "FLOW-JAVA-001": ("CWE-89", "Servlet request data reaches a recognized SQL query sink through a modeled Java flow.", "If the database interprets attacker-controlled data as query syntax, SQL injection may be possible.", "Confirm the JDBC/framework API, query construction, parameter binding, runtime reachability, and authorization context."),
            "FLOW-JAVA-002": ("CWE-78", "Servlet request data reaches a recognized process execution sink through a modeled Java flow.", "If attacker-controlled input influences a process command, command injection or unintended process execution may be possible.", "Confirm the exact Runtime/ProcessBuilder API, argument boundaries, operating-system interpretation, and input constraints."),
            "ACCESS-PY-001": ("CWE-862", "A sensitive-looking route has no recognized local authorization marker.", "If externally reachable and no middleware or service-layer authorization exists, unauthorized actions or data access may be possible.", "Inspect router dependencies, global middleware, decorators, service-layer checks, object ownership, and role enforcement."),
            "APK-CONFIG-001": ("CWE-489", "The APK manifest enables the debuggable application flag.", "In a release context this may expose debugging capabilities or diagnostic data; impact depends on build and deployment conditions.", "Confirm this is a production build and review the actual debug configuration and exposed data."),
            "APK-NET-001": ("CWE-319", "The APK manifest permits cleartext network traffic.", "Sensitive traffic could be exposed or modified on an untrusted network if sent over cleartext channels.", "Confirm whether cleartext requests occur, what data they carry, and whether network security configuration narrows the exception."),
            "APK-COMP-001": ("CWE-926", "An exported Android component has no component-level permission declared.", "Other applications may be able to invoke the component; impact depends on its actions, input validation, and application-level authorization.", "Confirm component reachability, intent filters, caller checks, data handled, and runtime protection."),
        }
        context = rule_context.get(item.get("rule_id"))
        if context:
            item.setdefault("cwe", context[0])
            item.setdefault("root_cause", context[1])
            item.setdefault("potential_impact", context[2])
            item.setdefault("confirmation_conditions", context[3])
        identity = "|".join(str(item.get(key, "")) for key in ("rule_id", "file", "line", "component", "evidence", "advisory_id"))
        item["finding_id"] = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        previous = existing.get(item["finding_id"], {})
        item["status"] = previous.get("status", "potential")
        item["validation_status"] = "human_review_recorded" if item["status"] == "validated" else "not_validated"
        item["reviewer_note"] = previous.get("reviewer_note")
        item["evidence_ref"] = previous.get("evidence_ref")
        item["first_seen_at"] = previous.get("first_seen_at", now)
        item["last_seen_at"] = now
        raw.update(item)
        existing[item["finding_id"]] = item
    data["findings"] = sorted(existing.values(), key=lambda item: (str(item.get("file", "")), item.get("line") or 0, item.get("rule_id", "")))
    statuses = [item.get("status", "potential") for item in data["findings"]]
    data["counts"] = {key: statuses.count(key) for key in ("potential", "needs_review", "validated", "false_positive")}
    data["counts"]["total"] = len(statuses)
    if data["counts"]["validated"]:
        data["status"] = "validated_findings_present_manual_review"
    elif data["counts"]["potential"] or data["counts"]["needs_review"]:
        data["status"] = "needs_manual_review"
    elif data["counts"]["false_positive"]:
        data["status"] = "no_open_findings"
    else:
        data["status"] = "no_findings"
    data["network_activity"] = "public_advisory_api_only" if data.get("online_correlation") else "none"
    data["updated_at"] = now
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return data


def run_analysis(input_path: str | Path, workspace_path: str | Path | None = None, online: bool = False) -> dict[str, Any]:
    from datetime import datetime, timezone
    from .online_intelligence import correlate_dependencies

    source = Path(input_path).expanduser().resolve()
    if not source.exists():
        raise ValueError(f"Input path does not exist: {source}")
    if source.is_file() and source.suffix.lower() == ".apk":
        result = analyze_apk(source)
        dependencies = {"root": str(source.parent), "manifests": [], "dependency_count": 0, "dependencies": []}
        incoming = [dict(item, source_type="apk") for item in result["findings"]]
    else:
        result = analyze_source(source)
        dependencies = discover_dependencies(source)
        incoming = [dict(item, source_type="source_code") for item in result["findings"]]
    correlation = None
    if online:
        correlation = correlate_dependencies(dependencies["dependencies"])
        for match in correlation["results"]:
            for advisory in match["advisories"]:
                incoming.append({
                    "rule_id": "DEP-OSV-001", "severity": "UNKNOWN",
                    "title": f"Public OSV advisory match: {advisory['id']}",
                    "file": ", ".join(match["manifests"]), "line": None,
                    "component": f"{match['ecosystem']}:{match['name']}@{match['version']}",
                    "evidence": f"Exact package version matched OSV record {advisory['id']}",
                    "recommendation": "Review the advisory's affected ranges and applicability; update to a fixed version when appropriate.",
                    "confidence": "medium", "source_type": "dependency_advisory",
                    "advisory_id": advisory["id"], "advisory_url": advisory["url"],
                    "advisory_source": correlation["source"],
                })
    if workspace_path:
        workspace = Path(workspace_path).expanduser().resolve()
        if not workspace.is_dir():
            raise ValueError(f"Workspace directory does not exist: {workspace}")
    else:
        workspace = Path("tools/outdata/source-intelligence").resolve() / datetime.now().strftime("%Y%m%d-%H%M%S")
        workspace.mkdir(parents=True, exist_ok=True)
    si = workspace / "source-intelligence"
    si.mkdir(parents=True, exist_ok=True)
    (si / "analysis.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (si / "dependency-inventory.json").write_text(json.dumps(dependencies, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if correlation is not None:
        online_dir = workspace / "online-intelligence"
        online_dir.mkdir(parents=True, exist_ok=True)
        (online_dir / "osv-correlation.json").write_text(json.dumps(correlation, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    findings = _merge_findings(workspace, incoming)
    findings["network_activity"] = "public_advisory_api_only" if online else "none"
    findings["source_intelligence"] = {
        "input": str(source), "analysis": "source-intelligence/analysis.json",
        "dependency_inventory": "source-intelligence/dependency-inventory.json",
        "online_correlation": bool(online),
    }
    if correlation is not None:
        findings["online_correlation"] = {
            "source": correlation["source"], "queried": correlation["queried"],
            "advisory_matches": sum(item["advisory_count"] for item in correlation["results"]),
        }
    (workspace / "findings" / "findings.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    from .workspace_review import _write_reports
    _write_reports(workspace, findings, result)
    report_dir = workspace / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Source Intelligence Report", "",
        f"- Input: {source}", f"- Input type: {result.get('source_type', 'source_code')}",
        f"- New review leads: {len(incoming)}", f"- Dependencies inventoried: {dependencies['dependency_count']}",
        f"- Online OSV correlation: {'enabled' if online else 'disabled'}",
        f"- Python data-flow files: {result.get('flow_analysis', {}).get('python', {}).get('files_analyzed', 0)}",
        f"- Python data-flow review leads: {result.get('flow_analysis', {}).get('python', {}).get('finding_count', 0)}",
        f"- Java AST files: {result.get('flow_analysis', {}).get('java', {}).get('files_analyzed', 0)}",
        f"- Java AST review leads: {result.get('flow_analysis', {}).get('java', {}).get('finding_count', 0)}",
        f"- Java AST available: {result.get('flow_analysis', {}).get('java', {}).get('available', False)}",
        f"- Semgrep available: {result.get('flow_analysis', {}).get('semgrep', {}).get('available', False)}",
        f"- Semgrep review leads: {result.get('flow_analysis', {}).get('semgrep', {}).get('finding_count', 0)}", "",
        "## Findings", "",
    ]
    if result.get("dex_analysis"):
        dex = result["dex_analysis"]
        lines.extend([
            "## APK DEX analysis", "",
            f"- Status: {dex.get('status')}",
            f"- Classes: {dex.get('class_count')}",
            f"- Methods: {dex.get('method_count')}",
            f"- Call graph edges: {dex.get('call_graph_edges')}",
            f"- Call graph sample entries: {len(dex.get('call_graph_sample', []))}",
            f"- Note: {dex.get('note', 'Method-level metadata is not original source code.')}", "",
        ])
    if not incoming:
        lines.append("No review leads were emitted by the enabled checks.")
    for item in incoming:
        location = f"{item.get('file')}:{item.get('line')}" if item.get("line") else f"{item.get('file')} / {item.get('component', 'component')}"
        lines.extend([
            f"### {item.get('rule_id')} — {item.get('title')}", "",
            f"- Severity: {item.get('severity')}", f"- Location: {location}",
            f"- Evidence: {item.get('evidence')}", f"- Confidence: {item.get('confidence')}",
            f"- Recommendation: {item.get('recommendation')}",
            f"- Advisory: {item.get('advisory_url', 'Not applicable')}",
            f"- CWE: {item.get('cwe', 'Not mapped')}",
            f"- Root cause: {item.get('root_cause', 'Requires manual source review')}",
            f"- Potential impact if confirmed: {item.get('potential_impact', 'Not assessed')}",
            f"- Conditions to confirm: {item.get('confirmation_conditions', 'Review context and applicability')}",
            f"- Validation: {item.get('validation_status', 'not_validated')}",
            f"- Impact assessment: {item.get('impact_assessment', 'requires_manual_review')}",
            f"- Reproducibility: {item.get('reproducibility', 'not_attempted')}",
        ])
        if item.get("flow"):
            flow = item["flow"]
            lines.extend([
                f"- Data-flow source: {flow.get('source')} at line {flow.get('source_line')}",
                f"- Data-flow sink: {flow.get('sink')} at line {flow.get('sink_line')}",
                f"- Function: {flow.get('function', 'unknown')}",
                f"- Source evidence: {flow.get('source_evidence', 'Not captured')}",
                f"- Variables: {', '.join(flow.get('variables', [])) or 'Direct flow'}",
                f"- Trace: {' -> '.join(flow.get('trace', []))}",
            ])
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend(result.get("limitations", []))
    lines.extend([
        "Static-analysis findings and advisory matches are review leads, not proof of exploitability.",
        "Source/APK inputs are not executed. Online mode contacts only the public OSV advisory API, not application targets.",
    ])
    (report_dir / "source-intelligence-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "workspace": str(workspace), "input": str(source), "input_type": result.get("source_type", "source_code"),
        "files_scanned": result.get("files_scanned", 0), "finding_count": len(incoming),
        "dependency_count": dependencies["dependency_count"], "online": online,
        "findings_path": str(workspace / "findings" / "findings.json"),
        "report_path": str(report_dir / "source-intelligence-report.md"),
        "analysis_path": str(si / "analysis.json"),
    }
