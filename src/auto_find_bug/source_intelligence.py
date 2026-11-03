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
        if not path.is_file() or any(part in ignored for part in path.parts) or path.stat().st_size > 2_000_000:
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
        for info in infos:
            member = PurePosixPath(info.filename)
            if member.is_absolute() or ".." in member.parts or info.file_size > MAX_APK_BYTES:
                raise ValueError("APK contains an unsafe or oversized archive entry.")
        names = [item.filename for item in infos]
        manifest_status = "missing"
        manifest_text = ""
        if "AndroidManifest.xml" in names:
            raw = archive.read("AndroidManifest.xml")
            try:
                manifest_text = raw.decode("utf-8")
                ET.fromstring(manifest_text)
                manifest_status = "text_xml"
            except (UnicodeDecodeError, ET.ParseError):
                manifest_status = "binary_xml_requires_optional_decoder"
        dex = [name for name in names if re.fullmatch(r"classes(?:\d+)?\.dex", PurePosixPath(name).name)]
        native = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
        permissions: list[str] = []
        package = None
        sdk = {}
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
        return {"source_type": "apk", "path": str(path), "sha256": _sha256(path), "size_bytes": size, "package": package, "manifest_status": manifest_status, "permissions": permissions, "sdk": sdk, "dex_files": dex, "native_libraries": native, "archive_entry_count": len(infos), "findings": _manifest_findings(manifest_text), "limitations": ["APK is analyzed statically and is never executed.", "Compiled APKs do not contain the original source tree or reliable original source line numbers.", "Binary AndroidManifest.xml decoding is not included in this base build; supply matching source or add an approved Android manifest decoder for deeper metadata."]}


def analyze_source(path: str | Path) -> dict[str, Any]:
    result = code_audit.analyze_source(path)
    result["source_type"] = "source_code"
    return result
