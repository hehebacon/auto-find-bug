from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from .network import create_http_client, privacy_status

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "tools" / "outdata" / "public-research" / "research.sqlite3"
MAX_RESULTS = 100
TAXONOMY = {
    "Authentication": ("authentication", "auth bypass", "login", "password", "credential", "mfa", "multi-factor"),
    "Authorization/access control": ("authorization", "access control", "privilege escalation", "idor", "permission", "improper access"),
    "Session management": ("session", "cookie", "token", "csrf", "cross-site request forgery"),
    "Input handling": ("injection", "cross-site scripting", "xss", "sql injection", "command injection", "deserialization", "path traversal", "ssrf"),
    "Sensitive-data exposure": ("information disclosure", "sensitive information", "data leak", "exposure of", "confidentiality"),
    "Business logic": ("business logic", "race condition", "workflow", "payment", "transaction"),
    "Mobile application security": ("android", "ios", "mobile application", "mobile app"),
    "Configuration and transport": ("misconfiguration", "tls", "ssl", "http", "certificate", "configuration", "default configuration"),
}


class ResearchError(RuntimeError):
    pass


def database_path() -> Path:
    raw = os.getenv("AFB_RESEARCH_DB", "").strip()
    return Path(raw).expanduser() if raw else DEFAULT_DB


def _connect() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("""
        CREATE TABLE IF NOT EXISTS advisories (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            published TEXT,
            modified TEXT,
            severity TEXT,
            cvss REAL,
            cwes TEXT NOT NULL DEFAULT '[]',
            categories TEXT NOT NULL DEFAULT '[]',
            references_json TEXT NOT NULL DEFAULT '[]',
            exploited INTEGER NOT NULL DEFAULT 0,
            source_url TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            imported_at TEXT NOT NULL
        )
    """)
    connection.execute("CREATE INDEX IF NOT EXISTS idx_advisories_published ON advisories(published)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_advisories_source ON advisories(source)")
    return connection


def _classify(text: str) -> list[str]:
    lowered = text.casefold()
    return [category for category, terms in TAXONOMY.items() if any(term in lowered for term in terms)] or ["Unclassified / manual review"]


def _severity(score: float | None, supplied: str | None = None) -> str:
    if supplied:
        return supplied.upper()
    if score is None:
        return "UNKNOWN"
    if score == 0:
        return "NONE"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if score < 9:
        return "HIGH"
    return "CRITICAL"


def _nvd_metrics(cve: dict[str, Any]) -> tuple[float | None, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            score = data.get("baseScore")
            try:
                value = float(score) if score is not None else None
            except (TypeError, ValueError):
                value = None
            return value, _severity(value, data.get("baseSeverity"))
    return None, "UNKNOWN"


def _description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"])[:12000]
    return str(descriptions[0].get("value", ""))[:12000] if descriptions else "No description supplied."


def _weaknesses(cve: dict[str, Any]) -> list[str]:
    values: set[str] = set()
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = description.get("value")
            if value:
                values.add(str(value))
    return sorted(values)


def _references(cve: dict[str, Any]) -> list[str]:
    values = []
    for item in cve.get("references") or []:
        url = item.get("url")
        if url and str(url).startswith("https://"):
            values.append(str(url))
    return list(dict.fromkeys(values))[:30]


def _save(items: list[dict[str, Any]]) -> int:
    if not items:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as db:
        for item in items:
            db.execute("""
                INSERT INTO advisories (
                    id, source, title, summary, published, modified, severity, cvss,
                    cwes, categories, references_json, exploited, source_url, raw_json, imported_at
                ) VALUES (
                    :id, :source, :title, :summary, :published, :modified, :severity, :cvss,
                    :cwes, :categories, :references_json, :exploited, :source_url, :raw_json, :imported_at
                )
                ON CONFLICT(id) DO UPDATE SET
                    source=excluded.source, title=excluded.title, summary=excluded.summary,
                    published=excluded.published, modified=excluded.modified,
                    severity=excluded.severity, cvss=excluded.cvss, cwes=excluded.cwes,
                    categories=excluded.categories, references_json=excluded.references_json,
                    exploited=excluded.exploited, source_url=excluded.source_url,
                    raw_json=excluded.raw_json, imported_at=excluded.imported_at
            """, {
                **item,
                "cwes": json.dumps(item["cwes"]),
                "categories": json.dumps(item["categories"]),
                "references_json": json.dumps(item["references"]),
                "raw_json": json.dumps(item["raw"], ensure_ascii=False),
                "imported_at": now,
            })
    return len(items)


def _http_client(timeout: float = 25.0) -> httpx.Client:
    return create_http_client(
        timeout=httpx.Timeout(timeout, connect=10.0),
        follow_redirects=False,
        headers={"User-Agent": "auto-find-bug/0.2.0 (public-advisory-research; contact: project-maintainer)"},
    )


def search_nvd(keyword: str, limit: int = 25) -> dict[str, Any]:
    keyword = keyword.strip()
    if len(keyword) < 2:
        raise ValueError("Search keyword must contain at least 2 characters.")
    if len(keyword) > 200:
        raise ValueError("Search keyword must be 200 characters or fewer.")
    if not 1 <= limit <= MAX_RESULTS:
        raise ValueError(f"Limit must be between 1 and {MAX_RESULTS}.")
    try:
        with _http_client() as client:
            response = client.get(NVD_API, params={"keywordSearch": keyword, "resultsPerPage": limit, "startIndex": 0})
            response.raise_for_status()
            payload = response.json()
    except PrivacyConfigurationError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise ResearchError(f"NVD request failed ({type(exc).__name__}). Check proxy configuration, rate limits, and connectivity.") from exc

    records = []
    for wrapper in payload.get("vulnerabilities") or []:
        cve = wrapper.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        summary = _description(cve)
        score, severity = _nvd_metrics(cve)
        title = f"{cve_id}: {summary[:160].rstrip()}"
        records.append({
            "id": str(cve_id), "source": "NVD", "title": title, "summary": summary,
            "published": cve.get("published"), "modified": cve.get("lastModified"),
            "severity": severity, "cvss": score, "cwes": _weaknesses(cve),
            "categories": _classify(summary), "references": _references(cve),
            "exploited": False, "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "raw": cve,
        })
    saved = _save(records)
    return {
        "query": keyword, "total_results_reported": int(payload.get("totalResults") or len(records)),
        "fetched": len(records), "saved_or_updated": saved, "database": str(database_path()),
        "records": records,
        "source": NVD_API,
        "note": "Public NVD records only. Search matches are not proof of exploitability, current exposure, or zero-day status.",
    }


def sync_cisa_kev() -> dict[str, Any]:
    try:
        with _http_client(timeout=40.0) as client:
            response = client.get(CISA_KEV_URL)
            response.raise_for_status()
            payload = response.json()
    except PrivacyConfigurationError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise ResearchError(f"CISA KEV feed request failed ({type(exc).__name__}).") from exc

    records = []
    for item in payload.get("vulnerabilities") or []:
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        summary = str(item.get("shortDescription") or item.get("vulnerabilityName") or "No description supplied.")[:12000]
        records.append({
            "id": str(cve_id), "source": "CISA KEV", "title": f"{cve_id}: {item.get('vulnerabilityName') or summary[:160]}",
            "summary": summary, "published": item.get("dateAdded"), "modified": None,
            "severity": "KNOWN_EXPLOITED_CATALOG", "cvss": None, "cwes": [],
            "categories": _classify(summary + " " + str(item.get("vulnerabilityName") or "")),
            "references": [str(item["notes"])] if str(item.get("notes", "")).startswith("https://") else [],
            "exploited": True, "source_url": CISA_KEV_URL, "raw": item,
        })
    saved = _save(records)
    return {
        "catalog_version": payload.get("catalogVersion"), "date_released": payload.get("dateReleased"),
        "fetched": len(records), "saved_or_updated": saved, "database": str(database_path()),
        "source": CISA_KEV_URL,
        "note": "KEV membership means CISA lists the CVE as known exploited in the wild; it does not establish exposure of any particular system.",
    }


def list_advisories(limit: int = 25, source: str | None = None, category: str | None = None) -> list[dict[str, Any]]:
    if not 1 <= limit <= 500:
        raise ValueError("Limit must be between 1 and 500.")
    with _connect() as db:
        rows = db.execute("SELECT * FROM advisories ORDER BY COALESCE(published, modified, imported_at) DESC LIMIT 500").fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["cwes"] = json.loads(item["cwes"])
        item["categories"] = json.loads(item["categories"])
        item["references"] = json.loads(item["references_json"])
        if source and item["source"].casefold() != source.casefold():
            continue
        if category and not any(category.casefold() in value.casefold() for value in item["categories"]):
            continue
        result.append(item)
        if len(result) >= limit:
            break
    return result


def research_status() -> dict[str, Any]:
    with _connect() as db:
        total = db.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
        sources = {row["source"]: row["count"] for row in db.execute("SELECT source, COUNT(*) AS count FROM advisories GROUP BY source")}
        latest = db.execute("SELECT MAX(imported_at) FROM advisories").fetchone()[0]
    return {"database": str(database_path()), "total_records": total, "by_source": sources, "last_imported_at": latest, "connection": privacy_status()}


def export_advisories(output: str | Path, fmt: str = "md", limit: int = 200) -> Path:
    if fmt not in {"md", "json"}:
        raise ValueError("Format must be md or json.")
    records = list_advisories(limit=limit)
    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        path.write_text(json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(), "records": records}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        lines = ["# Public Vulnerability Research Digest", "", f"- Generated: {datetime.now(timezone.utc).isoformat()}", f"- Records: {len(records)}", "- Sources: NVD and CISA KEV", "- This is public intelligence, not a target assessment or confirmation of exposure.", ""]
        for item in records:
            lines.extend([f"## {item['id']} — {item['severity']}", "", f"- Source: {item['source']}", f"- Published/added: {item['published'] or 'unknown'}", f"- CVSS: {item['cvss'] if item['cvss'] is not None else 'not supplied'}", f"- Categories: {', '.join(item['categories'])}", f"- Record: {item['source_url']}", "", item["summary"], ""])
        path.write_text("\n".join(lines), encoding="utf-8")
    return path
