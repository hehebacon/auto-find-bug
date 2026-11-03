from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from .network import create_http_client

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_BATCH = 50


def correlate_dependencies(dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    eligible = [
        item for item in dependencies
        if item.get("version_is_exact") and item.get("version")
        and item.get("ecosystem") and item.get("name")
    ][:MAX_BATCH]
    queries = [
        {"package": {"ecosystem": item["ecosystem"], "name": item["name"]}, "version": item["version"]}
        for item in eligible
    ]
    if not queries:
        return {
            "source": OSV_BATCH_URL, "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "queried": 0, "skipped_without_exact_version": len(dependencies),
            "results": [], "note": "No exact lockfile versions were available for correlation.",
        }
    try:
        with create_http_client(
            timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=False,
            headers={"User-Agent": "auto-find-bug/0.5.0 (public advisory correlation)"},
        ) as client:
            response = client.post(OSV_BATCH_URL, json={"queries": queries})
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError(f"OSV public advisory query failed ({type(exc).__name__}).") from exc

    results = []
    for dependency, response_item in zip(eligible, payload.get("results") or []):
        advisories = []
        for advisory in response_item.get("vulns") or []:
            advisory_id = advisory.get("id")
            advisories.append({
                "id": advisory_id, "summary": advisory.get("summary"),
                "published": advisory.get("published"), "modified": advisory.get("modified"),
                "aliases": advisory.get("aliases") or [],
                "url": f"https://osv.dev/vulnerability/{advisory_id}" if advisory_id else None,
            })
        results.append({**dependency, "advisory_count": len(advisories), "advisories": advisories})
    return {
        "source": OSV_BATCH_URL, "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "queried": len(eligible), "skipped_without_exact_version": len(dependencies) - len(eligible),
        "results": results,
        "note": "Advisory matches are leads only. Review affected ranges, platform applicability, reachability, and fixed versions before concluding that a project is vulnerable.",
    }
