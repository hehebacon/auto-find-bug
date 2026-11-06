from __future__ import annotations

"""Read-only dependency advisory correlation against the public OSV batch API."""

from datetime import datetime, timezone
from typing import Any

import httpx

from .network import create_http_client

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_BATCH = 50
USER_AGENT = "auto-find-bug/0.8.2 (public advisory correlation)"


def _advisory_record(advisory: dict[str, Any]) -> dict[str, Any]:
    advisory_id = advisory.get("id")
    return {
        "id": advisory_id,
        "summary": advisory.get("summary"),
        "details": advisory.get("details"),
        "published": advisory.get("published"),
        "modified": advisory.get("modified"),
        "withdrawn": advisory.get("withdrawn"),
        "aliases": advisory.get("aliases") or [],
        "references": advisory.get("references") or [],
        "severity": advisory.get("severity") or [],
        # Preserve the authoritative affected ranges and ecosystem-specific
        # metadata so a match can be reviewed instead of inferred from title.
        "affected": advisory.get("affected") or [],
        "database_specific": advisory.get("database_specific") or {},
        "url": f"https://osv.dev/vulnerability/{advisory_id}" if advisory_id else None,
        "source": "OSV",
        "match_semantics": "OSV querybatch matched the exact package version supplied in the query; independently review affected ranges and package identity.",
    }


def correlate_dependencies(dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    exact = [
        item for item in dependencies
        if item.get("version_is_exact") and item.get("version")
        and item.get("ecosystem") and item.get("name")
    ]
    eligible = exact[:MAX_BATCH]
    skipped_without_exact = len(dependencies) - len(exact)
    skipped_batch_limit = max(0, len(exact) - len(eligible))
    queries = [
        {"package": {"ecosystem": item["ecosystem"], "name": item["name"]}, "version": item["version"]}
        for item in eligible
    ]
    base = {
        "source": OSV_BATCH_URL,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "queried": len(eligible),
        "skipped_without_exact_version": skipped_without_exact,
        "skipped_batch_limit": skipped_batch_limit,
    }
    if not queries:
        return {
            **base, "results": [],
            "note": "No exact lockfile versions were available for correlation; no network request was made.",
        }
    try:
        with create_http_client(
            timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            response = client.post(OSV_BATCH_URL, json={"queries": queries})
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError(f"OSV public advisory query failed ({type(exc).__name__}).") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise RuntimeError("OSV returned an invalid response schema; no dependency conclusions were recorded.")
    response_items = payload["results"]
    if len(response_items) != len(eligible):
        raise RuntimeError(
            f"OSV response count mismatch: queried {len(eligible)} packages but received {len(response_items)} results."
        )

    results = []
    for dependency, response_item in zip(eligible, response_items):
        if not isinstance(response_item, dict):
            raise RuntimeError("OSV returned a malformed per-package result; correlation was stopped.")
        raw_advisories = response_item.get("vulns") or []
        if not isinstance(raw_advisories, list):
            raise RuntimeError("OSV returned a malformed advisory list; correlation was stopped.")
        if any(not isinstance(item, dict) for item in raw_advisories):
            raise RuntimeError("OSV returned a malformed advisory record; correlation was stopped.")
        advisories = [_advisory_record(item) for item in raw_advisories]
        results.append({
            **dependency,
            "query_version": dependency["version"],
            "advisory_count": len(advisories),
            "advisories": advisories,
            "query_status": "matched_advisories" if advisories else "no_matching_advisories",
        })
    return {
        **base,
        "results": results,
        "note": (
            "OSV querybatch returned records for the exact package versions supplied. "
            "A returned advisory is a version-match lead, not proof of runtime exposure or exploitability. "
            "Review affected package identity, ranges, ecosystem, platform, reachability, and fixed versions."
        ),
    }
