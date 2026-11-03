from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

USER_AGENT = "auto-find-bug/0.1 (low-impact program-scope metadata check)"
SAFE_HEADERS = (
    "server", "content-type", "content-length", "strict-transport-security",
    "content-security-policy", "x-content-type-options", "x-frame-options",
    "referrer-policy", "permissions-policy",
)


def _safe_target(asset: str) -> str:
    parsed = urlparse(asset if "://" in asset else f"https://{asset}")
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/"):
        raise ValueError(f"Not a plain HTTPS hostname: {asset}")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError(f"Non-standard target rejected: {asset}")
    return f"https://{parsed.hostname}/"


def run_metadata_checks(assets: list[str], output_dir: Path, delay_seconds: float = 1.0) -> list[dict]:
    """One HEAD request per manually confirmed hostname; no crawling or payloads."""
    results: list[dict] = []
    output_dir.mkdir(parents=True, exist_ok=True)
    for index, asset in enumerate(assets):
        target = _safe_target(asset)
        record: dict = {"asset": asset, "url": target, "checked_at": datetime.now(timezone.utc).isoformat()}
        try:
            with httpx.Client(
                follow_redirects=False, timeout=8.0, verify=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                response = client.head(target)
            record.update({
                "status_code": response.status_code,
                "headers": {key: response.headers.get(key) for key in SAFE_HEADERS if response.headers.get(key)},
                "redirect_location_present": "location" in response.headers,
                "note": "Observation only; a missing header is not by itself a confirmed vulnerability.",
            })
        except (httpx.HTTPError, ValueError) as exc:
            record["error"] = type(exc).__name__
            record["note"] = "Request failed; no further probing was attempted."
        serialized = json.dumps(record, sort_keys=True, ensure_ascii=False)
        record["evidence_sha256"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        safe_name = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in asset)
        (output_dir / f"{index + 1:03d}-{safe_name}.json").write_text(
            json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        results.append(record)
        if index < len(assets) - 1:
            time.sleep(max(1.0, delay_seconds))
    return results
