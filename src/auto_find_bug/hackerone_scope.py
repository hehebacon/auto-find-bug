from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

from .network import create_http_client
from bs4 import BeautifulSoup


USER_AGENT = "auto-find-bug/0.2 (+read-only public scope inventory)"
MIRROR_HOST = "targets.bastet.ai"


def hackerone_handle_from_url(program_url: str) -> str | None:
    parsed = urlparse(program_url)
    if (parsed.hostname or "").lower() not in {"hackerone.com", "www.hackerone.com"}:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if not parts or parts[0] in {"directory", "hacktivity", "reports", "users"}:
        return None
    handle = parts[0].lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", handle):
        return None
    return handle


def _require_public_host(host: str) -> None:
    try:
        addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, 443)}
    except (OSError, ValueError):
        raise ValueError("Public scope source could not be resolved.") from None
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("Public scope source did not resolve exclusively to public IP addresses.")


def _parse_assets(soup: BeautifulSoup) -> list[dict]:
    asset_pattern = re.compile(
        r"(?m)^[ \t]*([^\n]+?)[ \t]*\n[ \t]*Type:[ \t]*([^\n]+)\n"
        r"[ \t]*Submission eligible:[ \t]*(yes|no)\n"
        r"[ \t]*Bounty eligible:[ \t]*(yes|no)\n"
        r"[ \t]*Maximum severity:[ \t]*([^\n]+)",
        re.IGNORECASE,
    )
    assets: list[dict] = []
    for block in soup.find_all("pre"):
        block_text = block.get_text("\n", strip=True)
        if "Submission eligible:" not in block_text:
            continue
        for match in asset_pattern.finditer(block_text):
            identifier = match.group(1).strip().strip("`").strip()
            assets.append({
                "asset_identifier": identifier,
                "asset_type": match.group(2).strip(),
                "submission_eligible": match.group(3).lower() == "yes",
                "bounty_eligible": match.group(4).lower() == "yes",
                "maximum_severity": match.group(5).strip(),
                "verification_status": "third_party_snapshot_unverified",
            })
    return assets


def fetch_hackerone_public_snapshot(program_url: str) -> dict:
    """Fetch a read-only third-party snapshot for a public HackerOne program.

    This is inventory assistance only. The mirror may be stale and omits some
    exclusions; it must never be treated as authorization to test.
    """
    handle = hackerone_handle_from_url(program_url)
    if not handle:
        raise ValueError("The URL is not a supported HackerOne program URL.")

    _require_public_host(MIRROR_HOST)
    snapshot_url = f"https://{MIRROR_HOST}/programs/{quote(handle, safe='')}/public-scope/"
    with create_http_client(
        follow_redirects=False,
        timeout=20.0,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html"},
    ) as client:
        response = client.get(snapshot_url)
        if response.is_redirect:
            raise ValueError("The public scope source redirected; refusing to follow it.")
        response.raise_for_status()
        if "text/html" not in response.headers.get("content-type", "").lower():
            raise ValueError("The public scope source did not return HTML.")
        html = response.text[:5_000_000]

    soup = BeautifulSoup(html, "html.parser")
    text = re.sub(r"\n{3,}", "\n\n", soup.get_text("\n", strip=True))
    assets = _parse_assets(soup)
    if not assets:
        raise ValueError("The public snapshot page contained no parseable structured assets.")

    verified_match = re.search(r"Publicly verified:\s*([^\n]+)", text, re.IGNORECASE)
    state_match = re.search(r"Program state:\s*([^\n]+)", text, re.IGNORECASE)
    submission_match = re.search(r"Submission state:\s*([^\n]+)", text, re.IGNORECASE)
    policy_blocks = [
        block.get_text("\n", strip=True)
        for block in soup.find_all("pre")
        if "Program Policy" in block.get_text(" ", strip=True)
    ]
    policy_text = policy_blocks[0] if policy_blocks else ""

    return {
        "program_handle": handle,
        "source_url": snapshot_url,
        "canonical_policy_url": program_url,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "snapshot_publicly_verified_at": verified_match.group(1).strip() if verified_match else None,
        "program_state": state_match.group(1).strip() if state_match else None,
        "submission_state": submission_match.group(1).strip() if submission_match else None,
        "source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "assets": assets,
        "asset_count": len(assets),
        "policy_text": policy_text,
        "exclusions_complete": False,
        "source_trust": "third_party_mirror_not_authoritative",
        "limitations": [
            "Snapshot freshness depends on the third-party publisher.",
            "Separate scope-exclusion records may be absent.",
            "The current HackerOne policy and scope page remain authoritative.",
            "This inventory is not permission to test any asset.",
        ],
        "page_text": text,
        "page_html": html,
    }
