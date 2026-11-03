from __future__ import annotations

import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"(?i)(?<![a-z0-9.-])(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![a-z0-9.-])")
URL_RE = re.compile(r"https?://[^\s<>()\[\]{}"']+", re.I)


def extract_scope_candidates(policy_text: str) -> list[str]:
    found: set[str] = set()
    for raw in URL_RE.findall(policy_text):
        parsed = urlparse(raw.rstrip(".,;:"))
        if parsed.hostname:
            host = parsed.hostname.lower().rstrip(".")
            if not host.startswith("*."):
                found.add(host)
    for match in DOMAIN_RE.findall(policy_text):
        host = match.lower().removeprefix("*.")
        if not match.startswith("*."):
            found.add(host)
    return sorted(found)


def normalize_confirmed_assets(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        item = value.strip().lower().rstrip(".")
        if not item or "*" in item or "/" in item or "://" in item:
            continue
        if DOMAIN_RE.fullmatch(item) and item not in normalized:
            normalized.append(item)
    return normalized
