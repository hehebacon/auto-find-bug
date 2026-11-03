from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup


USER_AGENT = "auto-find-bug/0.1 (+scope-first policy review)"


def validate_program_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// program policy URL.")
    return value.strip()


def fetch_policy(url: str) -> tuple[str, str]:
    """Fetch one public policy page only; do not crawl linked targets."""
    with httpx.Client(
        follow_redirects=True,
        timeout=15.0,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        response = client.get(url)
        response.raise_for_status()
        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            raise ValueError("The supplied URL did not return an HTML policy page.")
        html = response.text[:2_000_000]

    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "noscript", "svg"]):
        node.decompose()
    text = re.sub(r"\n{3,}", "\n\n", soup.get_text("\n", strip=True))
    return html, text
