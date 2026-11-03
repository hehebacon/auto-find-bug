from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup


USER_AGENT = "auto-find-bug/0.1 (+scope-first policy review)"
MIN_POLICY_TEXT_LENGTH = 120


def validate_program_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// program policy URL.")
    if parsed.username or parsed.password or parsed.port not in (None, 80, 443):
        raise ValueError("Credentials and non-standard ports are not accepted.")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Localhost policy URLs are not accepted.")
    try:
        addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None)}
    except (OSError, ValueError):
        raise ValueError("The policy hostname could not be resolved.") from None
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("Policy URL must resolve only to public IP addresses.")
    return value


def fetch_policy(url: str) -> tuple[str, str]:
    """Fetch only the supplied public policy page; redirects and linked targets are not followed."""
    with httpx.Client(
        follow_redirects=False,
        timeout=15.0,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        response = client.get(url)
        if response.is_redirect:
            raise ValueError("The policy page redirected. Enter its final canonical URL directly.")
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


def policy_extraction_incomplete(text: str) -> bool:
    """Detect pages whose visible HTML contains only a shell/title, not usable policy text."""
    cleaned = re.sub(r"\s+", " ", text).strip()
    return len(cleaned) < MIN_POLICY_TEXT_LENGTH


def load_manual_policy_text(path_value: str) -> str:
    """Load policy text manually saved by the operator; never fetch additional URLs."""
    path = Path(path_value).expanduser()
    if not path.is_file():
        raise ValueError("That path is not a readable file.")
    try:
        text = path.read_text(encoding="utf-8-sig").strip()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Could not read the file ({type(exc).__name__}).") from None
    if len(text) < 40:
        raise ValueError("The file is still too short to contain usable policy text.")
    return text
