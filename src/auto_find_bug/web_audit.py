from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from .network import create_http_client

MAX_BODY_BYTES = 1_000_000
USER_AGENT = "auto-find-bug/0.3.0 (passive security posture review)"


def validate_audit_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Enter an HTTPS URL. HTTP and non-web schemes are not accepted.")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("Credentials and non-standard ports are not accepted.")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Localhost URLs are not accepted.")
    try:
        addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    except (OSError, ValueError):
        raise ValueError("The website hostname could not be resolved.") from None
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("The website must resolve only to public IP addresses.")
    return value


def _finding(rule_id: str, severity: str, title: str, detail: str, recommendation: str) -> dict:
    return {"rule_id": rule_id, "severity": severity, "title": title, "detail": detail, "recommendation": recommendation}


def _access_gate_signals(headers: dict, body: str, status_code: int) -> tuple[list[str], bool]:
    """Classify access restrictions without attempting to get around them."""
    signals: list[str] = []
    lowered_headers = {str(key).lower(): str(value).lower() for key, value in headers.items()}
    lowered_body = body.lower()

    if status_code == 403:
        signals.append("http_403_access_denied")
    elif status_code == 429:
        signals.append("http_429_rate_limited")
    elif status_code == 503:
        signals.append("http_503_service_unavailable")

    for header in ("cf-mitigated", "x-datadome", "x-akamai-session-info", "x-sucuri-id"):
        if lowered_headers.get(header):
            signals.append("protection_header:" + header)
    if lowered_headers.get("cf-mitigated") == "challenge":
        signals.append("cloudflare_challenge_header")

    markers = (
        "cf-chl-", "challenge-platform", "captcha", "verify you are human",
        "datadome", "akamai bot manager", "perimeterx", "imperva",
        "px-captcha", "cloudflare ray id",
    )
    for marker in markers:
        if marker in lowered_body:
            signals.append("challenge_page_marker:" + marker)

    bot_detected = any(
        item.startswith("protection_header:")
        or item.startswith("challenge_page_marker:")
        or item == "cloudflare_challenge_header"
        for item in signals
    )
    return sorted(set(signals)), bot_detected


def audit_public_page(url: str, *, authorized: bool = False) -> dict:
    """Make one bounded GET to an operator-authorized HTTPS page; never crawl or probe."""
    if not authorized:
        raise ValueError("Confirm that you own this site or have explicit permission to review it.")
    url = validate_audit_url(url)
    try:
        with create_http_client(
            follow_redirects=False,
            timeout=httpx.Timeout(15.0, connect=8.0),
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
        ) as client:
            with client.stream("GET", url) as response:
                if response.is_redirect:
                    raise ValueError("The page redirected. Supply its final canonical HTTPS URL directly.")
                headers = dict(response.headers)
                content_type = response.headers.get("content-type", "").lower()
                status_code = response.status_code
                chunks = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_BODY_BYTES:
                        raise ValueError("The response body exceeds the 1 MB review limit.")
                    chunks.append(chunk)
                body = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
                gate_signals, bot_detected = _access_gate_signals(headers, body, status_code)
                if status_code in (403, 429, 503) or bot_detected:
                    if status_code == 429:
                        state = "rate_limited"
                    elif bot_detected:
                        state = "anti_bot_or_challenge_detected"
                    elif status_code == 403:
                        state = "access_denied"
                    else:
                        state = "upstream_unavailable"
                    finding = _finding(
                        "WEB-ACCESS-001", "INFO",
                        "Access restriction or automated-traffic challenge detected",
                        f"HTTP {status_code}; signals: {', '.join(gate_signals) or 'none'}",
                        "Stop automated requests. Use the site's documented API, request permission, or analyze an operator-provided export. Do not attempt to evade the restriction.",
                    )
                    return {
                        "scanner": "auto-find-bug-passive-web-review",
                        "url": url,
                        "http_status": status_code,
                        "content_type": content_type,
                        "access_state": state,
                        "anti_bot_detected": bot_detected,
                        "access_gate_signals": gate_signals,
                        "retry_after": headers.get("retry-after"),
                        "bytes_reviewed": len(body.encode("utf-8")),
                        "requests_sent": 1,
                        "crawl_performed": False,
                        "forms_submitted": False,
                        "payloads_sent": False,
                        "finding_count": 1,
                        "findings": [finding],
                        "limitations": [
                            "The tool records access restrictions and challenge signals only; it does not solve, evade, or retry challenges.",
                            "A 403 or 429 alone does not prove anti-bot protection; it may represent an ordinary access policy or rate limit.",
                            "Use documented APIs or data supplied by an authorized operator.",
                        ],
                    }
                response.raise_for_status()
                if "text/html" not in content_type:
                    raise ValueError("The supplied URL did not return HTML; this review supports one HTML page.")
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Could not retrieve the supplied page ({type(exc).__name__}).") from None

    findings = []
    checks = [
        ("SEC001", "MEDIUM", "Content-Security-Policy is missing", "content-security-policy", "Define a restrictive CSP; start with report-only mode and tune it for the application."),
        ("SEC002", "MEDIUM", "Strict-Transport-Security is missing", "strict-transport-security", "Enable HSTS after confirming all relevant subdomains support HTTPS."),
        ("SEC003", "LOW", "X-Content-Type-Options is missing", "x-content-type-options", "Set X-Content-Type-Options: nosniff."),
        ("SEC004", "LOW", "Referrer-Policy is missing", "referrer-policy", "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin."),
        ("SEC005", "LOW", "Permissions-Policy is missing", "permissions-policy", "Explicitly disable browser features the page does not need."),
    ]
    for rule_id, severity, title, header, recommendation in checks:
        if header not in headers:
            findings.append(_finding(rule_id, severity, title, f"Response header '{header}' was not present.", recommendation))

    soup = BeautifulSoup(body, "html.parser")
    for index, cookie in enumerate(headers.get("set-cookie", "").split("\n"), start=1):
        if not cookie.strip():
            continue
        lower = cookie.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lower]
        if missing:
            findings.append(_finding("SEC006", "MEDIUM", "Cookie missing recommended attributes",
                f"Set-Cookie entry {index} is missing: {', '.join(missing)}.",
                "Review whether the cookie needs Secure, HttpOnly, and an appropriate SameSite value."))

    insecure_forms = 0
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip().lower()
        if action.startswith("http://"):
            insecure_forms += 1
    if insecure_forms:
        findings.append(_finding("SEC007", "HIGH", "Form submits to an HTTP URL",
            f"{insecure_forms} form(s) declare an insecure HTTP action.",
            "Submit sensitive form data only over HTTPS and verify the destination is correct."))

    external_scripts_without_sri = 0
    for script in soup.find_all("script", src=True):
        src = str(script.get("src", ""))
        if src.startswith(("https://", "//")) and not script.get("integrity"):
            external_scripts_without_sri += 1
    if external_scripts_without_sri:
        findings.append(_finding("SEC008", "INFO", "External scripts lack Subresource Integrity",
            f"{external_scripts_without_sri} external script(s) do not declare an integrity attribute.",
            "For stable third-party assets, consider Subresource Integrity and crossorigin where supported."))

    return {
        "scanner": "auto-find-bug-passive-web-review",
        "url": url,
        "http_status": status_code,
        "content_type": content_type,
        "access_state": "accessible",
        "anti_bot_detected": False,
        "access_gate_signals": [],
        "bytes_reviewed": len(body.encode("utf-8")),
        "requests_sent": 1,
        "crawl_performed": False,
        "forms_submitted": False,
        "payloads_sent": False,
        "finding_count": len(findings),
        "findings": findings,
        "limitations": [
            "This is a single-page, read-only posture review, not an active vulnerability scan.",
            "Missing headers and HTML patterns are hardening observations, not proof of an exploitable vulnerability.",
            "No login, form submission, payload, endpoint enumeration, crawling, or intrusive testing is performed.",
            "If a 403/429/503 or anti-bot challenge is detected, the tool stops and records it without evasion or automatic retry.",
            "Review only sites you own or are explicitly authorized to assess.",
        ],
    }


def write_web_report(result: dict, output: str | Path, fmt: str = "md") -> Path:
    if fmt not in {"md", "json"}:
        raise ValueError("Format must be md or json.")
    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        lines = ["# Passive Web Security Review", "", f"- URL: {result['url']}", f"- HTTP status: {result['http_status']}", f"- Requests sent: {result['requests_sent']}", f"- Findings: {result['finding_count']}", ""]
        for item in result["findings"]:
            lines.extend([f"## {item['severity']} — {item['title']}", "", f"- Rule: {item['rule_id']}", f"- Detail: {item['detail']}", f"- Recommendation: {item['recommendation']}", ""])
        lines.extend(["## Limitations", *[f"- {item}" for item in result["limitations"]], ""])
        path.write_text("\n".join(lines), encoding="utf-8")
    return path
