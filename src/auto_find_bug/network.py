from __future__ import annotations

import httpx


def create_http_client(**kwargs) -> httpx.Client:
    """Create a regular HTTP client using the machine's standard network settings.

    httpx respects the normal proxy environment variables by default. No
    project-specific proxy, privacy mode, or IP-hiding configuration is used.
    """
    return httpx.Client(**kwargs)


def network_status() -> dict:
    """Describe the standard connection mode without implying anonymity."""
    return {
        "mode": "standard",
        "system_proxy_environment": "respected_by_httpx",
        "note": "Requests use the normal network route. Public services may see the public IP address used by the connection.",
    }
