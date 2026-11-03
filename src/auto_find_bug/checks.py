from __future__ import annotations

from urllib.parse import urlparse


def _safe_target(asset: str) -> str:
    """Validate a plain HTTPS hostname without contacting it."""
    parsed = urlparse(asset if "://" in asset else f"https://{asset}")
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/"):
        raise ValueError(f"Not a plain HTTPS hostname: {asset}")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError(f"Non-standard target rejected: {asset}")
    return f"https://{parsed.hostname}/"


def run_metadata_checks(assets: list[str], output_dir=None, delay_seconds: float = 1.0) -> list[dict]:
    """Network checks are intentionally disabled; use the offline review workflow."""
    raise RuntimeError(
        "Active target checks are disabled in this build. "
        "The CLI only prepares offline policy and scope review material."
    )
