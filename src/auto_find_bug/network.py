from __future__ import annotations

import os
from urllib.parse import urlparse
import httpx

class PrivacyConfigurationError(RuntimeError):
    pass

def privacy_mode_enabled() -> bool:
    return os.getenv('AFB_PRIVACY_MODE', '1').strip().lower() not in {'0', 'false', 'no', 'off'}

def configured_proxy() -> str | None:
    value = os.getenv('AFB_HTTPS_PROXY', '').strip()
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise PrivacyConfigurationError('AFB_HTTPS_PROXY must be an http:// or https:// proxy URL.')
    if parsed.query or parsed.fragment:
        raise PrivacyConfigurationError('Proxy URLs must not contain query strings or fragments.')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise PrivacyConfigurationError('The proxy port is invalid.')
    return value

def privacy_status() -> dict:
    proxy = configured_proxy()
    enabled = privacy_mode_enabled()
    return {
        'privacy_mode': enabled,
        'proxy_configured': bool(proxy),
        'online_access': 'proxy_only' if enabled and proxy else ('blocked_until_proxy_configured' if enabled else 'direct_or_environment_network'),
        'environment_proxy_trust': False,
        'note': 'A proxy may hide the device IP from destination sites, but the proxy provider can see the connecting IP. This status does not independently verify anonymity or prevent all metadata disclosure.',
    }

def create_http_client(**kwargs) -> httpx.Client:
    proxy = configured_proxy()
    if privacy_mode_enabled() and not proxy:
        raise PrivacyConfigurationError('Privacy mode is enabled but no proxy is configured. Set AFB_HTTPS_PROXY; online requests are blocked rather than sent directly.')
    options = dict(kwargs)
    options['trust_env'] = False
    if proxy:
        options['proxy'] = proxy
    return httpx.Client(**options)
