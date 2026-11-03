import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from auto_find_bug.network import (
    PrivacyConfigurationError,
    create_http_client,
    privacy_status,
)


class PrivacyNetworkTests(unittest.TestCase):
    def test_privacy_mode_blocks_online_client_without_proxy(self):
        with patch.dict("os.environ", {"AFB_PRIVACY_MODE": "1"}, clear=True):
            with self.assertRaises(PrivacyConfigurationError):
                create_http_client(timeout=1)

    def test_proxy_is_explicit_and_environment_proxies_are_ignored(self):
        with patch.dict(
            "os.environ",
            {
                "AFB_PRIVACY_MODE": "1",
                "AFB_HTTPS_PROXY": "http://127.0.0.1:8080",
                "HTTPS_PROXY": "http://unexpected-proxy:9999",
            },
            clear=True,
        ), patch("auto_find_bug.network.httpx.Client") as client_factory:
            create_http_client(timeout=3)
            kwargs = client_factory.call_args.kwargs
            self.assertEqual(kwargs["proxy"], "http://127.0.0.1:8080")
            self.assertFalse(kwargs["trust_env"])

    def test_direct_mode_is_explicit_and_still_ignores_environment_proxy(self):
        with patch.dict(
            "os.environ",
            {"AFB_PRIVACY_MODE": "0", "HTTPS_PROXY": "http://unexpected-proxy:9999"},
            clear=True,
        ), patch("auto_find_bug.network.httpx.Client") as client_factory:
            create_http_client(timeout=3)
            kwargs = client_factory.call_args.kwargs
            self.assertFalse(kwargs["trust_env"])
            self.assertNotIn("proxy", kwargs)

    def test_invalid_proxy_scheme_is_rejected(self):
        with patch.dict(
            "os.environ",
            {"AFB_PRIVACY_MODE": "1", "AFB_HTTPS_PROXY": "socks5://127.0.0.1:9050"},
            clear=True,
        ):
            with self.assertRaises(PrivacyConfigurationError):
                create_http_client()

    def test_status_reports_blocked_default(self):
        with patch.dict("os.environ", {}, clear=True):
            status = privacy_status()
        self.assertTrue(status["privacy_mode"])
        self.assertFalse(status["proxy_configured"])
        self.assertEqual(status["online_access"], "blocked_until_proxy_configured")


if __name__ == "__main__":
    unittest.main()
