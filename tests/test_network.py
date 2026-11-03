import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from auto_find_bug.network import create_http_client, network_status


class StandardNetworkTests(unittest.TestCase):
    def test_client_uses_normal_httpx_defaults(self):
        with patch("auto_find_bug.network.httpx.Client") as client_factory:
            create_http_client(timeout=3)
            kwargs = client_factory.call_args.kwargs
            self.assertEqual(kwargs["timeout"], 3)
            self.assertNotIn("proxy", kwargs)
            self.assertNotIn("trust_env", kwargs)

    def test_project_privacy_environment_variables_are_not_required(self):
        with patch.dict("os.environ", {}, clear=True), patch(
            "auto_find_bug.network.httpx.Client"
        ) as client_factory:
            create_http_client(timeout=1)
            client_factory.assert_called_once()

    def test_network_status_reports_standard_mode(self):
        status = network_status()
        self.assertEqual(status["mode"], "standard")
        self.assertIn("public IP", status["note"])


if __name__ == "__main__":
    unittest.main()
