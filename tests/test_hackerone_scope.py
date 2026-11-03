import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from auto_find_bug.hackerone_scope import hackerone_handle_from_url, _parse_assets
from bs4 import BeautifulSoup


class HackerOneScopeTests(unittest.TestCase):
    def test_extracts_handle_from_policy_url(self):
        self.assertEqual(
            hackerone_handle_from_url("https://hackerone.com/tiktok/policy_scopes"),
            "tiktok",
        )

    def test_rejects_non_hackerone_urls(self):
        self.assertIsNone(hackerone_handle_from_url("https://example.com/tiktok"))

    def test_parses_structured_asset_eligibility(self):
        html = """
        <pre>
        *.example.com
        Type: WILDCARD
        Submission eligible: yes
        Bounty eligible: no
        Maximum severity: none
        </pre>
        """
        assets = _parse_assets(BeautifulSoup(html, "html.parser"))
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["asset_identifier"], "*.example.com")
        self.assertTrue(assets[0]["submission_eligible"])
        self.assertFalse(assets[0]["bounty_eligible"])
        self.assertEqual(assets[0]["verification_status"], "third_party_snapshot_unverified")


if __name__ == "__main__":
    unittest.main()
