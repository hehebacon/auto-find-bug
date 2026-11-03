import tempfile
import unittest
from pathlib import Path

from auto_find_bug.scope_review import build_scope_review, write_scope_review


class ScopeReviewTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {
            "program_handle": "demo",
            "canonical_policy_url": "https://hackerone.com/demo/policy_scopes",
            "source_url": "https://mirror.invalid/demo",
            "snapshot_publicly_verified_at": "2026-10-01T00:00:00Z",
            "assets": [
                {"asset_identifier": "*.example.com", "asset_type": "WILDCARD", "submission_eligible": True, "bounty_eligible": True},
                {"asset_identifier": "excluded.example.com", "asset_type": "URL", "submission_eligible": False, "bounty_eligible": False},
                {"asset_identifier": "docs.example.com", "asset_type": "URL", "submission_eligible": True, "bounty_eligible": False},
            ],
        }

    def test_classifies_snapshot_flags_without_authorizing(self):
        result = build_scope_review(self.snapshot)
        self.assertEqual(result["counts"]["total_parsed"], 3)
        self.assertEqual(result["counts"]["snapshot_eligible_unverified"], 1)
        self.assertEqual(result["counts"]["out_of_scope_or_not_submission_eligible"], 1)
        self.assertEqual(result["counts"]["submission_eligible_bounty_ineligible"], 1)
        self.assertEqual(result["authorization"], "not_established")
        self.assertEqual(result["wildcard_expansion"], "disabled")
        self.assertEqual(result["network_activity"], "none")

    def test_writes_review_and_taxonomy(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            result = write_scope_review(workspace, self.snapshot)
            self.assertEqual(result["program_handle"], "demo")
            self.assertTrue((workspace / "policy" / "scope-review.json").exists())
            self.assertTrue((workspace / "policy" / "scope-review.md").exists())
            self.assertTrue((workspace / "reconnaissance" / "vulnerability-class-checklist.md").exists())


if __name__ == "__main__":
    unittest.main()
