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
        self.assertEqual(result["counts"]["not_submission_eligible_in_snapshot"], 1)
        self.assertEqual(result["counts"]["submission_eligible_bounty_ineligible"], 1)
        self.assertEqual(result["authorization"], "not_established")
        self.assertEqual(result["wildcard_expansion"], "disabled")
        self.assertEqual(result["network_activity"], "none")

    def test_string_flags_are_parsed_as_booleans_not_truthy_strings(self):
        snapshot = {"assets": [
            {"asset_identifier": "a.example", "asset_type": "URL", "submission_eligible": "no", "bounty_eligible": "no"},
            {"asset_identifier": "b.example", "asset_type": "ANDROID", "submission_eligible": "yes", "bounty_eligible": "yes"},
        ]}
        result = build_scope_review(snapshot)
        self.assertEqual(result["counts"]["not_submission_eligible_in_snapshot"], 1)
        self.assertEqual(result["counts"]["snapshot_eligible_unverified"], 1)
        mobile = result["snapshot_eligible_unverified"][0]
        self.assertIn("Mobile application security", mobile["applicable_review_classes"])

    def test_unknown_flags_and_malformed_records_are_not_assumed_false(self):
        snapshot = {"assets": [
            {"asset_identifier": "unknown.example", "asset_type": "URL", "submission_eligible": None, "bounty_eligible": "maybe"},
            {"asset_identifier": "", "asset_type": "URL", "submission_eligible": False, "bounty_eligible": False},
            "not-an-asset-record",
        ]}
        result = build_scope_review(snapshot)
        self.assertEqual(result["counts"]["eligibility_flags_incomplete_manual_review_required"], 1)
        self.assertEqual(result["counts"]["skipped_malformed_records"], 2)
        self.assertIsNone(result["eligibility_flags_incomplete_manual_review_required"][0]["submission_eligible"])

    def test_duplicate_assets_are_ignored(self):
        asset = {"asset_identifier": "same.example", "asset_type": "URL", "submission_eligible": True, "bounty_eligible": True}
        result = build_scope_review({"assets": [asset, dict(asset, asset_identifier="SAME.EXAMPLE")]})
        self.assertEqual(result["counts"]["total_parsed"], 1)
        self.assertEqual(result["counts"]["duplicate_records_ignored"], 1)

    def test_writes_review_and_taxonomy(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            result = write_scope_review(workspace, self.snapshot)
            self.assertEqual(result["program_handle"], "demo")
            self.assertTrue((workspace / "policy" / "scope-review.json").exists())
            self.assertTrue((workspace / "policy" / "scope-review.md").exists())
            self.assertTrue((workspace / "reconnaissance" / "vulnerability-class-checklist.md").exists())
            report = (workspace / "policy" / "scope-review.md").read_text(encoding="utf-8")
            self.assertIn("not authoritative exclusion", report)


if __name__ == "__main__":
    unittest.main()
