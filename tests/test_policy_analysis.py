import tempfile
import unittest
from pathlib import Path

from auto_find_bug.policy_analysis import analyze_policy_text, write_policy_analysis


class PolicyAnalysisTests(unittest.TestCase):
    def test_extracts_exclusion_inclusion_and_conflicts(self):
        text = """In scope: https://app.example.com
Out of scope: https://legacy.example.com
Do not test https://blocked.example.com
Testing is permitted for https://app.example.com
"""
        result = analyze_policy_text(text, "https://example.org/policy")
        self.assertIn("legacy.example.com", result["exclusion_asset_candidates_unverified"])
        self.assertIn("blocked.example.com", result["exclusion_asset_candidates_unverified"])
        self.assertIn("app.example.com", result["inclusion_asset_candidates_unverified"])
        self.assertIn("app.example.com", result["conflicting_asset_candidates"])
        self.assertEqual(result["authorization"], "not_established")
        self.assertEqual(result["network_activity"], "none")

    def test_extracts_policy_requirements_without_treating_them_as_permission(self):
        text = "Rate limit: 2 requests per second. Use a test account. Do not access user data."
        result = analyze_policy_text(text)
        self.assertTrue(result["policy_rules"]["rate_limits"])
        self.assertTrue(result["policy_rules"]["account_requirements"])
        self.assertTrue(result["policy_rules"]["data_handling"])
        self.assertEqual(result["completeness"], "heuristic_incomplete_manual_review_required")

    def test_writes_json_and_markdown_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            result = write_policy_analysis(Path(directory), "Out of scope: old.example.com")
            self.assertEqual(result["counts"]["exclusion_asset_candidates"], 1)
            self.assertTrue((Path(directory) / "policy" / "policy-analysis.json").is_file())
            report = (Path(directory) / "policy" / "policy-analysis.md").read_text(encoding="utf-8")
            self.assertIn("old.example.com", report)
            self.assertIn("not established", report.lower())


if __name__ == "__main__":
    unittest.main()
