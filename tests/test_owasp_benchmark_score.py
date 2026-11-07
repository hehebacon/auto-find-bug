import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.score_owasp_benchmark import score


class OwaspScoreTests(unittest.TestCase):
    def test_scores_true_and_false_positives_by_expected_cwe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expected = root / "expected.csv"
            expected.write_text(
                "# header\n"
                "BenchmarkTest00001,cmdi,true,78\n"
                "BenchmarkTest00002,cmdi,false,78\n"
                "BenchmarkTest00003,sqli,true,89\n"
                "BenchmarkTest00004,sqli,false,89\n"
                "BenchmarkTest00005,xss,true,79\n",
                encoding="utf-8",
            )
            results = root / "semgrep.json"
            results.write_text(json.dumps({
                "paths": {"scanned": [
                    "/benchmark/BenchmarkTest00001.java",
                    "/benchmark/BenchmarkTest00002.java",
                    "/benchmark/BenchmarkTest00003.java",
                    "/benchmark/BenchmarkTest00004.java",
                ]},
                "results": [
                    {"path": "/benchmark/BenchmarkTest00001.java", "check_id": "rules.auto-find-bug.java.servlet-to-command"},
                    {"path": "/benchmark/BenchmarkTest00002.java", "check_id": "rules.auto-find-bug.java.servlet-to-command"},
                    {"path": "/benchmark/BenchmarkTest00003.java", "check_id": "rules.auto-find-bug.java.servlet-to-sql"},
                ],
            }), encoding="utf-8")
            report = score(expected, results, "fixture-commit")
        self.assertEqual(report["overall_scored_subset"]["tp"], 2)
        self.assertEqual(report["overall_scored_subset"]["fp"], 1)
        self.assertEqual(report["overall_scored_subset"]["fn"], 0)
        self.assertEqual(report["overall_scored_subset"]["tn"], 1)
        self.assertEqual(report["not_scanned_cases"], 0)
        self.assertNotIn("79", report["categories"])

    def test_comparison_reports_all_confusion_matrix_and_rate_deltas(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expected = root / "expected.csv"
            expected.write_text(
                "BenchmarkTest00001,sqli,true,89\\n"
                "BenchmarkTest00002,sqli,false,89\\n",
                encoding="utf-8",
            )
            results = root / "semgrep.json"
            results.write_text(json.dumps({
                "paths": {"scanned": [
                    "/benchmark/BenchmarkTest00001.java",
                    "/benchmark/BenchmarkTest00002.java",
                ]},
                "results": [
                    {"path": "/benchmark/BenchmarkTest00001.java", "check_id": "rules.auto-find-bug.java.servlet-to-sql"}
                ],
            }), encoding="utf-8")
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({
                "analyzer_commit": "baseline-sha",
                "benchmark_commit": "fixture-commit",
                "overall_scored_subset": {
                    "tp": 0, "fp": 1, "fn": 1, "tn": 0,
                    "precision": 0.0, "recall": 0.0, "false_positive_rate": 1.0,
                },
            }), encoding="utf-8")
            report = score(expected, results, "fixture-commit", baseline)
        comparison = report["comparison_to_baseline"]
        self.assertEqual(comparison["baseline_analyzer_commit"], "baseline-sha")
        self.assertEqual(comparison["delta"]["tp"], 1)
        self.assertEqual(comparison["delta"]["fp"], -1)
        self.assertEqual(comparison["delta"]["fn"], -1)
        self.assertEqual(comparison["delta"]["tn"], 1)
        self.assertEqual(comparison["delta"]["recall"], 1.0)


if __name__ == "__main__":
    unittest.main()
