import json
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from auto_find_bug import semgrep_analysis


class SemgrepAnalysisTests(unittest.TestCase):
    def test_optional_engine_degrades_gracefully_when_not_installed(self):
        with patch.object(semgrep_analysis.shutil, "which", return_value=None):
            result = semgrep_analysis.analyze_with_semgrep(Path(__file__))
        self.assertFalse(result["available"])
        self.assertEqual(result["findings"], [])
        self.assertIn(".[sast]", result["note"])

    def test_maps_semgrep_json_result_to_normalized_finding(self):
        payload = {
            "paths": {"scanned": 4},
            "results": [{
                "check_id": "auto-find-bug.python.request-to-sql",
                "path": "app.py",
                "start": {"line": 12},
                "extra": {
                    "severity": "WARNING",
                    "message": "Request data may reach SQL.",
                    "lines": "cursor.execute(query)",
                    "metadata": {"cwe": "CWE-89", "confidence": "MEDIUM"},
                },
            }],
            "errors": [],
        }
        completed = SimpleNamespace(stdout=json.dumps(payload), returncode=0)
        with patch.object(semgrep_analysis.shutil, "which", return_value="/usr/bin/semgrep"), patch.object(
            semgrep_analysis.subprocess, "run", return_value=completed
        ):
            result = semgrep_analysis.analyze_with_semgrep(Path(__file__))
        finding = result["findings"][0]
        self.assertEqual(result["files_analyzed"], 4)
        self.assertEqual(finding["file"], "app.py")
        self.assertEqual(finding["line"], 12)
        self.assertEqual(finding["cwe"], "CWE-89")
        self.assertEqual(finding["validation_status"], "not_validated")


if __name__ == "__main__":
    unittest.main()
