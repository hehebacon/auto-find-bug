import shutil
import tempfile
import unittest
from pathlib import Path

from auto_find_bug.semgrep_analysis import analyze_with_semgrep


@unittest.skipUnless(shutil.which("semgrep"), "Semgrep optional engine is not installed")
class SemgrepIntegrationTests(unittest.TestCase):
    def test_bundled_rules_detect_synthetic_request_to_shell_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "import os\n"
                "def endpoint(request):\n"
                "    value = request.args.get('command')\n"
                "    os.system(value)\n",
                encoding="utf-8",
            )
            result = analyze_with_semgrep(root)

        self.assertTrue(result["available"])
        self.assertGreaterEqual(result["files_analyzed"], 1)
        self.assertTrue(
            any(item["rule_id"] == "auto-find-bug.python.request-to-shell" for item in result["findings"]),
            msg=f"Expected bundled rule did not match. Diagnostics: {result['diagnostics']}; note: {result['note']}",
        )


if __name__ == "__main__":
    unittest.main()
