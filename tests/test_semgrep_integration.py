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
        finding = next(
            (item for item in result["findings"] if item["rule_id"] == "auto-find-bug.python.request-to-shell"),
            None,
        )
        self.assertIsNotNone(finding, msg=f"Expected bundled rule did not match. Full result: {result}")
        self.assertEqual(finding["file"], "app.py")
        self.assertEqual(finding["line"], 4)
        self.assertIn("os.system(value)", finding["evidence"])

    def test_java_header_to_sql_and_process_sinks(self):
        cases = {
            "sql.java": (
                "class Demo { void handle(HttpServletRequest request, Connection connection) throws Exception { "
                "String value = request.getHeader(\"q\"); String sql = \"SELECT * FROM users WHERE name='\" + value + \"'\"; "
                "connection.prepareCall(sql); } }",
                "auto-find-bug.java.servlet-to-sql",
            ),
            "command.java": (
                "class Demo { void handle(HttpServletRequest request) throws Exception { "
                "String value = request.getHeader(\"cmd\"); Runtime.getRuntime().exec(value); } }",
                "auto-find-bug.java.servlet-to-command",
            ),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, (source, _rule) in cases.items():
                (root / name).write_text(source, encoding="utf-8")
            result = analyze_with_semgrep(root)
        observed = {(Path(item["file"]).name, item["rule_id"]) for item in result["findings"]}
        for name, (_source, rule_id) in cases.items():
            self.assertIn((name, rule_id), observed, msg=f"Missing Java taint result for {name}: {result}")


if __name__ == "__main__":
    unittest.main()
