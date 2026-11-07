import shutil
import tempfile
import unittest
from pathlib import Path

from auto_find_bug.semgrep_analysis import analyze_with_semgrep


@unittest.skipUnless(shutil.which("semgrep"), "Semgrep optional engine is not installed")
class SemgrepIntegrationTests(unittest.TestCase):
    def _scan_java(self, cases):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, source in cases.items():
                (root / name).write_text(source, encoding="utf-8")
            return analyze_with_semgrep(root)

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
                "connection.prepareCall(sql); } }"
            ),
            "command.java": (
                "class Demo { void handle(HttpServletRequest request) throws Exception { "
                "String value = request.getHeader(\"cmd\"); Runtime.getRuntime().exec(value); } }"
            ),
        }
        result = self._scan_java(cases)
        observed = {(Path(item["file"]).name, item["rule_id"]) for item in result["findings"]}
        expected = {
            ("sql.java", "auto-find-bug.java.servlet-to-sql"),
            ("command.java", "auto-find-bug.java.servlet-to-command"),
        }
        self.assertTrue(expected.issubset(observed), msg=f"Missing Java taint result: {result}")

    def test_java_spring_jdbc_query_for_object_is_a_sql_sink(self):
        source = (
            "class Demo { void handle(HttpServletRequest request, JdbcTemplate jdbc) { "
            "String value = request.getParameter(\"q\"); "
            "String sql = \"SELECT * FROM users WHERE name='\" + value + \"'\"; "
            "jdbc.queryForObject(sql, Long.class); } }"
        )
        result = self._scan_java({"spring.java": source})
        self.assertTrue(
            any(item["rule_id"] == "auto-find-bug.java.servlet-to-sql" for item in result["findings"]),
            msg=f"Spring JDBC queryForObject flow was not detected: {result}",
        )

    def test_java_mult_argument_prepared_statement_is_a_sql_sink(self):
        source = (
            "class Demo { void handle(HttpServletRequest request, Connection connection) throws Exception { "
            "String value = request.getParameter(\"q\"); "
            "String sql = \"SELECT * FROM users WHERE name='\" + value + \"'\"; "
            "connection.prepareStatement(sql, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY); } }"
        )
        result = self._scan_java({"prepared.java": source})
        self.assertTrue(
            any(item["rule_id"] == "auto-find-bug.java.servlet-to-sql" for item in result["findings"]),
            msg=f"Multi-argument prepareStatement flow was not detected: {result}",
        )

    def test_java_process_builder_list_add_flow_is_a_command_sink(self):
        source = (
            "class Demo { void handle(HttpServletRequest request) throws Exception { "
            "List<String> args = new ArrayList<>(); "
            "args.add(\"echo \" + request.getHeader(\"cmd\")); "
            "new ProcessBuilder(args).start(); } }"
        )
        result = self._scan_java({"process_builder.java": source})
        self.assertTrue(
            any(item["rule_id"] == "auto-find-bug.java.servlet-to-command" for item in result["findings"]),
            msg=f"List-to-ProcessBuilder flow was not detected: {result}",
        )


if __name__ == "__main__":
    unittest.main()
