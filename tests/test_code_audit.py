import tempfile
import unittest
from pathlib import Path

from auto_find_bug.code_audit import analyze_source, write_code_report


class CodeAuditTests(unittest.TestCase):
    def test_detects_python_dynamic_execution_and_unsafe_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.py"
            path.write_text("eval(user_input)\nyaml.load(data)\n", encoding="utf-8")
            result = analyze_source(tmp)
        rules = {item["rule_id"] for item in result["findings"]}
        self.assertIn("PY001", rules)
        self.assertIn("PY004", rules)
        self.assertEqual(result["files_scanned"], 1)

    def test_detects_javascript_html_sink(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.js").write_text("node.innerHTML = value;\neval(code);\n", encoding="utf-8")
            result = analyze_source(tmp)
        rules = {item["rule_id"] for item in result["findings"]}
        self.assertIn("JS001", rules)
        self.assertIn("JS002", rules)

    def test_skips_dependency_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            vendor = Path(tmp) / "node_modules"
            vendor.mkdir()
            (vendor / "bad.js").write_text("eval(code)", encoding="utf-8")
            result = analyze_source(tmp)
        self.assertEqual(result["files_scanned"], 0)
        self.assertEqual(result["finding_count"], 0)

    def test_writes_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src"
            root.mkdir()
            (root / "x.py").write_text("eval(x)", encoding="utf-8")
            result = analyze_source(root)
            output = write_code_report(result, Path(tmp) / "report.json", "json")
            self.assertIn("PY001", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
