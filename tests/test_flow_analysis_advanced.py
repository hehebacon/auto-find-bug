import tempfile
import unittest
from pathlib import Path

from auto_find_bug.flow_analysis_advanced import analyze_python_flows


class AdvancedFlowAnalysisTests(unittest.TestCase):
    def analyze(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            path.write_text(source, encoding="utf-8")
            return analyze_python_flows(path)["findings"]

    def rules(self, source):
        return [item["rule_id"] for item in self.analyze(source)]

    def test_constant_false_branch_is_not_followed(self):
        findings = self.analyze("""
def endpoint(request):
    if 2 + 2 == 5:
        value = request.args.get("cmd")
    else:
        value = "fixed"
    os.system(value)
""")
        self.assertNotIn("FLOW-PY-002", [f["rule_id"] for f in findings])

    def test_unknown_branch_joins_tainted_and_safe_values(self):
        findings = self.analyze("""
def endpoint(request, flag):
    if flag:
        value = request.args.get("cmd")
    else:
        value = "fixed"
    os.system(value)
""")
        self.assertIn("FLOW-PY-002", [f["rule_id"] for f in findings])

    def test_safe_overwrite_kills_previous_taint(self):
        findings = self.analyze("""
def endpoint(request):
    value = request.args.get("cmd")
    value = "fixed-command"
    os.system(value)
""")
        self.assertNotIn("FLOW-PY-002", [f["rule_id"] for f in findings])

    def test_list_pop_removes_tainted_element_before_sink(self):
        findings = self.analyze("""
def endpoint(request):
    values = ["fixed"]
    values.append(request.args.get("cmd"))
    values.pop()
    os.system(values[0])
""")
        self.assertNotIn("FLOW-PY-002", [f["rule_id"] for f in findings])

    def test_dictionary_overwrite_replaces_tainted_value(self):
        findings = self.analyze("""
def endpoint(request):
    data = {"cmd": request.args.get("cmd")}
    data["cmd"] = "fixed"
    os.system(data["cmd"])
""")
        self.assertNotIn("FLOW-PY-002", [f["rule_id"] for f in findings])

    def test_same_project_helper_argument_reaches_sink(self):
        findings = self.analyze("""
def run_command(command):
    os.system(command)

def endpoint(request):
    value = request.args.get("cmd")
    run_command(value)
""")
        finding = next(f for f in findings if f["rule_id"] == "FLOW-PY-002")
        self.assertEqual(finding["flow"]["source_line"], 6)
        self.assertEqual(finding["flow"]["sink_line"], 3)

    def test_same_project_helper_return_preserves_taint(self):
        findings = self.analyze("""
def passthrough(value):
    return value

def endpoint(request):
    value = passthrough(request.args.get("cmd"))
    os.system(value)
""")
        self.assertIn("FLOW-PY-002", [f["rule_id"] for f in findings])

    def test_source_without_sink_does_not_emit_warning(self):
        findings = self.analyze("""
def endpoint(request):
    value = request.args.get("q")
    print(value)
""")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
