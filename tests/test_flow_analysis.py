import tempfile
import unittest
from pathlib import Path

from auto_find_bug.flow_analysis import analyze_python_flows


class FlowAnalysisTests(unittest.TestCase):
    def test_tracks_request_input_through_assignment_to_dynamic_sql(self):
        source = '''\ndef endpoint(request):\n    user_value = request.args.get("q")\n    query = f"SELECT * FROM records WHERE name = '{user_value}'"\n    cursor.execute(query)\n'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            path.write_text(source, encoding="utf-8")
            result = analyze_python_flows(path)
        finding = next(item for item in result["findings"] if item["rule_id"] == "FLOW-PY-003")
        self.assertEqual(finding["flow"]["source_line"], 3)
        self.assertEqual(finding["flow"]["sink_line"], 5)
        self.assertEqual(finding["file"], "app.py")

    def test_tracks_request_input_to_shell_sink(self):
        source = '''\ndef endpoint(request):\n    value = request.form["name"]\n    os.system(value)\n'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            path.write_text(source, encoding="utf-8")
            result = analyze_python_flows(path)
        self.assertTrue(any(item["rule_id"] == "FLOW-PY-002" for item in result["findings"]))

    def test_flags_sensitive_route_without_recognized_guard_as_low_confidence(self):
        source = '''\n@app.route("/admin/delete")\ndef delete_user():\n    return "ok"\n'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "routes.py"
            path.write_text(source, encoding="utf-8")
            result = analyze_python_flows(path)
        finding = next(item for item in result["findings"] if item["rule_id"] == "ACCESS-PY-001")
        self.assertEqual(finding["confidence"], "low")

    def test_does_not_report_parameterized_query_as_interpolated(self):
        source = '''\ndef endpoint(request):\n    value = request.args.get("q")\n    cursor.execute("SELECT * FROM records WHERE name = ?", (value,))\n'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safe.py"
            path.write_text(source, encoding="utf-8")
            result = analyze_python_flows(path)
        self.assertFalse(any(item["rule_id"] == "FLOW-PY-003" for item in result["findings"]))


if __name__ == "__main__":
    unittest.main()
