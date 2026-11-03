import json
import tempfile
import unittest
from pathlib import Path

from auto_find_bug.workspace_review import review_source, triage_finding


class WorkspaceReviewTests(unittest.TestCase):
    def test_imports_local_static_findings_and_generates_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            (workspace / "findings").mkdir(parents=True)
            (workspace / "evidence").mkdir()
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            result = review_source(workspace, source)
            data = json.loads((workspace / "findings" / "findings.json").read_text())
            self.assertEqual(result["finding_count"], 1)
            self.assertEqual(data["findings"][0]["status"], "potential")
            self.assertTrue((workspace / "reports" / "final-report.md").is_file())
            self.assertEqual(data["network_activity"], "none")

    def test_validated_requires_evidence_inside_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            (workspace / "findings").mkdir(parents=True)
            (workspace / "evidence").mkdir()
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            review_source(workspace, source)
            data = json.loads((workspace / "findings" / "findings.json").read_text())
            finding_id = data["findings"][0]["finding_id"]
            with self.assertRaises(ValueError):
                triage_finding(workspace, finding_id, "validated", "Reviewed")
            evidence = workspace / "evidence" / "review-notes.md"
            evidence.write_text("Independent review notes.", encoding="utf-8")
            result = triage_finding(workspace, finding_id, "validated", "Impact independently reviewed.", "evidence/review-notes.md")
            self.assertEqual(result["status"], "validated")
            final = (workspace / "reports" / "final-report.md").read_text()
            self.assertIn("review-notes.md", final)

    def test_triage_requires_note_and_rejects_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            (workspace / "findings").mkdir(parents=True)
            (workspace / "evidence").mkdir()
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("eval(x)", encoding="utf-8")
            review_source(workspace, source)
            data = json.loads((workspace / "findings" / "findings.json").read_text())
            finding_id = data["findings"][0]["finding_id"]
            with self.assertRaises(ValueError):
                triage_finding(workspace, finding_id, "needs_review", "")
            outside = root / "outside.txt"
            outside.write_text("not workspace evidence")
            with self.assertRaises(ValueError):
                triage_finding(workspace, finding_id, "validated", "Reviewed", "../outside.txt")


if __python__ == "__main__":
    unittest.main()
