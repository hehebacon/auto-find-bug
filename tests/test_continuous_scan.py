from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from auto_find_bug import continuous_scan


class ContinuousScanTests(unittest.TestCase):
    def test_fingerprint_changes_when_source_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            source.mkdir()
            target = source / "app.py"
            target.write_text("x = 1\n", encoding="utf-8")
            first = continuous_scan.source_fingerprint(source)
            target.write_text("x = 2\n", encoding="utf-8")
            second = continuous_scan.source_fingerprint(source)
            self.assertNotEqual(first, second)

    def test_watcher_scans_immediately_and_preserves_history_on_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            workspace = Path(tmp) / "workspace"
            source.mkdir()
            workspace.mkdir()
            (source / "app.py").write_text("x = 1\n", encoding="utf-8")
            (workspace / "bugs").mkdir(parents=True)
            (workspace / "bugs" / "findings.json").write_text("{\"findings\": []}", encoding="utf-8")
            (workspace / "bugs" / "report.md").write_text("# report", encoding="utf-8")
            result = {
                "status": "findings_present",
                "finding_count": 1,
                "brain_statuses": {"code-audit": "complete"},
                "files_scanned": 1,
                "findings_path": str(workspace / "bugs" / "findings.json"),
                "report_path": str(workspace / "bugs" / "report.md"),
            }
            with (
                patch.object(continuous_scan, "run_five_brain_scan", return_value=result) as scan,
                patch.object(continuous_scan.time, "sleep", side_effect=KeyboardInterrupt),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    continuous_scan.watch_five_brain_scan(
                        source, workspace, poll_seconds=1, refresh_seconds=10
                    )
            scan.assert_called_once()
            history = workspace / "bugs" / "scan-history.jsonl"
            self.assertTrue(history.is_file())
            record = json.loads(history.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(record["finding_count"], 1)
            self.assertEqual(record["status"], "findings_present")
            self.assertTrue(Path(record["snapshot_directory"], "findings.json").is_file())
            state = json.loads((workspace / "bugs" / "scan-state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "stopped")


if __name__ == "__main__":
    unittest.main()
