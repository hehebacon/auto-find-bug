from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from auto_find_bug import multi_brain


class MultiBrainTests(unittest.TestCase):
    def _workspace(self, root: str) -> tuple[Path, Path]:
        base = Path(root)
        source = base / "source"
        workspace = base / "scope"
        source.mkdir()
        workspace.mkdir()
        (source / "app.py").write_text("print('test')\n", encoding="utf-8")
        return source, workspace

    def _complete(self, name: str):
        return {
            "brain": name,
            "status": "complete",
            "available": True,
            "files_analyzed": 1,
            "finding_count": 0,
            "findings": [],
            "note": "",
            "limitations": [],
        }

    def test_all_five_brains_clean_writes_scope_bugs_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, workspace = self._workspace(tmp)
            with (
                patch.object(multi_brain, "_brain_code_audit", return_value=self._complete("code-audit")),
                patch.object(multi_brain, "_brain_python_flow", return_value=self._complete("python-flow")),
                patch.object(multi_brain, "_brain_java_flow", return_value=self._complete("java-flow")),
                patch.object(multi_brain, "_brain_semgrep", return_value=self._complete("semgrep-local-rules")),
                patch.object(multi_brain, "_brain_public_intel", return_value=self._complete("public-vulnerability-intel")),
            ):
                result = multi_brain.run_five_brain_scan(source, workspace)

            self.assertEqual(result["status"], "clean")
            self.assertEqual(result["finding_count"], 0)
            self.assertTrue((workspace / "bugs" / "findings.json").is_file())
            report = (workspace / "bugs" / "report.md").read_text(encoding="utf-8")
            self.assertIn("NO BUGS APPEARED / FOUND ON THIS SCOPE", report)

    def test_unavailable_brain_never_reports_clean_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, workspace = self._workspace(tmp)
            unavailable = self._complete("semgrep-local-rules")
            unavailable["status"] = "unavailable"
            unavailable["available"] = False
            with (
                patch.object(multi_brain, "_brain_code_audit", return_value=self._complete("code-audit")),
                patch.object(multi_brain, "_brain_python_flow", return_value=self._complete("python-flow")),
                patch.object(multi_brain, "_brain_java_flow", return_value=self._complete("java-flow")),
                patch.object(multi_brain, "_brain_semgrep", return_value=unavailable),
                patch.object(multi_brain, "_brain_public_intel", return_value=self._complete("public-vulnerability-intel")),
            ):
                result = multi_brain.run_five_brain_scan(source, workspace)

            self.assertEqual(result["status"], "incomplete")
            report = (workspace / "bugs" / "report.md").read_text(encoding="utf-8")
            self.assertIn("coverage is incomplete", report)
            self.assertNotIn("NO BUGS APPEARED / FOUND ON THIS SCOPE", report)

    def test_public_intel_cache_reuses_only_unchanged_dependency_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            workspace = root / "workspace"
            source.mkdir()
            workspace.mkdir()
            cache = workspace / "bugs" / "public-intel-cache.json"
            dependencies = {"dependencies": [{"name": "requests", "version": "2.0"}]}
            brain_result = {
                "brain": "public-vulnerability-intel",
                "status": "complete",
                "available": True,
                "files_analyzed": 0,
                "finding_count": 0,
                "findings": [],
                "note": "fresh",
                "limitations": [],
            }
            with (
                patch.object(multi_brain, "discover_dependencies", side_effect=lambda _source: dependencies),
                patch.object(multi_brain, "_brain_public_intel", return_value=brain_result) as run_brain,
            ):
                multi_brain._brain_public_intel_with_cache(source, cache, 900)
                cached = multi_brain._brain_public_intel_with_cache(source, cache, 900)
                self.assertIn("reused from cache", cached["note"])
                self.assertEqual(run_brain.call_count, 1)

                dependencies["dependencies"] = [{"name": "requests", "version": "2.1"}]
                multi_brain._brain_public_intel_with_cache(source, cache, 900)
                self.assertEqual(run_brain.call_count, 2)

    def test_findings_are_deduplicated_and_saved(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, workspace = self._workspace(tmp)
            finding = {
                "rule_id": "TEST-001",
                "file": "app.py",
                "line": 1,
                "evidence": "unsafe pattern",
                "title": "Review lead",
                "severity": "LOW",
            }
            def brain(name):
                item = self._complete(name)
                item["findings"] = [dict(finding)]
                item["finding_count"] = 1
                return item

            with (
                patch.object(multi_brain, "_brain_code_audit", return_value=brain("code-audit")),
                patch.object(multi_brain, "_brain_python_flow", return_value=brain("python-flow")),
                patch.object(multi_brain, "_brain_java_flow", return_value=self._complete("java-flow")),
                patch.object(multi_brain, "_brain_semgrep", return_value=self._complete("semgrep-local-rules")),
                patch.object(multi_brain, "_brain_public_intel", return_value=self._complete("public-vulnerability-intel")),
            ):
                result = multi_brain.run_five_brain_scan(source, workspace)

            self.assertEqual(result["status"], "findings_present")
            self.assertEqual(result["finding_count"], 1)
            payload = json.loads((workspace / "bugs" / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(len(payload["findings"]), 1)
            self.assertEqual(payload["findings"][0]["status"], "potential")


if __name__ == "__main__":
    unittest.main()
