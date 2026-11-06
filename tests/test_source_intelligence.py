import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from auto_find_bug.source_intelligence import analyze_apk, discover_dependencies, run_analysis


class SourceIntelligenceTests(unittest.TestCase):
    def test_dependency_inventory_marks_only_pinned_versions_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests==2.31.0\nflask>=2.0\n", encoding="utf-8")
            result = discover_dependencies(root)
        by_name = {item["name"]: item for item in result["dependencies"]}
        self.assertTrue(by_name["requests"]["version_is_exact"])
        self.assertFalse(by_name["flask"]["version_is_exact"])

    def test_apk_manifest_inventory(self):
        manifest = '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.test"><uses-permission android:name="android.permission.INTERNET"/><application android:debuggable="true" android:usesCleartextTraffic="true"><activity android:name=".MainActivity" android:exported="true"/></application></manifest>'
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "sample.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", manifest)
                archive.writestr("classes.dex", b"metadata")
                archive.writestr("lib/arm64-v8a/libsample.so", b"binary")
            result = analyze_apk(apk)
        rules = {item["rule_id"] for item in result["findings"]}
        self.assertEqual(result["package"], "example.test")
        self.assertIn("APK-CONFIG-001", rules)
        self.assertIn("APK-NET-001", rules)
        self.assertIn("APK-COMP-001", rules)

    def test_rejects_invalid_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.apk"
            path.write_text("not a zip", encoding="utf-8")
            with self.assertRaises(ValueError):
                analyze_apk(path)

    def test_pipeline_writes_workspace_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "project"
            source.mkdir()
            (source / "app.py").write_text("print('hello')\n", encoding="utf-8")
            workspace = root / "workspace"
            workspace.mkdir()
            result = run_analysis(source, workspace)
            data = json.loads((workspace / "findings" / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(result["finding_count"], 0)
            self.assertEqual(data["counts"]["total"], 0)
            self.assertTrue((workspace / "reports" / "source-intelligence-report.md").is_file())
            self.assertTrue((workspace / "source-intelligence" / "dependency-inventory.json").is_file())

    def test_dex_analysis_uses_androguard_call_graph_adapter(self):
        import sys
        import types
        from unittest.mock import patch

        class FakeGraph:
            def edges(self, data=True):
                return [("Lsample/A;->source()V", "Lsample/B;->sink()V", {"offset": 12})]

        class FakeAnalysis:
            def get_classes(self):
                return ["Lsample/A;", "Lsample/B;"]

            def get_methods(self):
                return ["source", "sink"]

            def get_call_graph(self, no_isolated=True):
                self.assert_no_isolated = no_isolated
                return FakeGraph()

        fake_analysis = FakeAnalysis()
        misc = types.ModuleType("androguard.misc")
        misc.AnalyzeAPK = lambda _path: (object(), [object()], fake_analysis)
        package = types.ModuleType("androguard")
        package.__path__ = []
        with patch.dict(sys.modules, {"androguard": package, "androguard.misc": misc}):
            with tempfile.TemporaryDirectory() as tmp:
                apk = Path(tmp) / "dex.apk"
                with zipfile.ZipFile(apk, "w") as archive:
                    archive.writestr("AndroidManifest.xml", '<manifest package="sample"><application/></manifest>')
                    archive.writestr("classes.dex", b"synthetic-dex-marker")
                result = analyze_apk(apk)
        self.assertEqual(result["dex_analysis"]["status"], "analyzed")
        self.assertEqual(result["dex_analysis"]["class_count"], 2)
        self.assertEqual(result["dex_analysis"]["method_count"], 2)
        self.assertEqual(result["dex_analysis"]["call_graph_edges"], 1)
        self.assertIn("source()V", result["dex_analysis"]["call_graph_sample"][0]["caller"])

    def test_dex_size_limit_is_reported_without_calling_androguard(self):
        from unittest.mock import patch
        from auto_find_bug.source_intelligence import _analyze_apk_dex
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "large.apk"
            apk.write_bytes(b"placeholder")
            with patch.dict("sys.modules", {"androguard": None, "androguard.misc": None}):
                result = _analyze_apk_dex(apk, ["classes.dex"], 64 * 1024 * 1024 + 1)
        self.assertEqual(result["status"], "skipped_size_limit")


if __name__ == "__main__":
    unittest.main()
