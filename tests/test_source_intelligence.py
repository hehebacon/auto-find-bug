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


if __name__ == "__main__":
    unittest.main()
