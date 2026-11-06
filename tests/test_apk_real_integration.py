import os
import unittest
from pathlib import Path

from auto_find_bug.source_intelligence import analyze_apk


FIXTURE = os.environ.get("AFB_APK_FIXTURE")


@unittest.skipUnless(FIXTURE and Path(FIXTURE).is_file(), "Pinned real APK fixture is supplied only by optional-engine CI")
class RealAPKIntegrationTests(unittest.TestCase):
    def test_androguard_decodes_manifest_and_analyzes_dex(self):
        result = analyze_apk(FIXTURE)
        self.assertEqual(result["source_type"], "apk")
        self.assertEqual(result["manifest_status"], "decoded_with_androguard")
        self.assertTrue(result["package"])
        self.assertTrue(result["dex_files"], "Fixture must contain at least one DEX file")
        self.assertIn(
            result["dex_analysis"]["status"],
            {"analyzed", "analyzed_call_graph_skipped_method_limit"},
            msg=f"Androguard DEX integration did not complete: {result['dex_analysis']}",
        )
        self.assertGreaterEqual(result["dex_analysis"]["class_count"], 1)
        self.assertGreaterEqual(result["dex_analysis"]["method_count"], 1)
        self.assertIsInstance(result["dex_analysis"]["call_graph_edges"], int)


if __name__ == "__main__":
    unittest.main()
