import os
import unittest

from auto_find_bug.online_intelligence import correlate_dependencies


@unittest.skipUnless(os.environ.get("AFB_LIVE_OSV_TEST") == "1", "Live OSV integration runs only in CI")
class LiveOSVIntegrationTests(unittest.TestCase):
    def test_public_osv_returns_advisories_for_known_affected_exact_version(self):
        result = correlate_dependencies([{
            "ecosystem": "PyPI",
            "name": "urllib3",
            "version": "1.24.1",
            "version_is_exact": True,
            "manifests": ["requirements.txt"],
        }])
        self.assertEqual(result["queried"], 1)
        self.assertEqual(len(result["results"]), 1)
        match = result["results"][0]
        self.assertEqual(match["query_version"], "1.24.1")
        self.assertGreater(
            match["advisory_count"], 0,
            msg="OSV no longer returns an advisory for the pinned known-affected urllib3 version; review fixture before changing this test.",
        )
        self.assertTrue(all(item["id"] and item["url"] for item in match["advisories"]))
        self.assertTrue(all(isinstance(item["affected"], list) for item in match["advisories"]))


if __name__ == "__main__":
    unittest.main()
