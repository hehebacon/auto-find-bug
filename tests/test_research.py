import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from auto_find_bug import research


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"AFB_RESEARCH_DB": str(Path(self.temp.name) / "research.sqlite3")})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_classification_is_multi_label_and_has_fallback(self):
        labels = research._classify("Improper access control and SQL injection")
        self.assertIn("Authorization/access control", labels)
        self.assertIn("Input handling", labels)
        self.assertEqual(research._classify("unusual advisory text"), ["Unclassified / manual review"])

    def test_severity_bands(self):
        self.assertEqual(research._severity(9.8), "CRITICAL")
        self.assertEqual(research._severity(7.5), "HIGH")
        self.assertEqual(research._severity(5.0), "MEDIUM")
        self.assertEqual(research._severity(2.0), "LOW")
        self.assertEqual(research._severity(None), "UNKNOWN")

    def test_nvd_normalization_and_storage(self):
        cve = {
            "id": "CVE-2099-1234", "published": "2099-01-01T00:00:00.000",
            "lastModified": "2099-01-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "SQL injection permits unauthorized access."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            "weaknesses": [{"description": [{"value": "CWE-89"}]}],
            "references": [{"url": "https://example.org/advisory"}],
        }
        with patch.object(research, "_http_client") as factory:
            client = factory.return_value.__enter__.return_value
            response = client.get.return_value
            response.json.return_value = {"totalResults": 1, "vulnerabilities": [{"cve": cve}]}
            result = research.search_nvd("sql injection", 10)
        self.assertEqual(result["fetched"], 1)
        rows = research.list_advisories()
        self.assertEqual(rows[0]["id"], "CVE-2099-1234")
        self.assertIn("Input handling", rows[0]["categories"])
        self.assertEqual(rows[0]["cwes"], ["CWE-89"])

    def test_export_json(self):
        research._save([{
            "id": "CVE-2099-0001", "source": "NVD", "title": "Example", "summary": "Test",
            "published": None, "modified": None, "severity": "LOW", "cvss": 2.0,
            "cwes": [], "categories": ["Input handling"], "references": [],
            "exploited": False, "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
            "raw": {},
        }])
        output = Path(self.temp.name) / "out.json"
        research.export_advisories(output, "json")
        self.assertIn("CVE-2099-0001", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
