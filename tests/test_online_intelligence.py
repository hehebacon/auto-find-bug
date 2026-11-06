import unittest
from unittest.mock import MagicMock, patch

import httpx

from auto_find_bug.online_intelligence import MAX_BATCH, correlate_dependencies


def dependency(name="requests", version="2.31.0", exact=True, ecosystem="PyPI"):
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "version_is_exact": exact,
        "manifests": ["requirements.txt"],
    }


class OSVCorrelationTests(unittest.TestCase):
    def _client(self, payload, status_code=200):
        response = MagicMock()
        response.status_code = status_code
        response.json.return_value = payload
        response.raise_for_status.return_value = None
        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = None
        client.post.return_value = response
        return client

    def test_exact_version_query_preserves_affected_ranges_and_identity(self):
        advisory = {
            "id": "GHSA-test-1234-5678",
            "summary": "Test advisory",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}],
                "versions": ["2.31.0"],
            }],
            "references": [{"type": "ADVISORY", "url": "https://example.invalid/advisory"}],
        }
        client = self._client({"results": [{"vulns": [advisory]}]})
        with patch("auto_find_bug.online_intelligence.create_http_client", return_value=client):
            result = correlate_dependencies([dependency()])
        query = client.post.call_args.kwargs["json"]["queries"][0]
        self.assertEqual(query, {"package": {"ecosystem": "PyPI", "name": "requests"}, "version": "2.31.0"})
        match = result["results"][0]
        self.assertEqual(match["query_status"], "matched_advisories")
        self.assertEqual(match["advisories"][0]["affected"], advisory["affected"])
        self.assertEqual(match["advisories"][0]["id"], "GHSA-test-1234-5678")
        self.assertEqual(result["queried"], 1)

    def test_non_exact_versions_are_skipped_without_network(self):
        with patch("auto_find_bug.online_intelligence.create_http_client") as factory:
            result = correlate_dependencies([dependency(version=">=2.0", exact=False)])
        factory.assert_not_called()
        self.assertEqual(result["queried"], 0)
        self.assertEqual(result["skipped_without_exact_version"], 1)

    def test_batch_limit_is_reported(self):
        items = [dependency(name=f"pkg-{i}") for i in range(MAX_BATCH + 3)]
        client = self._client({"results": [{"vulns": []} for _ in range(MAX_BATCH)]})
        with patch("auto_find_bug.online_intelligence.create_http_client", return_value=client):
            result = correlate_dependencies(items)
        self.assertEqual(result["queried"], MAX_BATCH)
        self.assertEqual(result["skipped_batch_limit"], 3)
        self.assertEqual(len(result["results"]), MAX_BATCH)

    def test_incomplete_osv_response_fails_closed(self):
        client = self._client({"results": []})
        with patch("auto_find_bug.online_intelligence.create_http_client", return_value=client):
            with self.assertRaisesRegex(RuntimeError, "count mismatch"):
                correlate_dependencies([dependency()])

    def test_invalid_osv_schema_fails_closed(self):
        client = self._client({"unexpected": []})
        with patch("auto_find_bug.online_intelligence.create_http_client", return_value=client):
            with self.assertRaisesRegex(RuntimeError, "invalid response schema"):
                correlate_dependencies([dependency()])

    def test_http_failure_is_reported(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = None
        client.post.side_effect = httpx.ConnectError("offline")
        with patch("auto_find_bug.online_intelligence.create_http_client", return_value=client):
            with self.assertRaisesRegex(RuntimeError, "OSV public advisory query failed"):
                correlate_dependencies([dependency()])

    def test_malformed_advisory_record_fails_closed(self):
        client = self._client({"results": [{"vulns": ["not-an-advisory-object"]}]})
        with patch("auto_find_bug.online_intelligence.create_http_client", return_value=client):
            with self.assertRaisesRegex(RuntimeError, "malformed advisory record"):
                correlate_dependencies([dependency()])


if __name__ == "__main__":
    unittest.main()
