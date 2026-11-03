import unittest
from unittest.mock import patch

from auto_find_bug import web_audit


class WebAuditTests(unittest.TestCase):
    def test_requires_explicit_authorization(self):
        with self.assertRaisesRegex(ValueError, "explicit permission"):
            web_audit.audit_public_page("https://example.com", authorized=False)

    def test_rejects_plain_http(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            web_audit.validate_audit_url("http://example.com")

    def test_rejects_non_public_resolution(self):
        with patch.object(web_audit.socket, "getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 443))]):
            with self.assertRaisesRegex(ValueError, "public IP"):
                web_audit.validate_audit_url("https://example.com")

    def test_one_page_audit_reports_missing_headers_and_form_action(self):
        class FakeResponse:
            is_redirect = False
            status_code = 200
            encoding = "utf-8"
            headers = {"content-type": "text/html; charset=utf-8"}
            def raise_for_status(self): pass
            def iter_bytes(self):
                yield b'<html><form action="http://example.com/send"></form><script src="https://cdn.example/x.js"></script></html>'
        class FakeStream:
            def __enter__(self): return FakeResponse()
            def __exit__(self, *args): return False
        class FakeClient:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def stream(self, *args, **kwargs): return FakeStream()
        with patch.object(web_audit, "validate_audit_url", return_value="https://example.com"), patch.object(
            web_audit, "create_http_client", return_value=FakeClient()
        ):
            result = web_audit.audit_public_page("https://example.com", authorized=True)
        rules = {item["rule_id"] for item in result["findings"]}
        self.assertIn("SEC001", rules)
        self.assertIn("SEC007", rules)
        self.assertEqual(result["requests_sent"], 1)
        self.assertFalse(result["crawl_performed"])


if __name__ == "__main__":
    unittest.main()
