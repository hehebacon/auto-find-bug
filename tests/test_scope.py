import unittest

from auto_find_bug.scope import extract_scope_candidates, normalize_confirmed_assets


class ScopeTests(unittest.TestCase):
    def test_extracts_domains_as_candidates(self):
        text = "In scope: https://app.example.com and api.example.org. Excluded: *.legacy.example.net"
        self.assertEqual(
            extract_scope_candidates(text),
            ["api.example.org", "app.example.com", "legacy.example.net"],
        )

    def test_normalizes_only_concrete_domains(self):
        self.assertEqual(
            normalize_confirmed_assets([" App.Example.com ", "*.example.com", "https://x.example.com/path", "api.example.org"]),
            ["app.example.com", "api.example.org"],
        )


if __name__ == "__main__":
    unittest.main()
