import sys
import unittest
from pathlib import Path

# Support running unittest directly from a source checkout without pip install -e .
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from auto_find_bug.scope import extract_scope_candidates, normalize_confirmed_assets
from auto_find_bug.checks import _safe_target, run_metadata_checks


class ScopeTests(unittest.TestCase):
    def test_extracts_concrete_domains_as_candidates(self):
        text = "In scope: https://app.example.com and api.example.org. Excluded: *.legacy.example.net"
        self.assertEqual(
            extract_scope_candidates(text),
            ["api.example.org", "app.example.com"],
        )

    def test_normalizes_only_concrete_domains(self):
        self.assertEqual(
            normalize_confirmed_assets([" App.Example.com ", "*.example.com", "https://x.example.com/path", "api.example.org"]),
            ["app.example.com", "api.example.org"],
        )

    def test_active_target_checks_are_disabled(self):
        with self.assertRaises(RuntimeError):
            run_metadata_checks(["example.com"])

    def test_target_builder_rejects_paths_and_plain_http(self):
        self.assertEqual(_safe_target("app.example.com"), "https://app.example.com/")
        for value in ("http://app.example.com", "app.example.com/admin", "app.example.com:8443"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    _safe_target(value)


if __name__ == "__main__":
    unittest.main()
