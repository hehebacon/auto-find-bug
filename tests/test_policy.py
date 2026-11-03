import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from auto_find_bug.policy import load_manual_policy_text, policy_extraction_incomplete


class PolicyExtractionTests(unittest.TestCase):
    def test_detects_javascript_shell_only_page(self):
        self.assertTrue(policy_extraction_incomplete("HackerOne"))

    def test_accepts_substantial_policy_text(self):
        text = "In scope assets and exclusions. " * 10
        self.assertFalse(policy_extraction_incomplete(text))

    def test_loads_operator_supplied_policy_text(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "policy.txt"
            expected = "Program policy and in-scope assets. " * 3
            path.write_text(expected, encoding="utf-8")
            self.assertEqual(load_manual_policy_text(str(path)), expected.strip())


if __name__ == "__main__":
    unittest.main()
