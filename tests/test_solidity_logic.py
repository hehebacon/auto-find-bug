import tempfile
import unittest
from pathlib import Path

from auto_find_bug.solidity_logic import analyze_solidity_logic


class SolidityLogicReviewTests(unittest.TestCase):
    def test_flags_privileged_surface_and_external_call_ordering(self):
        source = """
        contract Vault {
            mapping(address => uint256) public balances;
            address public owner;
            function setFee(uint256 fee) external { fee = fee; }
            function withdraw(uint256 amount) external {
                (bool ok, ) = msg.sender.call{value: amount}("");
                balances[msg.sender] -= amount;
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Vault.sol").write_text(source, encoding="utf-8")
            result = analyze_solidity_logic(tmp)
        rules = {item["rule_id"] for item in result["findings"]}
        self.assertIn("SOL-LOGIC-001", rules)
        self.assertIn("SOL-LOGIC-002", rules)

    def test_ignores_comments_and_strings_and_recognizes_authorization_marker(self):
        source = '''
        contract Safe {
            // function upgrade() external { }
            string note = "function setOwner(address x) external { }";
            function setOwner(address next) external onlyOwner { owner = next; }
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Safe.sol").write_text(source, encoding="utf-8")
            result = analyze_solidity_logic(tmp)
        self.assertEqual(result["finding_count"], 0)

    def test_reports_unchecked_low_level_call(self):
        source = """
        contract Calls {
            function notify(address target) external {
                target.call("");
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Calls.sol").write_text(source, encoding="utf-8")
            result = analyze_solidity_logic(tmp)
        self.assertIn("SOL-LOGIC-003", {item["rule_id"] for item in result["findings"]})

    def test_skips_large_solidity_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Large.sol"
            path.write_text(" " * 1_000_001, encoding="utf-8")
            result = analyze_solidity_logic(tmp)
        self.assertEqual(result["files_scanned"], 0)
        self.assertEqual(result["files_skipped_large"], 1)


if __name__ == "__main__":
    unittest.main()
