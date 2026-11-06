import shutil
import tempfile
import unittest
from pathlib import Path

from auto_find_bug.semgrep_analysis import analyze_with_semgrep


@unittest.skipUnless(shutil.which("semgrep"), "Semgrep optional engine is not installed")
class SecurityRegressionBenchmark(unittest.TestCase):
    """Small labeled regression corpus; not a claim of real-world recall."""

    CASES = {
        "python_vuln.py": (
            "import os\ndef handler(request):\n    value = request.args.get('cmd')\n    os.system(value)\n",
            "auto-find-bug.python.request-to-shell",
        ),
        "javascript_vuln.js": (
            "function handler(req) { const value = req.query.cmd; eval(value); }\n",
            "auto-find-bug.javascript.request-to-eval",
        ),
        "java_vuln.java": (
            "class Demo { void handle(HttpServletRequest req, Statement stmt) throws Exception { String value = req.getParameter(\"q\"); stmt.executeQuery(value); } }\n",
            "auto-find-bug.java.servlet-to-sql",
        ),
        "php_vuln.php": (
            "<?php $value = $_GET['cmd']; system($value); ?>\n",
            "auto-find-bug.php.request-to-shell",
        ),
        "python_safe.py": (
            "def handler(request, cursor):\n    value = request.args.get('q')\n    cursor.execute('SELECT * FROM items WHERE name = ?', (value,))\n",
            None,
        ),
        "javascript_safe.js": (
            "function handler(req) { const value = req.query.q; console.log(value); }\n",
            None,
        ),
        "java_safe.java": (
            "class Safe { void handle(HttpServletRequest req) { String value = req.getParameter(\"q\"); System.out.println(value); } }\n",
            None,
        ),
        "php_safe.php": (
            "<?php $value = $_GET['q']; echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); ?>\n",
            None,
        ),
    }

    def test_labeled_multilanguage_regression_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename, (source, _expected_rule) in self.CASES.items():
                (root / filename).write_text(source, encoding="utf-8")
            result = analyze_with_semgrep(root)

        self.assertTrue(result["available"])
        observed = {
            Path(item["file"]).name: item["rule_id"]
            for item in result["findings"]
        }
        true_positive = 0
        false_negative = 0
        false_positive = 0
        true_negative = 0
        for filename, (_source, expected_rule) in self.CASES.items():
            actual = observed.get(filename)
            if expected_rule:
                if actual == expected_rule:
                    true_positive += 1
                else:
                    false_negative += 1
            elif actual is None:
                true_negative += 1
            else:
                false_positive += 1

        self.assertEqual(
            (true_positive, false_positive, false_negative, true_negative),
            (4, 0, 0, 4),
            msg=f"Regression benchmark mismatch. Confusion counts: TP={true_positive}, FP={false_positive}, FN={false_negative}, TN={true_negative}; full result={result}",
        )


if __name__ == "__main__":
    unittest.main()
