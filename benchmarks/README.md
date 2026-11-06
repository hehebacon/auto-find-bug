# Security regression benchmark

This directory documents the labeled regression tests in `tests/test_security_benchmark.py`.

The test corpus contains four synthetic positive cases (Python, JavaScript, Java, PHP) and four synthetic negative cases. The expected labels are checked against the bundled Semgrep rules. The current CI gate expects TP=4, FP=0, FN=0, TN=4 on this small corpus.

**Interpretation:** this is a regression smoke benchmark, not a representative sample of production applications. Its 100% score on eight hand-authored examples must not be presented as 100% real-world precision or recall. Real-world accuracy requires a larger, independently labeled corpus spanning frameworks, versions, code paths, and application architectures, with false positives and false negatives adjudicated by reviewers.


## Latest measured result

Pinned run: OWASP Benchmark Java v1.2, benchmark commit `0119da404a3418bc337beb529b72ae755f018f97`, Auto Find Bug commit `577b322d3f2b693debeebcaf85f5e288dc773abd`.

Semgrep scanned all 2,740 Java files. The scored subset contains 755 cases for SQL injection (CWE-89) and command injection (CWE-78), the only two OWASP categories currently mapped by the bundled Java rules.

| Metric | Result |
|---|---:|
| True positives | 69 |
| False positives | 46 |
| False negatives | 329 |
| True negatives | 311 |
| Precision | 60.00% |
| Recall | 17.34% |
| False-positive rate | 12.89% |

This is a measured baseline, **not an acceptable claim of high coverage**. The analyzer currently misses most vulnerable cases in this benchmark and flags some safe cases. Do not treat a clean scan as evidence that an application is secure. The next work is to improve Java source/sink coverage and context handling, then rerun the same pinned benchmark and compare all four confusion-matrix values. Other OWASP categories and non-Java real applications remain unmeasured.
