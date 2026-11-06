# Security regression benchmark

This directory documents the labeled regression tests in `tests/test_security_benchmark.py`.

The test corpus contains four synthetic positive cases (Python, JavaScript, Java, PHP) and four synthetic negative cases. The expected labels are checked against the bundled Semgrep rules. The current CI gate expects TP=4, FP=0, FN=0, TN=4 on this small corpus.

**Interpretation:** this is a regression smoke benchmark, not a representative sample of production applications. Its 100% score on eight hand-authored examples must not be presented as 100% real-world precision or recall. Real-world accuracy requires a larger, independently labeled corpus spanning frameworks, versions, code paths, and application architectures, with false positives and false negatives adjudicated by reviewers.
