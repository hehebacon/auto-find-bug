# Security regression benchmark

This directory documents the labeled regression tests in `tests/test_security_benchmark.py`.

The test corpus contains four synthetic positive cases (Python, JavaScript, Java, PHP) and four synthetic negative cases. The expected labels are checked against the bundled Semgrep rules. The current CI gate expects TP=4, FP=0, FN=0, TN=4 on this small corpus.

**Interpretation:** this is a regression smoke benchmark, not a representative sample of production applications. Its 100% score on eight hand-authored examples must not be presented as 100% real-world precision or recall. Real-world accuracy requires a larger, independently labeled corpus spanning frameworks, versions, code paths, and application architectures, with false positives and false negatives adjudicated by reviewers.


## Latest measured result

Pinned benchmark: OWASP Benchmark Java v1.2, benchmark commit `0119da404a3418bc337beb529b72ae755f018f97`. The comparison baseline is analyzer commit `babb601e5afb39d166e00a47caa4d18e59b56be0`. The expanded Java rules were measured at analyzer commit `0ff073532d30a4410af52b32f07cc5b51f9720b5` on the same pinned corpus. All 2,740 Java files were scanned; all 755 labeled SQLi/command-injection cases were included.

### Overall comparison

| Metric | Baseline | Expanded rules | Change |
|---|---:|---:|---:|
| True positives | 69 | 234 | +165 |
| False positives | 46 | 154 | +108 |
| False negatives | 329 | 164 | -165 |
| True negatives | 311 | 203 | -108 |
| Precision | 60.00% | 60.31% | +0.31 pp |
| Recall | 17.34% | 58.79% | +41.46 pp |
| False-positive rate | 12.89% | 43.14% | +30.25 pp |

### Per-CWE result after expansion

| CWE | TP | FP | FN | TN | Precision | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-89 SQL injection | 155 | 95 | 117 | 137 | 62.00% | 56.99% | 40.95% |
| CWE-78 Command injection | 79 | 59 | 47 | 66 | 57.25% | 62.70% | 47.20% |

The rule expansion materially improved recall but also caused a large increase in false positives. This is **not an accepted quality improvement yet**. Initial source review found examples where Semgrep over-approximates taint across a collection after an element is removed, and where it does not prove a branch condition is constant. These are analysis limitations, not cases to suppress with benchmark-specific exceptions.

The scorecard now records the complete missed-case and false-positive ID lists for each CWE, as well as the first 100 IDs for quick inspection. CI compares TP/FP/FN/TN, precision, recall, and false-positive rate against the pinned baseline. Keep the benchmark commit and expected labels fixed; do not modify labels to improve scores.

The benchmark only measures Java CWE-89 and CWE-78. It does not establish accuracy for other OWASP categories, other languages, arbitrary real-world projects, or exploitability. A successful CI run means the tests and scoring pipeline completed; it does not mean the detector is production-ready.
