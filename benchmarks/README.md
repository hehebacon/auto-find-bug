# Security regression benchmark

This directory documents the labeled regression tests in `tests/test_security_benchmark.py`.

The test corpus contains four synthetic positive cases (Python, JavaScript, Java, PHP) and four synthetic negative cases. The expected labels are checked against the bundled Semgrep rules. The current CI gate expects TP=4, FP=0, FN=0, TN=4 on this small corpus.

**Interpretation:** this is a regression smoke benchmark, not a representative sample of production applications. Its 100% score on eight hand-authored examples must not be presented as 100% real-world precision or recall. Real-world accuracy requires a larger, independently labeled corpus spanning frameworks, versions, code paths, and application architectures, with false positives and false negatives adjudicated by reviewers.


## Latest measured result

Pinned benchmark: OWASP Benchmark Java v1.2, benchmark commit `0119da404a3418bc337beb529b72ae755f018f97`. CI pins Semgrep `1.184.0` and scans all 2,740 Java files; all 755 labeled SQLi/command-injection cases are scored. The workflow re-runs the historical baseline rule file from analyzer commit `babb601e5afb39d166e00a47caa4d18e59b56be0` on the same runner and retains complete case-ID lists for both scorecards.

### Iteration comparison

| Metric | Baseline rules | Expanded sinks | Expanded sources + propagation |
|---|---:|---:|---:|
| True positives | 69 | 234 | 339 |
| False positives | 46 | 154 | 221 |
| False negatives | 329 | 164 | 59 |
| True negatives | 311 | 203 | 136 |
| Precision | 60.00% | 60.31% | 60.54% |
| Recall | 17.34% | 58.79% | 85.18% |
| False-positive rate | 12.89% | 43.14% | 61.90% |

### Latest per-CWE result

| CWE | TP | FP | FN | TN | Precision | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-89 SQL injection | 245 | 150 | 27 | 82 | 62.03% | 90.07% | 64.66% |
| CWE-78 Command injection | 94 | 71 | 32 | 54 | 56.97% | 74.60% | 56.80% |

The latest iteration catches substantially more labeled vulnerable cases, but the false-positive rate is too high. **This is not an accepted accuracy result.** More source/propagator coverage has traded many safe cases for additional detections; precision barely moved. Do not use the recall increase alone as evidence that the detector is reliable.

### Baseline error analysis

The baseline's 329 false negatives split into 234 SQL injection and 95 command injection cases. The 46 false positives split into 28 SQL injection and 18 command injection cases. Representative patterns and case IDs are documented in [OWASP Java case analysis](owasp-java-v1.2-case-analysis.md). CI artifacts retain the full case-ID lists, not only a truncated sample.

The scorecard compares TP/FP/FN/TN, precision, recall, and false-positive rate against a pinned baseline. Keep the benchmark commit and expected labels fixed; do not modify labels to improve scores. The two scored CWEs are the only OWASP categories currently mapped by the Java rules.

CI now also runs the separate bounded Java AST flow engine against the same pinned corpus and writes `owasp-java-ast-scorecard.json`. This result is intentionally separate from the Semgrep iteration table above. The AST engine must parse all labeled Java cases for the scorecard to be considered complete; parser gaps are reported as unscanned cases and fail the benchmark step. No Java AST accuracy result is published until that CI artifact exists and is reviewed.

This benchmark does not establish accuracy for other OWASP categories, other languages, arbitrary real-world projects, or exploitability. A successful CI run means the tests and scoring pipeline completed; it does not mean the detector is production-ready.
