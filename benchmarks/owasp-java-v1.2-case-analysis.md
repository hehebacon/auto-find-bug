# OWASP Benchmark Java v1.2 — case analysis

## Scope and baseline

- Benchmark commit: 0119da404a3418bc337beb529b72ae755f018f97
- Baseline analyzer commit: babb601e5afb39d166e00a47caa4d18e59b56be0
- Scored labels: Java SQL injection (CWE-89) and command injection (CWE-78)
- Baseline confusion matrix: TP=69, FP=46, FN=329, TN=311
- Baseline false negatives: 234 CWE-89 + 95 CWE-78
- Baseline false positives: 28 CWE-89 + 18 CWE-78

The CI workflow pins Semgrep 1.184.0, re-runs the baseline rules and current rules against the same checked-out benchmark commit, and uploads both complete scorecards. The benchmark labels and benchmark commit must remain unchanged.

## False-negative analysis

### CWE-89 — SQL injection (234 baseline misses)

Representative cases show several distinct coverage gaps:

1. **Missing SQL sink APIs and overloads**
   - BenchmarkTest00024–00026: request data is concatenated into SQL, then passed to JDBC prepareStatement or Spring JDBC query methods such as queryForObject and queryForRowSet.
   - BenchmarkTest00032–00034: SQL reaches Spring execute or JDBC Statement.execute overloads, including generated-key arguments.
   - BenchmarkTest00194: SQL reaches Spring batchUpdate.

2. **Missing request-source and container propagation**
   - BenchmarkTest00032: getParameterMap() → map lookup → array element → SQL.
   - BenchmarkTest00037–00039: parameter-name enumeration / parameter-value arrays are used to build the query.
   - BenchmarkTest00100 and 00115: cookie values and collection/map operations contribute to the query.

3. **Transformation and helper-flow gaps**
   - BenchmarkTest00194: request header data passes through URL decoding and Base64 encode/decode before reaching SQL.
   - Other missed cases use helper methods, map/list state, or additional framework APIs. A simple source-to-sink pattern does not reliably model these paths.

### CWE-78 — command injection (95 baseline misses)

Representative baseline misses include BenchmarkTest00007, 00091, 00092, and groups such as 00172–00176. The existing rule set did not cover all combinations of request source, command construction, overloaded Runtime.exec, and ProcessBuilder argument containers. These need to be tested as separate source → propagation → sink shapes; a match on a method name alone is not enough to establish an exploitable command path.

## False-positive analysis

### CWE-89 — SQL injection (28 baseline false positives)

Representative cases reviewed:

- **Constant-condition branches:** BenchmarkTest00329, 00344, and 00436 assign request-controlled data only in a branch that is unreachable after evaluating a constant arithmetic condition.
- **Collection mutation / indexed retrieval:** BenchmarkTest00773 adds a tainted value to a list, removes an earlier element, then reads a different safe element. A coarse List.add propagator taints the whole list and does not model the removal/index state.
- **Map overwrite and constant-key retrieval:** BenchmarkTest01219 retrieves a tainted value and later overwrites the variable with a safe map value; a flow-insensitive approximation can retain stale taint.
- **Helper-method context:** examples such as BenchmarkTest01001, 01085, and 01092 pass values through helper methods whose return value depends on local constants, branches, or collection state. Simple taint rules do not prove the returned value is still tainted.

### CWE-78 — command injection (18 baseline false positives)

- **Unreachable branch:** BenchmarkTest00090 and 00158 assign request-controlled data only in the else branch of a condition that is always true.
- Other false positives in the baseline list use similar branch, switch, or helper-method patterns where the analyzer does not prove whether the tainted assignment can reach the process sink.

## What the rule expansions changed

The measured iterations are:

| Iteration | TP | FP | FN | TN | Recall | False-positive rate |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 69 | 46 | 329 | 311 | 17.34% | 12.89% |
| Expanded SQL/process sinks | 234 | 154 | 164 | 203 | 58.79% | 43.14% |
| Expanded sources and propagation | 339 | 221 | 59 | 136 | 85.18% | 61.90% |

This confirms that the added sources, sinks, and propagators find many more labeled vulnerable cases, but they also over-approximate many safe paths. The latest rule set is therefore **experimental and not accepted as an accuracy improvement**. Do not hide this trade-off by reporting recall alone.

## Java AST flow-engine implementation status

A bounded Java AST engine has now been added behind the optional SAST extra. It models supported constant conditions, variable overwrites, literal arrays/List/Map state and selected collection mutations, and same-class or uniquely named helper methods. When the AST engine is available, broad Semgrep Java taint matches are suppressed rather than retained without path evidence. Parsed files use source-to-propagation-to-sink findings; unparsed files are explicitly listed as coverage gaps. A dedicated adapter feeds its results into the existing pinned scorecard without changing benchmark labels or the baseline.

**No new benchmark metrics are recorded here yet.** The CI run must parse the complete labeled Java corpus and produce the separate AST scorecard before any precision/recall claim is made. A parser gap or incomplete scan must remain visible as an incomplete benchmark, not be counted as a clean negative.

## Required next engineering work

1. Run the new Java AST scorecard on the exact pinned OWASP Benchmark Java v1.2 commit.
2. Inspect every remaining false positive and false negative, including source → propagation → sink traces.
3. Extend only the demonstrated gaps in branch feasibility, array/map/list state, overwrites, and helper summaries.
4. Compare TP/FP/FN/TN, precision, recall, and false-positive rate against the unchanged baseline and previous Semgrep iteration.
5. Add regression tests for each fixed case and nearby safe variants.

No benchmark-specific case ID should be hard-coded as safe or vulnerable in the detector. The benchmark is a measurement corpus, not a list of exceptions.
