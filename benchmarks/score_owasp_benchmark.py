from __future__ import annotations

"""Score Auto Find Bug's Java SQLi/command-injection rules on OWASP Benchmark v1.2."""

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any

TEST_NAME = re.compile(r"(BenchmarkTest\d+)[.]java$")
RULE_BY_CWE = {
    "89": "auto-find-bug.java.servlet-to-sql",
    "78": "auto-find-bug.java.servlet-to-command",
}


def score(expected_csv: Path, semgrep_json: Path, benchmark_commit: str) -> dict[str, Any]:
    with expected_csv.open(newline="", encoding="utf-8") as stream:
        rows = [
            row for row in csv.reader(stream)
            if row and not row[0].lstrip().startswith("#") and len(row) >= 4
        ]
    selected = {
        row[0]: {"category": row[1], "vulnerable": row[2].strip().lower() == "true", "cwe": row[3].strip()}
        for row in rows if row[3].strip() in RULE_BY_CWE
    }
    if not selected:
        raise ValueError("No Java SQLi/command-injection cases found in expected-results CSV.")

    payload = json.loads(semgrep_json.read_text(encoding="utf-8"))
    results = payload.get("results")
    if not isinstance(results, list):
        raise ValueError("Semgrep output has no results array.")

    reported: dict[str, set[str]] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        match = TEST_NAME.search(Path(str(item.get("path", ""))).name)
        if not match:
            continue
        test_name = match.group(1)
        rule_id = str(item.get("check_id", ""))
        for cwe, expected_rule in RULE_BY_CWE.items():
            if rule_id.endswith(expected_rule):
                reported.setdefault(test_name, set()).add(cwe)

    scanned_paths = (payload.get("paths") or {}).get("scanned") or []
    scanned_names = {
        match.group(1)
        for path in scanned_paths if (match := TEST_NAME.search(Path(str(path)).name))
    }
    report: dict[str, Any] = {
        "benchmark": "OWASP Benchmark Java v1.2",
        "benchmark_commit": benchmark_commit,
        "scored_categories": ["SQL injection (CWE-89)", "Command injection (CWE-78)"],
        "scope_note": "Only the two Java CWEs covered by bundled rules are scored; other OWASP categories are not evaluated.",
        "semgrep_files_scanned": len(scanned_paths),
        "benchmark_cases_in_scope": len(selected),
        "benchmark_cases_scanned": len(set(selected) & scanned_names),
        "categories": {},
    }

    totals = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for cwe, rule_id in RULE_BY_CWE.items():
        cases = [(name, case) for name, case in selected.items() if case["cwe"] == cwe]
        tp = fp = fn = tn = 0
        missed_cases = []
        false_positive_cases = []
        detected_cases = []
        for name, case in cases:
            flagged = cwe in reported.get(name, set())
            if case["vulnerable"] and flagged:
                tp += 1
                detected_cases.append(name)
            elif case["vulnerable"] and not flagged:
                fn += 1
                missed_cases.append(name)
            elif not case["vulnerable"] and flagged:
                fp += 1
                false_positive_cases.append(name)
            else:
                tn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        category = {
            "rule_id": rule_id,
            "total": len(cases),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "false_positive_rate": round(fpr, 6),
            "youden_score": round(recall - fpr, 6),
            "missed_cases_sample": missed_cases[:100],
            "false_positive_cases_sample": false_positive_cases[:100],
            "detected_cases_sample": detected_cases[:100],
        }
        report["categories"][cwe] = category
        for key in totals:
            totals[key] += category[key]
    tp, fp, fn, tn = (totals[key] for key in ("tp", "fp", "fn", "tn"))
    report["overall_scored_subset"] = {
        **totals,
        "total": sum(totals.values()),
        "precision": round(tp / (tp + fp), 6) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 6) if tp + fn else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 6) if fp + tn else 0.0,
    }
    report["not_scanned_cases"] = len(set(selected) - scanned_names)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected", required=True, type=Path)
    parser.add_argument("--semgrep-json", required=True, type=Path)
    parser.add_argument("--benchmark-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = score(args.expected, args.semgrep_json, args.benchmark_commit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report["not_scanned_cases"]:
        raise SystemExit(f"Benchmark scan incomplete: {report['not_scanned_cases']} labeled cases were not scanned.")


if __name__ == "__main__":
    main()
