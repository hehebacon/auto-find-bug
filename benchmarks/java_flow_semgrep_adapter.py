from __future__ import annotations

"""Adapt Java AST flow findings to the existing OWASP scorecard input format."""

import argparse
import json
from pathlib import Path

from auto_find_bug.java_flow_analysis import analyze_java_flows


RULE_IDS = {
    "FLOW-JAVA-001": "auto-find-bug.java.servlet-to-sql",
    "FLOW-JAVA-002": "auto-find-bug.java.servlet-to-command",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    result = analyze_java_flows(args.source_root)
    if not result["available"]:
        raise SystemExit(result["note"])

    matches = []
    for finding in result["findings"]:
        rule = RULE_IDS.get(finding.get("rule_id"))
        if not rule:
            continue
        matches.append({
            "check_id": rule,
            "path": finding["file"],
            "start": {"line": finding["line"]},
            "extra": {
                "severity": "ERROR",
                "message": finding["title"],
                "lines": finding["evidence"],
                "metadata": {
                    "confidence": finding.get("confidence", "medium"),
                    "cwe": "CWE-89" if finding["rule_id"] == "FLOW-JAVA-001" else "CWE-78",
                },
                "flow": finding.get("flow", {}),
            },
        })

    payload = {
        "engine": result["engine"],
        "files_analyzed": result["files_analyzed"],
        "limitations": result["limitations"],
        "paths": {"scanned": result.get("analyzed_files", [])},
        "results": matches,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "engine": result["engine"],
        "files_analyzed": result["files_analyzed"],
        "finding_count": len(matches),
        "output": str(args.output),
        "limitations": result["limitations"],
    }, indent=2))


if __name__ == "__main__":
    main()
