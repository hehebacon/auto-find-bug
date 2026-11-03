from __future__ import annotations

import json
from pathlib import Path

from .scope import extract_scope_candidates

EXCLUSION_TERMS = ("out of scope", "not in scope", "excluded", "exclusion", "do not test", "not permitted", "not eligible")
INCLUSION_TERMS = ("in scope", "eligible for testing", "testing is permitted", "testing is allowed")
RULE_TERMS = {
    "rate_limits": ("rate limit", "requests per second", "requests per minute"),
    "account_requirements": ("test account", "testing account", "provided account"),
    "data_handling": ("personal data", "user data", "customer data", "sensitive data"),
    "automation_rules": ("automated testing", "automated scanning", "scanner", "crawling"),
    "reporting_rules": ("responsible disclosure", "disclosure policy", "report submission"),
    "program_protections": ("safe harbor", "good faith research"),
}
MAX_EXCERPTS = 250


def _matches(line: str, terms: tuple[str, ...]) -> bool:
    lowered = line.casefold()
    return any(term in lowered for term in terms)


def analyze_policy_text(policy_text: str, source_url: str | None = None) -> dict:
    """Extract policy clues for human review; extracted text never establishes permission."""
    candidates = set(extract_scope_candidates(policy_text))
    exclusions, inclusions = [], []
    rules = {key: [] for key in RULE_TERMS}
    excluded_hosts, included_hosts = set(), set()

    for number, raw in enumerate(policy_text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        hosts = set(extract_scope_candidates(line))
        if _matches(line, EXCLUSION_TERMS):
            exclusions.append({"line": number, "text": line[:1000], "asset_candidates": sorted(hosts)})
            excluded_hosts.update(hosts)
        elif _matches(line, INCLUSION_TERMS):
            inclusions.append({"line": number, "text": line[:1000], "asset_candidates": sorted(hosts)})
            included_hosts.update(hosts)
        for key, terms in RULE_TERMS.items():
            if _matches(line, terms):
                rules[key].append({"line": number, "text": line[:1000]})

    conflicts = sorted(excluded_hosts & included_hosts)
    return {
        "source_url": source_url,
        "authorization": "not_established",
        "analysis_mode": "offline_text_review",
        "network_activity": "none",
        "completeness": "heuristic_incomplete_manual_review_required",
        "candidate_hosts_unverified": sorted(candidates),
        "exclusion_statements": exclusions[:MAX_EXCERPTS],
        "inclusion_statements": inclusions[:MAX_EXCERPTS],
        "exclusion_asset_candidates_unverified": sorted(excluded_hosts),
        "inclusion_asset_candidates_unverified": sorted(included_hosts),
        "conflicting_asset_candidates": conflicts,
        "policy_rules": {key: values[:MAX_EXCERPTS] for key, values in rules.items()},
        "counts": {
            "candidate_hosts": len(candidates),
            "exclusion_statements": len(exclusions),
            "inclusion_statements": len(inclusions),
            "exclusion_asset_candidates": len(excluded_hosts),
            "inclusion_asset_candidates": len(included_hosts),
            "conflicts": len(conflicts),
        },
        "limitations": [
            "Keyword extraction can miss information in tables, images, scripts, linked documents, or unusual wording.",
            "A host mentioned in policy text is only a candidate and is not automatically in scope.",
            "An exclusion candidate may have exceptions or asset-specific conditions.",
            "Third-party snapshots are not authoritative and may omit exclusions.",
            "Compare all results with the current canonical policy and program announcements.",
            "This module performs no network checks against listed assets.",
        ],
    }


def write_policy_analysis(workspace: Path, policy_text: str, source_url: str | None = None) -> dict:
    result = analyze_policy_text(policy_text, source_url)
    folder = workspace / "policy"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "policy-analysis.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# Offline policy analysis", "",
        f"- Source: {source_url or 'operator-supplied text'}",
        "- Permission status: **not established**",
        "- Completeness: **heuristic; manual review required**",
        "- Network activity against listed assets: **none**", "",
        "## Summary", "",
        f"- Host candidates: {result['counts']['candidate_hosts']}",
        f"- Inclusion statements: {result['counts']['inclusion_statements']}",
        f"- Exclusion statements: {result['counts']['exclusion_statements']}",
        f"- Conflicts requiring review: {result['counts']['conflicts']}", "",
        "## Exclusion asset candidates", "",
    ]
    lines.extend([f"- {host} — unverified; compare with canonical policy" for host in result["exclusion_asset_candidates_unverified"]] or ["- None extracted."])
    lines.extend(["", "## Inclusion asset candidates", ""])
    lines.extend([f"- {host} — unverified; not permission" for host in result["inclusion_asset_candidates_unverified"]] or ["- None extracted."])
    lines.extend(["", "## Conflicts requiring review", ""])
    lines.extend([f"- {host} appears in both inclusion and exclusion statements." for host in result["conflicting_asset_candidates"]] or ["- None detected by keyword matching."])
    lines.extend(["", "## Program rules and requirements", ""])
    for key, records in result["policy_rules"].items():
        if records:
            lines.extend([f"### {key.replace('_', ' ').title()}", ""])
            lines.extend([f"- Line {item['line']}: {item['text']}" for item in records])
            lines.append("")
    lines.extend(["## Extracted statements", ""])
    for heading, records in (("Exclusion", result["exclusion_statements"]), ("Inclusion", result["inclusion_statements"])):
        lines.extend([f"### {heading}", ""])
        lines.extend([f"- Line {item['line']}: {item['text']}" for item in records] or ["- None extracted."])
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend([f"- {item}" for item in result["limitations"]])
    lines.append("")
    (folder / "policy-analysis.md").write_text("\n".join(lines), encoding="utf-8")
    return result
