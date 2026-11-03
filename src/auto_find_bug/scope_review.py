from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import json


VULNERABILITY_CLASSES = [
    ("Authentication", "Review authentication design and documented account-recovery flows."),
    ("Authorization / access control", "Review documented roles and permissions."),
    ("Session management", "Review session lifecycle and published security requirements."),
    ("Input handling", "Review validation boundaries and the program's explicitly permitted rules."),
    ("Sensitive-data exposure", "Review protected-data definitions and prohibited access."),
    ("Business logic", "Review documented workflows without manipulating real accounts or transactions."),
    ("Mobile application security", "Review only app assets explicitly listed in the live scope."),
    ("Configuration and transport", "Missing hardening alone is informational unless impact and policy support a finding."),
]

ASSET_CLASS_MAP = {
    "URL": ["Authentication", "Authorization / access control", "Session management", "Input handling", "Sensitive-data exposure", "Business logic", "Configuration and transport"],
    "DOMAIN": ["Authentication", "Authorization / access control", "Session management", "Input handling", "Sensitive-data exposure", "Business logic", "Configuration and transport"],
    "WILDCARD": ["Authentication", "Authorization / access control", "Session management", "Input handling", "Sensitive-data exposure", "Business logic", "Configuration and transport"],
    "ANDROID": ["Mobile application security", "Authentication", "Authorization / access control", "Session management", "Sensitive-data exposure"],
    "IOS": ["Mobile application security", "Authentication", "Authorization / access control", "Session management", "Sensitive-data exposure"],
    "MOBILE_APPLICATION": ["Mobile application security", "Authentication", "Authorization / access control", "Session management", "Sensitive-data exposure"],
    "IP_ADDRESS": ["Configuration and transport"],
    "CIDR": ["Configuration and transport"],
    "SOURCE_CODE": ["Authentication", "Authorization / access control", "Session management", "Input handling", "Sensitive-data exposure", "Business logic", "Configuration and transport"],
}


def _eligibility_flag(value: object) -> bool | None:
    """Parse only explicit boolean-like values; unknown values remain unknown."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"yes", "true", "1"}:
            return True
        if normalized in {"no", "false", "0"}:
            return False
    return None


def build_scope_review(snapshot: dict) -> dict:
    """Classify third-party snapshot records offline; never expands or probes assets."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    eligible, not_submission_eligible, no_bounty, needs_review = [], [], [], []
    seen: set[tuple[str, str]] = set()
    skipped_records = 0
    duplicate_records = 0

    for raw in snapshot.get("assets", []):
        if not isinstance(raw, dict):
            skipped_records += 1
            continue
        identifier = str(raw.get("asset_identifier", "")).strip()
        if not identifier:
            skipped_records += 1
            continue

        asset_type = str(raw.get("asset_type") or "UNKNOWN").strip().upper()
        key = (asset_type, identifier.casefold())
        if key in seen:
            duplicate_records += 1
            continue
        seen.add(key)

        submission = _eligibility_flag(raw.get("submission_eligible"))
        bounty = _eligibility_flag(raw.get("bounty_eligible"))
        asset = {
            "asset_identifier": identifier,
            "asset_type": asset_type,
            "submission_eligible": submission,
            "bounty_eligible": bounty,
            "maximum_severity": raw.get("maximum_severity"),
            "verification_status": "third_party_snapshot_unverified",
            "applicable_review_classes": ASSET_CLASS_MAP.get(asset_type, [item[0] for item in VULNERABILITY_CLASSES]),
        }
        grouped[asset_type].append(asset)

        if submission is False:
            asset["snapshot_classification"] = "not_submission_eligible_in_snapshot"
            not_submission_eligible.append(asset)
        elif submission is True and bounty is False:
            asset["snapshot_classification"] = "submission_eligible_bounty_ineligible"
            no_bounty.append(asset)
        elif submission is True and bounty is True:
            asset["snapshot_classification"] = "snapshot_eligible_unverified"
            eligible.append(asset)
        else:
            asset["snapshot_classification"] = "eligibility_flags_incomplete_manual_review_required"
            needs_review.append(asset)

    total = len(eligible) + len(not_submission_eligible) + len(no_bounty) + len(needs_review)
    return {
        "program_handle": snapshot.get("program_handle"),
        "canonical_policy_url": snapshot.get("canonical_policy_url"),
        "source_url": snapshot.get("source_url"),
        "snapshot_timestamp": snapshot.get("snapshot_publicly_verified_at"),
        "authorization": "not_established",
        "wildcard_expansion": "disabled",
        "network_activity": "none",
        "counts": {
            "total_parsed": total,
            "snapshot_eligible_unverified": len(eligible),
            "not_submission_eligible_in_snapshot": len(not_submission_eligible),
            "submission_eligible_bounty_ineligible": len(no_bounty),
            "eligibility_flags_incomplete_manual_review_required": len(needs_review),
            "skipped_malformed_records": skipped_records,
            "duplicate_records_ignored": duplicate_records,
        },
        "groups_by_asset_type": {
            kind: sorted(items, key=lambda item: item["asset_identifier"].lower())
            for kind, items in sorted(grouped.items())
        },
        "snapshot_eligible_unverified": eligible,
        "not_submission_eligible_in_snapshot": not_submission_eligible,
        "submission_eligible_bounty_ineligible": no_bounty,
        "eligibility_flags_incomplete_manual_review_required": needs_review,
        "limitations": [
            "This classification reflects third-party snapshot flags only.",
            "Not submission-eligible in a snapshot is not proof that an asset is excluded by the live policy.",
            "It does not prove current authorization or replace the live program policy.",
            "Separate exclusions and special testing rules may be missing.",
            "Wildcard assets are not expanded into hostnames.",
            "Unknown eligibility flags are held for manual review rather than assumed false.",
            "No discovery, scanning, crawling, authentication, or exploit testing is performed.",
        ],
    }


def write_scope_review(workspace: Path, snapshot: dict) -> dict:
    review = build_scope_review(snapshot)
    policy_dir, recon_dir = workspace / "policy", workspace / "reconnaissance"
    policy_dir.mkdir(parents=True, exist_ok=True)
    recon_dir.mkdir(parents=True, exist_ok=True)
    (policy_dir / "scope-review.json").write_text(
        json.dumps(review, indent=2) + "\\n", encoding="utf-8"
    )

    lines = [
        "# Scope review — offline snapshot classification",
        "",
        f"- Program: {review.get('program_handle') or 'unknown'}",
        f"- Snapshot timestamp: {review.get('snapshot_timestamp') or 'not supplied'}",
        "- Authorization: **not established**",
        "- Network activity: **none**",
        "",
        "## Snapshot counts",
        "",
        "| Classification | Count |",
        "|---|---:|",
        f"| Snapshot-eligible, unverified | {review['counts']['snapshot_eligible_unverified']} |",
        f"| Not submission eligible in snapshot (not authoritative exclusion) | {review['counts']['not_submission_eligible_in_snapshot']} |",
        f"| Submission eligible, bounty ineligible | {review['counts']['submission_eligible_bounty_ineligible']} |",
        f"| Incomplete flags — manual review required | {review['counts']['eligibility_flags_incomplete_manual_review_required']} |",
        f"| Malformed records skipped | {review['counts']['skipped_malformed_records']} |",
        f"| Duplicate records ignored | {review['counts']['duplicate_records_ignored']} |",
        "",
        "## Assets grouped by type",
        "",
    ]
    for asset_type, assets in review["groups_by_asset_type"].items():
        lines.extend([f"### {asset_type}", ""])
        for asset in assets:
            lines.append(
                f"- {asset['asset_identifier']} — {asset['snapshot_classification']}; "
                f"submission={asset['submission_eligible']}; bounty={asset['bounty_eligible']}"
            )
            lines.append(
                "  - Review categories: " + ", ".join(asset["applicable_review_classes"])
            )
        lines.append("")
    lines.extend([
        "## Required manual policy review",
        "",
        "- Confirm the program is currently open and participation requirements are met.",
        "- Compare every exact asset identifier with the live canonical scope.",
        "- Read complete exclusions, announcements, asset-specific instructions, and testing rules.",
        "- Do not expand wildcards or infer authorization for related services, apps, vendors, or subsidiaries.",
        "- Keep unclear or conflicting assets blocked from testing.",
        "",
        "## Limitations",
        "",
        *[f"- {item}" for item in review["limitations"]],
        "",
    ])
    (policy_dir / "scope-review.md").write_text("\\n".join(lines), encoding="utf-8")

    checklist = [
        "# Vulnerability-class review checklist",
        "",
        "High-level taxonomy for policy review and learning only. This is not a scan plan, "
        "does not identify bugs, and does not authorize testing.",
        "",
    ]
    for title, note in VULNERABILITY_CLASSES:
        checklist.extend([
            f"## {title}", "", f"- {note}",
            "- Record policy restrictions and required evidence before considering activity.", "",
        ])
    checklist.extend([
        "## Never infer a finding", "",
        "- A category match is not a vulnerability.",
        "- Do not access another person's data or account.",
        "- Do not perform destructive, high-volume, social-engineering, or availability-impacting tests.",
        "- Do not assign severity without demonstrated impact and the program's severity rules.",
        "",
    ])
    (recon_dir / "vulnerability-class-checklist.md").write_text(
        "\\n".join(checklist), encoding="utf-8"
    )
    return review
