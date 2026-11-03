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


def build_scope_review(snapshot: dict) -> dict:
    """Classify third-party snapshot records offline; never expands or probes assets."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    in_snapshot, out_snapshot, no_bounty = [], [], []

    for raw in snapshot.get("assets", []):
        identifier = str(raw.get("asset_identifier", "")).strip()
        if not identifier:
            continue
        asset = {
            "asset_identifier": identifier,
            "asset_type": str(raw.get("asset_type", "UNKNOWN")).upper(),
            "submission_eligible": bool(raw.get("submission_eligible", False)),
            "bounty_eligible": bool(raw.get("bounty_eligible", False)),
            "maximum_severity": raw.get("maximum_severity"),
            "verification_status": "third_party_snapshot_unverified",
        }
        grouped[asset["asset_type"]].append(asset)
        if not asset["submission_eligible"]:
            asset["snapshot_classification"] = "out_of_scope_or_not_submission_eligible"
            out_snapshot.append(asset)
        elif not asset["bounty_eligible"]:
            asset["snapshot_classification"] = "submission_eligible_bounty_ineligible"
            no_bounty.append(asset)
        else:
            asset["snapshot_classification"] = "snapshot_eligible_unverified"
            in_snapshot.append(asset)

    return {
        "program_handle": snapshot.get("program_handle"),
        "canonical_policy_url": snapshot.get("canonical_policy_url"),
        "source_url": snapshot.get("source_url"),
        "snapshot_timestamp": snapshot.get("snapshot_publicly_verified_at"),
        "authorization": "not_established",
        "wildcard_expansion": "disabled",
        "network_activity": "none",
        "counts": {
            "total_parsed": len(in_snapshot) + len(out_snapshot) + len(no_bounty),
            "snapshot_eligible_unverified": len(in_snapshot),
            "out_of_scope_or_not_submission_eligible": len(out_snapshot),
            "submission_eligible_bounty_ineligible": len(no_bounty),
        },
        "groups_by_asset_type": {
            kind: sorted(items, key=lambda item: item["asset_identifier"].lower())
            for kind, items in sorted(grouped.items())
        },
        "snapshot_eligible_unverified": in_snapshot,
        "out_of_scope_or_not_submission_eligible": out_snapshot,
        "submission_eligible_bounty_ineligible": no_bounty,
        "limitations": [
            "This classification reflects third-party snapshot flags only.",
            "It does not prove current authorization or replace the live program policy.",
            "Separate exclusions and special testing rules may be missing.",
            "Wildcard assets are not expanded into hostnames.",
            "No discovery, scanning, crawling, authentication, or exploit testing is performed.",
        ],
    }


def write_scope_review(workspace: Path, snapshot: dict) -> dict:
    review = build_scope_review(snapshot)
    policy_dir, recon_dir = workspace / "policy", workspace / "reconnaissance"
    policy_dir.mkdir(parents=True, exist_ok=True)
    recon_dir.mkdir(parents=True, exist_ok=True)
    (policy_dir / "scope-review.json").write_text(
        json.dumps(review, indent=2) + "\n", encoding="utf-8"
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
        f"| Out of scope / not submission eligible | {review['counts']['out_of_scope_or_not_submission_eligible']} |",
        f"| Submission eligible, bounty ineligible | {review['counts']['submission_eligible_bounty_ineligible']} |",
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
    (policy_dir / "scope-review.md").write_text("\n".join(lines), encoding="utf-8")

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
        "\n".join(checklist), encoding="utf-8"
    )
    return review
