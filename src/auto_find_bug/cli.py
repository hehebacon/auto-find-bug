from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.table import Table

from .hackerone_scope import fetch_hackerone_public_snapshot, hackerone_handle_from_url
from .policy import (
    fetch_policy,
    load_manual_policy_text,
    policy_extraction_incomplete,
    validate_program_url,
)
from .reports import write_reports
from .policy_analysis import write_policy_analysis
from .scope_review import write_scope_review
from .scope import extract_scope_candidates, normalize_confirmed_assets
from .workspace import create_workspace
from . import research
from .research import ResearchError
from . import code_audit, web_audit

console = Console()


def log(message: str) -> None:
    now = datetime.now().astimezone().strftime("%H:%M:%S.%f")[:-3]
    console.print(f"[dim][{now}][/dim] {message}")


def boot() -> None:
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]AUTO FIND BUG[/bold cyan]\n[dim]Scope-first Bug Bounty research assistant[/dim]",
        border_style="cyan",
    ))
    tasks = [
        "Initializing terminal interface",
        "Loading policy review module",
        "Loading candidate scope parser",
        "Loading evidence and report modules",
        "Loading standard network client",
    ]
    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
        TimeElapsedColumn(), console=console, transient=True,
    ) as progress:
        task = progress.add_task("Booting", total=len(tasks))
        for item in tasks:
            progress.update(task, description=item)
            time.sleep(0.12)
            progress.advance(task)
    log("Core ready. No target is authorized by discovery alone.")


def _save_scope(workspace: Path, program_url: str, assets: list[str]) -> None:
    data = {
        "program_url": program_url,
        "assets": [{"host": asset, "operator_confirmed": True} for asset in assets],
        "excluded_assets": [],
        "confirmed_by_operator": True,
        "confirmation_note": "Operator attested that each selected hostname is explicitly in scope in the current live policy.",
    }
    (workspace / "policy" / "scope.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )


def run() -> None:
    boot()
    console.print()
    program_url = Prompt.ask("[bold cyan]Bug Bounty policy URL[/bold cyan]").strip()
    try:
        program_url = validate_program_url(program_url)
    except ValueError as exc:
        console.print(f"[red]Invalid URL:[/red] {exc}")
        return

    program_handle = hackerone_handle_from_url(program_url)
    workspace = create_workspace(program_url, program_name=program_handle)
    log(f"Created workspace: {workspace}")

    try:
        with console.status("[cyan]Fetching the supplied public policy page..."):
            html, policy_text = fetch_policy(program_url)
        (workspace / "policy" / "policy-source.html").write_text(html, encoding="utf-8")

        extraction_method = "page_html"
        if policy_extraction_incomplete(policy_text):
            handle = hackerone_handle_from_url(program_url)
            if handle:
                try:
                    with console.status("[cyan]Looking up the public structured-scope snapshot..."):
                        snapshot = fetch_hackerone_public_snapshot(program_url)
                    (workspace / "policy" / "public-scope-source.html").write_text(
                        snapshot.pop("page_html"), encoding="utf-8"
                    )
                    snapshot_text = snapshot.pop("page_text")
                    snapshot_policy = snapshot.pop("policy_text")
                    (workspace / "policy" / "policy-text.md").write_text(
                        "# Policy snapshot (third-party mirror)\n\n"
                        "Canonical source: " + program_url + "\n"
                        "Mirror source: " + snapshot["source_url"] + "\n\n"
                        + (snapshot_policy or snapshot_text) + "\n",
                        encoding="utf-8",
                    )
                    (workspace / "policy" / "scope-inventory.json").write_text(
                        json.dumps(snapshot, indent=2) + "\n", encoding="utf-8"
                    )
                    review = write_scope_review(workspace, snapshot)
                    write_policy_analysis(workspace, snapshot_policy or snapshot_text, program_url)
                    (workspace / "policy" / "extraction-status.json").write_text(
                        json.dumps({
                            "status": "THIRD_PARTY_SCOPE_SNAPSHOT_IMPORTED",
                            "method": "bastet_public_snapshot",
                            "program_handle": handle,
                            "asset_count": snapshot["asset_count"],
                            "exclusions_complete": False,
                            "authorization": "not_established",
                        }, indent=2) + "\n",
                        encoding="utf-8",
                    )
                    eligible = sum(1 for item in snapshot["assets"] if item["submission_eligible"])
                    bounty = sum(1 for item in snapshot["assets"] if item["bounty_eligible"])
                    console.print(Panel(
                        f"Program: {handle}\n"
                        f"Assets imported: {snapshot['asset_count']}\n"
                        f"Submission-eligible in snapshot: {eligible}\n"
                        f"Bounty-eligible in snapshot: {bounty}\n"
                        f"Snapshot timestamp: {snapshot.get('snapshot_publicly_verified_at') or 'not provided'}\n\n"
                        "[yellow]Third-party snapshot only. Exclusions may be missing and data may be stale. "
                        "This is an inventory, NOT authorization. No targets will be checked.[/yellow]",
                        title="PUBLIC SCOPE INVENTORY IMPORTED",
                        border_style="yellow",
                    ))
                    console.print(f"Saved inventory: {workspace / 'policy' / 'scope-inventory.json'}")
                    console.print(f"Scope review: {workspace / 'policy' / 'scope-review.md'}")
                    console.print(f"Vulnerability taxonomy: {workspace / 'reconnaissance' / 'vulnerability-class-checklist.md'}")
                    console.print(f"Policy analysis: {workspace / 'policy' / 'policy-analysis.md'}")
                    write_reports(workspace, [], [])
                    console.print(f"Snapshot classification: {review['counts']}")
                    console.print(f"Canonical policy: {program_url}")
                    console.print("Review the live HackerOne policy and exclusions separately before any research.")
                    return
                except Exception as mirror_exc:
                    log(f"[yellow]Public snapshot unavailable: {type(mirror_exc).__name__}; using manual fallback.[/yellow]")

            console.print(Panel(
                "The page returned only a short HTML shell/title. This commonly happens when "
                "the policy content is rendered by JavaScript. The tool will NOT guess assets "
                "or silently treat the page title as a policy.",
                title="POLICY_EXTRACTION_INCOMPLETE",
                border_style="yellow",
            ))
            manual_path = Prompt.ask(
                "Path to a text file containing the policy copied from the browser (Enter to stop)",
                default="",
            ).strip()
            if not manual_path:
                (workspace / "policy" / "policy-text.md").write_text(
                    "# Extracted policy text\n\nSource: " + program_url + "\n\n" + policy_text + "\n",
                    encoding="utf-8",
                )
                (workspace / "policy" / "extraction-status.json").write_text(
                    json.dumps({
                        "status": "POLICY_EXTRACTION_INCOMPLETE",
                        "method": extraction_method,
                        "text_length": len(policy_text),
                        "manual_import_requested": False,
                    }, indent=2) + "\n",
                    encoding="utf-8",
                )
                console.print(f"[yellow]Stopped safely. Review or manually import policy text at: {workspace / 'policy'}[/yellow]")
                return
            try:
                policy_text = load_manual_policy_text(manual_path)
            except ValueError as exc:
                console.print(f"[red]Manual policy import failed:[/red] {exc}")
                return
            extraction_method = "operator_supplied_text_file"

        (workspace / "policy" / "policy-text.md").write_text(
            "# Policy text for manual review\n\nSource: " + program_url + "\n\n" + policy_text + "\n",
            encoding="utf-8",
        )
        (workspace / "policy" / "extraction-status.json").write_text(
            json.dumps({
                "status": "TEXT_AVAILABLE_FOR_MANUAL_REVIEW",
                "method": extraction_method,
                "text_length": len(policy_text),
                "note": "Text extraction does not establish authorization; verify the live policy manually.",
            }, indent=2) + "\n",
            encoding="utf-8",
        )
        log("Policy text snapshot saved.")
    except Exception as exc:
        log(f"[red]Could not fetch policy page: {type(exc).__name__}[/red]")
        console.print(f"Workspace retained for manual policy entry: {workspace}")
        return

    policy_analysis = write_policy_analysis(workspace, policy_text, program_url)
    candidates = extract_scope_candidates(policy_text)
    excluded_candidates = set(policy_analysis["exclusion_asset_candidates_unverified"])
    conflicting_candidates = set(policy_analysis["conflicting_asset_candidates"])
    candidates_for_review = [host for host in candidates if host not in excluded_candidates and host not in conflicting_candidates]
    write_scope_review(workspace, {
        "program_handle": program_handle,
        "canonical_policy_url": program_url,
        "source_url": program_url,
        "snapshot_publicly_verified_at": None,
        "assets": [
            {"asset_identifier": host, "asset_type": "DOMAIN", "submission_eligible": None, "bounty_eligible": None}
            for host in candidates
        ],
    })
    (workspace / "reconnaissance" / "scope-candidates.json").write_text(
        json.dumps({
            "warning": "Candidates extracted from policy text are not authorization.",
            "candidates": candidates,
            "excluded_by_policy_keyword_review_unverified": sorted(excluded_candidates),
            "conflicts_blocked_for_manual_review": sorted(conflicting_candidates),
            "candidates_offered_for_manual_review": candidates_for_review,
        }, indent=2) + "\n",
        encoding="utf-8",
    )
    console.print(Panel(
        f"Policy source: {program_url}\n"
        f"Extraction method: {extraction_method}\n"
        f"Domain-like candidates found: {len(candidates)}\n"
        f"Candidates held back by exclusion/conflict clues: {len(candidates) - len(candidates_for_review)}\n\n"
        "[yellow]Candidates are unverified. This parser currently extracts domain names only; "
        "mobile apps, IP ranges, source code, and other asset types need separate manual review.[/yellow]\n"
        "Open the live policy and verify each exact hostname yourself.",
        title="MANUAL SCOPE REVIEW",
        border_style="yellow",
    ))
    if not candidates_for_review:
        console.print(
            "[yellow]No domain candidates are available for manual review. They may be absent, "
            "or held back by exclusion/conflict clues. Other asset types may still exist. "
            "No target checks will run.[/yellow]"
        )
        return

    choices = questionary.checkbox(
        "Select ONLY hostnames you personally verified as explicitly in scope (space to toggle, enter to continue):",
        choices=[questionary.Choice(host, value=host) for host in candidates_for_review],
        use_shortcuts=True,
    ).ask()
    if not choices:
        console.print("[yellow]No assets selected. Workspace saved; no checks run.[/yellow]")
        return

    selected = normalize_confirmed_assets(choices)
    if not selected:
        console.print("[yellow]No valid concrete hostnames selected. No checks run.[/yellow]")
        return

    console.print(Panel(
        "\n".join(f"• {host}" for host in selected),
        title="SELECTED HOSTS — OPERATOR ATTESTATION REQUIRED",
        border_style="cyan",
    ))
    console.print(
        "Before marking an asset as confirmed, compare its exact identifier with the live "
        "program policy, exclusions, announcements, and asset-specific rules."
    )
    if not questionary.confirm(
        "I personally verified every selected asset against the current canonical policy and exclusions?",
        default=False,
    ).ask():
        console.print("[yellow]Confirmation declined. Assets remain unconfirmed; no checks run.[/yellow]")
        return

    _save_scope(workspace, program_url, selected)
    write_reports(workspace, selected, [])
    log(f"Saved {len(selected)} operator-attested assets for offline review.")
    console.print(Panel(
        f"Workspace: {workspace}\nAssets recorded: {len(selected)}\n"
        "Network activity against assets: none\n"
        "Confirmed vulnerabilities: 0\nSeverity: not assigned",
        title="OFFLINE REVIEW PACK READY",
        border_style="green",
    ))
    console.print(
        "The workspace contains policy analysis, scope review, vulnerability categories, "
        "and report templates. No target requests or automated vulnerability tests were sent."
    )


def _research_command(args: argparse.Namespace) -> int:
    try:
        if args.research_action == "search":
            result = research.search_nvd(args.keyword, args.limit)
            console.print(Panel(
                f"Query: {result['query']}\nReported: {result['total_results_reported']}\n"
                f"Fetched: {result['fetched']}\nSaved/updated: {result['saved_or_updated']}\n"
                f"Database: {result['database']}",
                title="NVD PUBLIC ADVISORY SEARCH",
                border_style="cyan",
            ))
            for item in result["records"]:
                console.print(f"[bold]{item['id']}[/bold]  [{item['severity']}]  CVSS: {item['cvss'] if item['cvss'] is not None else 'N/A'}")
                console.print(f"  {item['summary'][:240]}")
                console.print(f"  Categories: {', '.join(item['categories'])}")
                console.print(f"  {item['source_url']}")
            console.print(f"[dim]{result['note']}[/dim]")
        elif args.research_action == "sync-kev":
            result = research.sync_cisa_kev()
            console.print_json(json.dumps(result, ensure_ascii=False))
        elif args.research_action == "list":
            records = research.list_advisories(args.limit, args.source, args.category)
            table = Table(title="Stored public vulnerability records")
            for heading in ("ID", "Source", "Severity", "CVSS", "Published", "Categories"):
                table.add_column(heading, overflow="fold")
            for item in records:
                table.add_row(
                    item["id"], item["source"], item["severity"],
                    str(item["cvss"]) if item["cvss"] is not None else "—",
                    str(item["published"] or "—"),
                    ", ".join(item["categories"]),
                )
            console.print(table)
            console.print(f"{len(records)} record(s) shown. Database: {research.database_path()}")
        elif args.research_action == "status":
            console.print_json(json.dumps(research.research_status(), ensure_ascii=False))
        elif args.research_action == "export":
            path = research.export_advisories(args.output, args.format, args.limit)
            console.print(f"[green]Exported {args.limit} most recent record(s) to {path}[/green]")
        return 0
    except (ValueError, ResearchError) as exc:
        console.print(f"[red]Research command failed:[/red] {exc}")
        return 2
    except Exception as exc:
        console.print(f"[red]Unexpected research error:[/red] {type(exc).__name__}: {exc}")
        return 1


def _code_audit_command(args: argparse.Namespace) -> int:
    try:
        result = code_audit.analyze_source(args.path)
        output = code_audit.write_code_report(result, args.output, args.format)
        console.print(Panel(
            f"Files scanned: {result['files_scanned']}\nFindings: {result['finding_count']}\nReport: {output}",
            title="LOCAL STATIC SOURCE REVIEW",
            border_style="cyan",
        ))
        for item in result["findings"]:
            console.print(f"[bold]{item['severity']}[/bold] {item['rule_id']} {item['file']}:{item['line']} — {item['title']}")
        console.print("[dim]Heuristic findings require manual review; no source code was executed and no network requests were made.[/dim]")
        return 0
    except (ValueError, OSError) as exc:
        console.print(f"[red]Code review failed:[/red] {exc}")
        return 2


def _web_audit_command(args: argparse.Namespace) -> int:
    try:
        result = web_audit.audit_public_page(args.url, authorized=args.confirm_authorized)
        output = web_audit.write_web_report(result, args.output, args.format)
        console.print(Panel(
            f"URL: {result['url']}\nHTTP status: {result['http_status']}\n"
            f"Requests sent: {result['requests_sent']}\nFindings: {result['finding_count']}\nReport: {output}",
            title="PASSIVE WEB SECURITY REVIEW",
            border_style="cyan",
        ))
        for item in result["findings"]:
            console.print(f"[bold]{item['severity']}[/bold] {item['rule_id']} — {item['title']}")
        console.print("[dim]One read-only page request only. No crawling, payloads, login, or form submission.[/dim]")
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        console.print(f"[red]Web review failed:[/red] {exc}")
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto-find-bug",
        description="Scope-first Bug Bounty policy review and passive public advisory research.",
    )
    commands = parser.add_subparsers(dest="command")

    code_parser = commands.add_parser("code-audit", help="Run local static security checks on source code.")
    code_parser.add_argument("path", help="Source file or project directory to review.")
    code_parser.add_argument("--format", choices=("md", "json"), default="md")
    code_parser.add_argument("--output", default="code-security-review.md")

    web_parser = commands.add_parser("web-audit", help="Review one authorized HTTPS page without crawling or probing.")
    web_parser.add_argument("url", help="Exact HTTPS page URL to review.")
    web_parser.add_argument("--confirm-authorized", action="store_true", help="Confirm you own the site or have explicit permission.")
    web_parser.add_argument("--format", choices=("md", "json"), default="md")
    web_parser.add_argument("--output", default="web-security-review.md")

    research_parser = commands.add_parser("research", help="Search and organize public vulnerability advisories.")
    actions = research_parser.add_subparsers(dest="research_action", required=True)

    search_parser = actions.add_parser("search", help="Search public NVD records by keyword.")
    search_parser.add_argument("keyword", help="Keyword or technology name; no target URL is accepted.")
    search_parser.add_argument("--limit", type=int, default=25, help="Maximum results (1-100).")

    actions.add_parser("sync-kev", help="Import CISA's public Known Exploited Vulnerabilities catalog.")

    list_parser = actions.add_parser("list", help="List locally stored public advisory records.")
    list_parser.add_argument("--limit", type=int, default=25)
    list_parser.add_argument("--source", choices=("NVD", "CISA KEV"))
    list_parser.add_argument("--category", help="Filter by taxonomy category text.")

    actions.add_parser("status", help="Show local database and standard network status.")

    export_parser = actions.add_parser("export", help="Export stored records as Markdown or JSON.")
    export_parser.add_argument("--format", choices=("md", "json"), default="md")
    export_parser.add_argument("--output", default="public-vulnerability-digest.md")
    export_parser.add_argument("--limit", type=int, default=200)

    return parser


def main() -> None:
    if len(sys.argv) == 1:
        try:
            run()
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled by operator.[/yellow]")
        return
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "research":
        raise SystemExit(_research_command(args))
    if args.command == "code-audit":
        raise SystemExit(_code_audit_command(args))
    if args.command == "web-audit":
        raise SystemExit(_web_audit_command(args))
    parser.print_help()


if __name__ == "__main__":
    main()
