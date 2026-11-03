from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt

from .checks import run_metadata_checks
from .policy import (
    fetch_policy,
    load_manual_policy_text,
    policy_extraction_incomplete,
    validate_program_url,
)
from .reports import write_reports
from .scope import extract_scope_candidates, normalize_confirmed_assets
from .workspace import create_workspace

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
        "Enforcing safe-mode defaults",
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

    workspace = create_workspace(program_url)
    log(f"Created workspace: {workspace}")

    try:
        with console.status("[cyan]Fetching the supplied public policy page..."):
            html, policy_text = fetch_policy(program_url)
        (workspace / "policy" / "policy-source.html").write_text(html, encoding="utf-8")

        extraction_method = "page_html"
        if policy_extraction_incomplete(policy_text):
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

    candidates = extract_scope_candidates(policy_text)
    (workspace / "reconnaissance" / "scope-candidates.json").write_text(
        json.dumps({
            "warning": "Candidates extracted from policy text are not authorization.",
            "candidates": candidates,
        }, indent=2) + "\n",
        encoding="utf-8",
    )
    console.print(Panel(
        f"Policy source: {program_url}\n"
        f"Extraction method: {extraction_method}\n"
        f"Domain-like candidates found: {len(candidates)}\n\n"
        "[yellow]Candidates are unverified. This parser currently extracts domain names only; "
        "mobile apps, IP ranges, source code, and other asset types need separate manual review.[/yellow]\n"
        "Open the live policy and verify each exact hostname yourself.",
        title="MANUAL SCOPE REVIEW",
        border_style="yellow",
    ))
    if not candidates:
        console.print(
            "[yellow]No domain candidates found. This does not mean the program has no scope: "
            "its assets may use non-domain types, or the supplied text may omit the scope table. "
            "No checks will run.[/yellow]"
        )
        return

    choices = questionary.checkbox(
        "Select ONLY hostnames you personally verified as explicitly in scope (space to toggle, enter to continue):",
        choices=[questionary.Choice(host, value=host) for host in candidates],
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
        "Verify the program is active, every exact host is in scope, and one HEAD request "
        "per host is permitted by the live policy."
    )
    if not questionary.confirm(
        "I checked the live policy and confirm every selected host is explicitly in scope; proceed with one HTTPS HEAD request per host?",
        default=False,
    ).ask():
        console.print("[yellow]Confirmation declined. No requests sent.[/yellow]")
        return
    if not questionary.confirm(
        "I understand this is a low-impact metadata check, not an exploit scan, and I will stop if policy prohibits it?",
        default=False,
    ).ask():
        console.print("[yellow]Safety confirmation declined. No requests sent.[/yellow]")
        return

    _save_scope(workspace, program_url, selected)
    log(f"Operator-confirmed assets saved: {len(selected)}")
    log("Starting one-request-per-host HTTPS metadata review; redirects disabled.")
    try:
        observations = run_metadata_checks(selected, workspace / "evidence", delay_seconds=1.0)
    except Exception as exc:
        log(f"[red]Checks stopped: {type(exc).__name__}[/red]")
        return

    for item in observations:
        if "status_code" in item:
            log(f"{item['asset']}: HTTP {item['status_code']} (metadata only)")
        else:
            log(f"{item['asset']}: request failed ({item.get('error', 'unknown error')})")

    write_reports(workspace, selected, observations)
    log("Evidence metadata and preliminary report saved.")
    console.print(Panel(
        f"Workspace: {workspace}\nHosts checked: {len(observations)}\n"
        "Confirmed vulnerabilities: 0\nSeverity: not assigned",
        title="RUN COMPLETE",
        border_style="green",
    ))
    console.print("Review evidence manually. Do not report metadata observations as vulnerabilities.")


def main() -> None:
    try:
        run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by operator.[/yellow]")


if __name__ == "__main__":
    main()
