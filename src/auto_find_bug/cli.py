from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.table import Table

from .policy import fetch_policy, validate_program_url
from .workspace import create_workspace

console = Console()


def log(message: str) -> None:
    now = datetime.now().astimezone().strftime("%H:%M:%S.%f")[:-3]
    console.print(f"[dim]\[{now}][/dim] {message}")


def boot() -> None:
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]AUTO FIND BUG[/bold cyan]\n[dim]Scope-first Bug Bounty research assistant[/dim]",
        border_style="cyan",
    ))
    tasks = [
        "Initializing terminal interface",
        "Loading policy review module",
        "Loading scope workspace manager",
        "Loading evidence and report modules",
        "Checking safe-mode defaults",
    ]
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Booting", total=len(tasks))
        for item in tasks:
            progress.update(task, description=item)
            time.sleep(0.12)
            progress.advance(task)
    log("Core ready. Active testing is disabled until scope is reviewed.")


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
        (workspace / "policy" / "policy-text.md").write_text(
            "# Extracted policy text\n\nSource: " + program_url + "\n\n" + policy_text + "\n",
            encoding="utf-8",
        )
        log("Policy snapshot saved.")
    except Exception as exc:
        log(f"[red]Could not fetch policy page: {exc}[/red]")
        console.print(f"Workspace retained for manual policy entry: {workspace}")
        return

    console.clear()
    console.print(Panel(
        f"[bold]Policy captured[/bold]\n{program_url}\n\n"
        "[yellow]The page text is not proof of authorization.[/yellow] "
        "Review the live program page and record exact in-scope and excluded assets.",
        title="SCOPE REVIEW REQUIRED",
        border_style="yellow",
    ))
    console.print(f"Policy text: {workspace / 'policy' / 'policy-text.md'}")
    console.print(f"Scope review: {workspace / 'policy' / 'scope-review.md'}")
    console.print()
    choice = questionary.select(
        "What would you like to do next?",
        choices=[
            "Open scope review checklist (manual confirmation)",
            "Finish and review saved workspace",
        ],
        use_shortcuts=True,
    ).ask()

    if choice == "Open scope review checklist (manual confirmation)":
        console.print(Panel(
            "1. Open the live policy URL.\n"
            "2. Copy only explicitly in-scope assets into policy/scope.json.\n"
            "3. Record exclusions, wildcard semantics, rate limits and prohibited tests.\n"
            "4. Confirm the program is active and the policy has not changed.\n"
            "5. Do not select assets discovered outside the written scope.",
            title="Operator checklist",
            border_style="cyan",
        ))
        console.print(f"Edit: {workspace / 'policy' / 'scope.json'}")

    console.print()
    console.print(f"[green]Workspace saved:[/green] {workspace}")
    console.print("[dim]No vulnerability scan or active probing was started.[/dim]")


def main() -> None:
    try:
        run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by operator.[/yellow]")


if __name__ == "__main__":
    main()
