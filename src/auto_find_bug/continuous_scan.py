from __future__ import annotations

"""Continuous, read-only watcher for local source trees.

It reruns the five independent analysis brains when source files change and on a
slower refresh interval. It never probes scope hosts or executes project code.
"""

import hashlib
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .multi_brain import run_five_brain_scan


IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".tox", "dist", "build", "target",
}


def source_fingerprint(source_path: str | Path) -> str:
    source = Path(source_path).expanduser().resolve()
    digest = hashlib.sha256()
    if source.is_file():
        candidates = [source]
    else:
        candidates = []
        for root, dirs, files in os.walk(source, followlinks=False):
            dirs[:] = sorted(
                name for name in dirs
                if name not in IGNORED_DIRS and not (Path(root) / name).is_symlink()
            )
            for name in sorted(files):
                path = Path(root) / name
                if path.is_symlink():
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                digest.update(str(path.relative_to(source)).encode("utf-8", "replace"))
                digest.update(f":{stat.st_size}:{stat.st_mtime_ns}".encode())
                # Hash bytes too: size/mtime alone can miss restored or generated edits.
                try:
                    with path.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(chunk)
                except OSError:
                    digest.update(b"<unreadable>")
        return digest.hexdigest()

    for path in candidates:
        try:
            stat = path.stat()
        except OSError:
            continue
        digest.update(path.name.encode("utf-8", "replace"))
        digest.update(f":{stat.st_size}:{stat.st_mtime_ns}".encode())
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            digest.update(b"<unreadable>")
    return digest.hexdigest()


def source_has_files(source_path: str | Path) -> bool:
    """Return true only when the configured source location contains real files."""
    source = Path(source_path).expanduser().resolve()
    if source.is_file():
        return source.stat().st_size > 0
    if not source.is_dir():
        return False
    for root, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = [
            name for name in dirs
            if name not in IGNORED_DIRS and not (Path(root) / name).is_symlink()
        ]
        for name in files:
            candidate = Path(root) / name
            if candidate.is_symlink():
                continue
            try:
                if candidate.is_file() and candidate.stat().st_size > 0:
                    return True
            except OSError:
                continue
    return False


def _append_history(workspace: Path, result: dict) -> None:
    bugs_dir = workspace / "bugs"
    bugs_dir.mkdir(parents=True, exist_ok=True)
    history = bugs_dir / "scan-history.jsonl"
    timestamp = datetime.now(timezone.utc)
    cycle_id = timestamp.strftime("%Y%m%dT%H%M%S%fZ")
    snapshot_dir = bugs_dir / "history" / cycle_id
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(result["findings_path"], snapshot_dir / "findings.json")
    shutil.copy2(result["report_path"], snapshot_dir / "report.md")
    record = {
        "timestamp": timestamp.isoformat(),
        "cycle_id": cycle_id,
        "status": result["status"],
        "finding_count": result["finding_count"],
        "brain_statuses": result["brain_statuses"],
        "files_scanned": result["files_scanned"],
        "findings_path": result["findings_path"],
        "report_path": result["report_path"],
        "snapshot_directory": str(snapshot_dir),
    }
    with history.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def watch_five_brain_scan(
    source_path: str | Path,
    workspace_path: str | Path,
    *,
    poll_seconds: int = 5,
    refresh_seconds: int = 900,
    on_scan: Callable[[dict], None] | None = None,
) -> None:
    """Run once immediately, then watch for edits and periodic advisory refreshes.

    Stop cleanly with Ctrl+C. Intervals are injectable for deterministic tests.
    """
    source = Path(source_path).expanduser().resolve()
    workspace = Path(workspace_path).expanduser().resolve()
    if not source.exists() or not (source.is_file() or source.is_dir()):
        raise ValueError(f"Source path does not exist: {source}")
    if not workspace.is_dir():
        raise ValueError(f"Scope workspace directory does not exist: {workspace}")
    if poll_seconds < 1 or refresh_seconds < poll_seconds:
        raise ValueError("Watch intervals must be positive and refresh_seconds >= poll_seconds.")

    state_path = workspace / "bugs" / "scan-state.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    last_fingerprint = None
    last_scan = 0.0
    state = {
        "status": "watching",
        "source": str(source),
        "workspace": str(workspace),
        "poll_seconds": poll_seconds,
        "refresh_seconds": refresh_seconds,
        "target_network_activity": "none",
    }
    # Make the active watcher state visible before the first potentially long scan.
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    try:
        while True:
            fingerprint = source_fingerprint(source)
            now = time.monotonic()
            changed = fingerprint != last_fingerprint
            refresh_due = now - last_scan >= refresh_seconds
            if not source_has_files(source):
                state["status"] = "waiting_for_source"
                state["source_files_present"] = False
                state["note"] = "No non-empty local source files found; no clean result is reported."
                state["last_checked_at"] = datetime.now(timezone.utc).isoformat()
                temporary = state_path.with_suffix(".json.tmp")
                temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
                temporary.replace(state_path)
                last_fingerprint = fingerprint
                time.sleep(poll_seconds)
                continue
            if changed or refresh_due:
                state["status"] = "scanning"
                state["source_files_present"] = True
                state.pop("note", None)
                state["scan_started_at"] = datetime.now(timezone.utc).isoformat()
                temporary = state_path.with_suffix(".json.tmp")
                temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
                temporary.replace(state_path)
                try:
                    result = run_five_brain_scan(
                        source, workspace, public_intel_cache_ttl_seconds=refresh_seconds
                    )
                    _append_history(workspace, result)
                    last_fingerprint = fingerprint
                    last_scan = time.monotonic()
                    state["status"] = "watching"
                    state["last_scan_at"] = datetime.now(timezone.utc).isoformat()
                    state["last_scan_status"] = result["status"]
                    state["last_finding_count"] = result["finding_count"]
                    state["last_brain_statuses"] = result["brain_statuses"]
                    state["history_path"] = str(workspace / "bugs" / "scan-history.jsonl")
                    if on_scan:
                        on_scan(result)
                except Exception as exc:
                    # A failed cycle must not silently terminate the watcher.
                    # Back off until the next poll interval rather than hot-looping.
                    last_scan = time.monotonic()
                    last_fingerprint = fingerprint
                    state["status"] = "cycle_error"
                    state["last_error"] = f"{type(exc).__name__}: {exc}"
                    state["last_error_at"] = datetime.now(timezone.utc).isoformat()
                temporary = state_path.with_suffix(".json.tmp")
                temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
                temporary.replace(state_path)
            time.sleep(poll_seconds)
    finally:
        state["status"] = "stopped"
        state["stopped_at"] = datetime.now(timezone.utc).isoformat()
        temporary = state_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        temporary.replace(state_path)
