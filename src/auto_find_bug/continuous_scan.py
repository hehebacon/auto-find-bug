from __future__ import annotations

"""Continuous, read-only watcher for local source trees.

It reruns the five independent analysis brains when source files change and on a
slower refresh interval. It never probes scope hosts or executes project code.
"""

import hashlib
import json
import os
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
        return digest.hexdigest()

    for path in candidates:
        try:
            stat = path.stat()
        except OSError:
            continue
        digest.update(path.name.encode("utf-8", "replace"))
        digest.update(f":{stat.st_size}:{stat.st_mtime_ns}".encode())
    return digest.hexdigest()


def _append_history(workspace: Path, result: dict) -> None:
    history = workspace / "bugs" / "scan-history.jsonl"
    history.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": result["status"],
        "finding_count": result["finding_count"],
        "brain_statuses": result["brain_statuses"],
        "files_scanned": result["files_scanned"],
        "findings_path": result["findings_path"],
        "report_path": result["report_path"],
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

    last_fingerprint = None
    last_scan = 0.0
    while True:
        fingerprint = source_fingerprint(source)
        now = time.monotonic()
        changed = fingerprint != last_fingerprint
        refresh_due = now - last_scan >= refresh_seconds
        if changed or refresh_due:
            result = run_five_brain_scan(source, workspace)
            _append_history(workspace, result)
            last_fingerprint = fingerprint
            last_scan = time.monotonic()
            if on_scan:
                on_scan(result)
        time.sleep(poll_seconds)
