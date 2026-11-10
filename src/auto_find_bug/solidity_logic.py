from __future__ import annotations

"""Conservative Solidity business-logic review signals.

This is a lightweight lexical pass, not a Solidity parser or proof engine. Every
result is a review lead and must be checked against the full contract context.
"""

import re
from pathlib import Path
from typing import Any

MAX_SOLIDITY_BYTES = 1_000_000

_FUNCTION = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?P<signature>[^;{}]*)\{",
    re.MULTILINE,
)
_PRIVILEGED_NAME = re.compile(
    r"^(?:set|update|change|transfer|renounce|upgrade|initialize|pause|unpause|"
    r"mint|burn|withdraw|rescue|sweep|grant|revoke|setRole|setOracle|setFee|setPrice)",
    re.IGNORECASE,
)
_AUTH = re.compile(
    r"\bonly[A-Z_a-z0-9]*\b|_checkRole\s*\(|hasRole\s*\(|"
    r"\brequire\s*\([^;]*(?:msg\.sender|_msgSender\s*\(\s*\))|"
    r"\bmsg\.sender\s*==|\b_msgSender\s*\(\s*\)\s*==",
    re.DOTALL,
)
_EXTERNAL_CALL = re.compile(r"\.\s*(?:call|delegatecall|staticcall)\s*(?:\{|\()", re.MULTILINE)
_STATE_WRITE = re.compile(
    r"(?:\b(?:balances|owners|roles|allowances|totalSupply|paused|owner|"
    r"nonce|nonces|shares|debt|credits|accounting|fee|price)\s*"
    r"(?:\[[^\]]+\])?\s*(?:=|\+=|-=|\+\+|--))|"
    r"\b(?:delete|push|pop)\s*\(",
    re.MULTILINE,
)


def _mask_comments_and_strings(source: str) -> str:
    """Replace comments/string contents with spaces while preserving offsets."""
    pattern = re.compile(
        r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        re.MULTILINE,
    )
    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))
    return pattern.sub(blank, source)


def _line(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def analyze_solidity_logic(path: str | Path) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise ValueError(f"Source path does not exist: {target}")
    files = [target] if target.is_file() else sorted(
        item for item in target.rglob("*.sol")
        if item.is_file() and not item.is_symlink()
        and not any(part in {".git", ".venv", "node_modules", "vendor", "lib", "out", "cache"} for part in item.parts)
    )
    findings: list[dict[str, Any]] = []
    scanned = 0
    skipped_large = 0

    for file_path in files:
        if file_path.suffix.lower() != ".sol" or file_path.is_symlink():
            continue
        try:
            if file_path.stat().st_size > MAX_SOLIDITY_BYTES:
                skipped_large += 1
                continue
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        masked = _mask_comments_and_strings(source)
        relative = file_path.name if target.is_file() else file_path.relative_to(target).as_posix()

        for match in _FUNCTION.finditer(masked):
            name = match.group("name")
            signature = match.group("signature") or ""
            open_brace = match.end() - 1
            depth = 1
            cursor = open_brace + 1
            while cursor < len(masked) and depth:
                if masked[cursor] == "{":
                    depth += 1
                elif masked[cursor] == "}":
                    depth -= 1
                cursor += 1
            if depth:
                continue
            body_start, body_end = open_brace + 1, cursor - 1
            body = masked[body_start:body_end]
            original_body = source[body_start:body_end]

            if _PRIVILEGED_NAME.match(name) and not _AUTH.search(signature + "\n" + body):
                findings.append({
                    "rule_id": "SOL-LOGIC-001", "severity": "MEDIUM",
                    "title": "Privileged-looking state-changing function lacks a recognized local authorization check",
                    "file": relative, "line": _line(source, match.start()),
                    "function": name, "evidence": source[match.start():match.end()].strip()[:180],
                    "recommendation": "Verify the complete call path, inherited modifiers, role checks, initialization state, and intended caller policy. Add explicit authorization only where required by the protocol design.",
                    "confidence": "low", "category": "access_control_review",
                    "validation_status": "not_validated",
                })

            calls = list(_EXTERNAL_CALL.finditer(body))
            writes = list(_STATE_WRITE.finditer(body))
            if calls and writes and not re.search(r"\bnonReentrant\b", signature):
                first_call = calls[0].start()
                later_write = next((item for item in writes if item.start() > first_call), None)
                if later_write is not None:
                    findings.append({
                        "rule_id": "SOL-LOGIC-002", "severity": "MEDIUM",
                        "title": "External call appears before a later state update",
                        "file": relative, "line": _line(source, body_start + first_call),
                        "function": name,
                        "evidence": original_body[max(0, first_call - 80):first_call + 100].strip()[:180],
                        "recommendation": "Review checks-effects-interactions ordering, reentrancy guards, callback behavior, and whether the later write is part of the same invariant. This ordering alone does not prove reentrancy.",
                        "confidence": "low", "category": "reentrancy_and_state_ordering",
                        "validation_status": "not_validated",
                    })

            for call in _EXTERNAL_CALL.finditer(body):
                call_line_start = body.rfind("\n", 0, call.start()) + 1
                call_line_end = body.find("\n", call.end())
                if call_line_end < 0:
                    call_line_end = len(body)
                call_line = body[call_line_start:call_line_end]
                assigned = re.search(r"(?:\bbool\b\s+\w+\s*=|\(\s*bool\b|\breturn\s+)", call_line)
                checked = re.search(r"\brequire\s*\(|\bif\s*\(", call_line)
                if not assigned and not checked:
                    findings.append({
                        "rule_id": "SOL-LOGIC-003", "severity": "MEDIUM",
                        "title": "Low-level call result may be ignored",
                        "file": relative, "line": _line(source, body_start + call.start()),
                        "function": name, "evidence": call_line.strip()[:180],
                        "recommendation": "Capture and check the success flag or explicitly document why failure is acceptable; review downstream accounting and retry behavior.",
                        "confidence": "low", "category": "external_call_result",
                        "validation_status": "not_validated",
                    })

    findings.sort(key=lambda item: (item["file"], item["line"], item["rule_id"]))
    return {
        "engine": "solidity-business-logic-review-heuristics",
        "files_scanned": scanned,
        "files_skipped_large": skipped_large,
        "finding_count": len(findings),
        "findings": findings,
        "limitations": [
            "This lexical review is not a Solidity compiler, AST, symbolic executor, or formal verifier.",
            "Inherited modifiers, library behavior, proxy storage, cross-contract invariants, and protocol economics are not fully modeled.",
            "A missing local authorization marker or external-call ordering is only a low-confidence review lead; inspect inherited and cross-function controls.",
            "No contracts are compiled, deployed, forked, called, or exploited by this engine.",
        ],
    }
