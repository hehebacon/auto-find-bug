from __future__ import annotations

import ast
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

SUPPORTED = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".html", ".htm"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "dist", "build", "vendor"}
MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    evidence: str
    recommendation: str
    confidence: str = "medium"


_RULES = [
    ("PY001", "HIGH", "Dynamic code execution", re.compile(r"\b(?:eval|exec)\s*\("), "Avoid evaluating strings as code; use explicit parsing or allow-listed operations.", ("py",)),
    ("PY002", "HIGH", "Unsafe deserialization", re.compile(r"\bpickle\.(?:loads?|Unpickler)\b"), "Do not deserialize untrusted data with pickle; use a data-only format.", ("py",)),
    ("PY003", "HIGH", "Subprocess with shell execution", re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^\n]*\bshell\s*=\s*True"), "Pass an argument list with shell=False and validate each argument.", ("py",)),
    ("PY004", "MEDIUM", "Potential unsafe YAML loading", re.compile(r"\byaml\.load\s*\("), "Use yaml.safe_load for untrusted YAML and validate the resulting schema.", ("py",)),
    ("PY005", "HIGH", "Potential SQL query interpolation", re.compile(r"(?:execute|executemany)\s*\(\s*(?:f[\"']|[\"'][^\n]*%s|[\"'][^\n]*\.format\s*\()"), "Use parameterized SQL queries; never build query text from untrusted values.", ("py",)),
    ("JS001", "HIGH", "Dynamic JavaScript evaluation", re.compile(r"\b(?:eval|new\s+Function)\s*\("), "Avoid evaluating dynamically constructed JavaScript.", ("js",)),
    ("JS002", "HIGH", "HTML injection sink", re.compile(r"\.innerHTML\s*="), "Prefer textContent or safe DOM construction; sanitize trusted rich HTML with a maintained sanitizer.", ("js",)),
    ("JS003", "MEDIUM", "Document.write usage", re.compile(r"\bdocument\.write\s*\("), "Avoid document.write; create DOM nodes safely instead.", ("js",)),
    ("JS004", "HIGH", "Potential unsafe child-process execution", re.compile(r"\b(?:exec|execSync|spawn)\s*\("), "Avoid shell command construction; use fixed executables and argument arrays with validation.", ("js",)),
    ("JS005", "MEDIUM", "React raw HTML rendering", re.compile(r"dangerouslySetInnerHTML\s*="), "Avoid raw HTML rendering or sanitize the content before rendering.", ("js",)),
    ("PHP001", "HIGH", "PHP dynamic code execution", re.compile(r"\b(?:eval|assert)\s*\("), "Remove dynamic code execution and use explicit application logic.", ("php",)),
    ("PHP002", "HIGH", "PHP command execution", re.compile(r"\b(?:shell_exec|system|passthru|exec)\s*\("), "Avoid shell execution; if essential, use fixed commands and strict argument handling.", ("php",)),
    ("PHP003", "HIGH", "PHP unsafe deserialization", re.compile(r"\bunserialize\s*\("), "Do not unserialize untrusted input; use JSON and validate its schema.", ("php",)),
    ("WEB001", "MEDIUM", "Potential inline event handler", re.compile(r"\bon(?:click|error|load|mouseover|submit)\s*=\s*[\"']"), "Use addEventListener and keep executable code out of HTML attributes.", ("html",)),
]

def _language(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return "py"
    if suffix == ".php":
        return "php"
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return "js"
    if suffix in {".html", ".htm"}:
        return "html"
    return ""


def _python_findings(source: str, relative: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [Finding("PARSE001", "INFO", "Python file could not be parsed", relative, exc.lineno or 1,
                        "Syntax error; static checks for this file were skipped.",
                        "Fix syntax errors before relying on static analysis.", "high")]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                base = node.func.value
                if isinstance(base, ast.Name):
                    name = f"{base.id}.{node.func.attr}"
            rule = None
            if name in {"eval", "exec"}:
                rule = ("PY001", "HIGH", "Dynamic code execution", "Avoid evaluating strings as code; use explicit parsing or allow-listed operations.")
            elif name in {"pickle.load", "pickle.loads", "pickle.Unpickler"}:
                rule = ("PY002", "HIGH", "Unsafe deserialization", "Do not deserialize untrusted data with pickle; use a data-only format.")
            elif name in {"yaml.load"}:
                safe_loader = any(k.arg == "Loader" and isinstance(k.value, ast.Attribute) and k.value.attr == "SafeLoader" for k in node.keywords)
                if not safe_loader:
                    rule = ("PY004", "MEDIUM", "Potential unsafe YAML loading", "Use yaml.safe_load for untrusted YAML and validate the resulting schema.")
            elif name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"}:
                if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                    rule = ("PY003", "HIGH", "Subprocess with shell execution", "Pass an argument list with shell=False and validate each argument.")
            elif name in {"cursor.execute", "db.execute", "conn.execute", "connection.execute"} and node.args:
                arg = node.args[0]
                if isinstance(arg, (ast.JoinedStr, ast.BinOp)) or (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format"):
                    rule = ("PY005", "HIGH", "Potential SQL query interpolation", "Use parameterized SQL queries; never build query text from untrusted values.")
            if rule:
                findings.append(Finding(*rule[:3], relative, getattr(node, "lineno", 1), name, rule[3], "high"))
    return findings


def analyze_source(root: str | Path) -> dict:
    base = Path(root).expanduser().resolve()
    if not base.exists() or not (base.is_file() or base.is_dir()):
        raise ValueError("Provide an existing source file or directory.")
    files = [base] if base.is_file() else [
        item for item in base.rglob("*")
        if item.is_file() and item.suffix.lower() in SUPPORTED
        and not any(part in SKIP_DIRS for part in item.parts)
    ]
    findings: list[Finding] = []
    scanned = 0
    skipped_large = 0
    for path in sorted(files):
        if path.suffix.lower() not in SUPPORTED:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped_large += 1
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        relative = str(path.relative_to(base)) if base.is_dir() else path.name
        if path.suffix.lower() == ".py":
            findings.extend(_python_findings(source, relative))
            continue
        language = _language(path)
        for rule_id, severity, title, pattern, recommendation, languages in _RULES:
            if language not in languages:
                continue
            for match in pattern.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                evidence = source.splitlines()[line - 1].strip()[:180] if source.splitlines() else ""
                findings.append(Finding(rule_id, severity, title, relative, line, evidence, recommendation))
    return {
        "scanner": "auto-find-bug-local-static-analyzer",
        "root": str(base),
        "files_scanned": scanned,
        "files_skipped_large": skipped_large,
        "finding_count": len(findings),
        "findings": [asdict(item) for item in sorted(findings, key=lambda f: (f.file, f.line, f.rule_id))],
        "limitations": [
            "Heuristic static analysis only; findings may be false positives or false negatives.",
            "No code is executed, no dependencies are installed, and no network requests are made.",
            "A finding is a review lead, not proof of exploitability.",
        ],
    }


def write_code_report(result: dict, output: str | Path, fmt: str = "md") -> Path:
    if fmt not in {"md", "json"}:
        raise ValueError("Format must be md or json.")
    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        lines = ["# Static Source Code Review", "", f"- Root: {result['root']}", f"- Files scanned: {result['files_scanned']}", f"- Findings: {result['finding_count']}", f"- Large files skipped: {result['files_skipped_large']}", ""]
        for item in result["findings"]:
            lines.extend([f"## {item['severity']} — {item['title']}", "", f"- Rule: {item['rule_id']}", f"- Location: {item['file']}:{item['line']}", f"- Confidence: {item['confidence']}", f"- Evidence: `{item['evidence']}`", f"- Recommendation: {item['recommendation']}", ""])
        lines.extend(["## Limitations", *[f"- {item}" for item in result["limitations"]], ""])
        path.write_text("\n".join(lines), encoding="utf-8")
    return path
