from __future__ import annotations

import ast
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path

EXTENSIONS = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript/JSX",
    ".ts": "TypeScript", ".tsx": "TypeScript/TSX", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".c": "C", ".h": "C/C++ header",
    ".hpp": "C++ header", ".hh": "C++ header", ".hxx": "C++ header",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
    ".cs": "C#", ".java": "Java", ".rs": "Rust", ".sol": "Solidity",
    ".pas": "Pascal", ".pp": "Pascal", ".php": "PHP",
    ".html": "HTML", ".htm": "HTML", ".css": "CSS",
    ".sql": "SQL", ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".bat": "Batch", ".cmd": "Batch", ".json": "JSON",
    ".jsonc": "JSONC", ".yaml": "YAML", ".yml": "YAML", ".xml": "XML",
}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "dist", "build", "vendor", "target"}
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


# Pattern rules are intentionally conservative review signals, not proofs.
_RULES = [
    ("JS001", "HIGH", "Dynamic JavaScript evaluation", r"\b(?:eval|new\s+Function)\s*\(", "Avoid evaluating dynamically constructed JavaScript.", ("JavaScript", "JavaScript/JSX", "TypeScript", "TypeScript/TSX")),
    ("JS002", "HIGH", "HTML injection sink", r"\.innerHTML\s*=", "Prefer textContent or safe DOM construction; sanitize rich HTML.", ("JavaScript", "JavaScript/JSX", "TypeScript", "TypeScript/TSX")),
    ("JS003", "MEDIUM", "Document.write usage", r"\bdocument\.write\s*\(", "Avoid document.write; create DOM nodes safely.", ("JavaScript", "JavaScript/JSX", "TypeScript", "TypeScript/TSX")),
    ("JS004", "HIGH", "Potential child-process execution", r"\b(?:exec|execSync|spawn)\s*\(", "Avoid shell command construction; use fixed executables and validated argument arrays.", ("JavaScript", "TypeScript")),
    ("JS005", "MEDIUM", "React raw HTML rendering", r"dangerouslySetInnerHTML\s*=", "Avoid raw HTML rendering or sanitize content with a maintained sanitizer.", ("JavaScript/JSX", "TypeScript/TSX")),
    ("PHP001", "HIGH", "PHP dynamic code execution", r"\b(?:eval|assert)\s*\(", "Remove dynamic code execution and use explicit application logic.", ("PHP",)),
    ("PHP002", "HIGH", "PHP command execution", r"\b(?:shell_exec|system|passthru|exec)\s*\(", "Avoid shell execution; use fixed commands and strict argument handling.", ("PHP",)),
    ("PHP003", "HIGH", "PHP unsafe deserialization", r"\bunserialize\s*\(", "Do not unserialize untrusted input; use JSON and validate its schema.", ("PHP",)),
    ("WEB001", "MEDIUM", "Potential inline event handler", r"\bon(?:click|error|load|mouseover|submit)\s*=", "Use addEventListener and keep executable code out of HTML attributes.", ("HTML",)),
    ("C001", "HIGH", "Potentially unsafe C string copy", r"\b(?:strcpy|strcat|sprintf|gets)\s*\(", "Use bounded operations, validate lengths, and prefer safer APIs; manually verify buffer sizes.", ("C", "C/C++ header", "C++ header", "C++")),
    ("C002", "HIGH", "Native command execution", r"\b(?:system|popen)\s*\(", "Avoid invoking a shell from native code; use safer process APIs and fixed arguments.", ("C", "C/C++ header", "C++ header", "C++")),
    ("CS001", "HIGH", "C# process execution", r"\bProcess\.Start\s*\(", "Review whether arguments can be influenced by untrusted input; avoid shell execution.", ("C#",)),
    ("CS002", "HIGH", "C# legacy binary deserialization", r"\bBinaryFormatter\b", "Avoid BinaryFormatter; use a safe data contract format.", ("C#",)),
    ("JAVA001", "HIGH", "Java native command execution", r"\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(", "Avoid shell command construction and validate fixed executable arguments.", ("Java",)),
    ("JAVA002", "HIGH", "Java object deserialization", r"\bObjectInputStream\b", "Do not deserialize untrusted Java object streams; use constrained data formats.", ("Java",)),
    ("RS001", "MEDIUM", "Rust unsafe block", r"\bunsafe\s*\{", "Review unsafe blocks for memory and aliasing invariants; document the safety argument.", ("Rust",)),
    ("RS002", "MEDIUM", "Rust raw pointer conversion", r"\b(?:transmute|from_raw_parts|from_raw)\s*(?:::<[^>]+>)?\s*\(", "Review pointer validity, alignment, lifetime, and size assumptions.", ("Rust",)),
    ("SOL001", "HIGH", "Solidity tx.origin authorization", r"\btx\.origin\b", "Use msg.sender and a carefully designed authorization model instead of tx.origin.", ("Solidity",)),
    ("SOL002", "HIGH", "Solidity delegatecall", r"\.delegatecall\s*\(", "Review delegatecall target control, storage layout, and authorization.", ("Solidity",)),
    ("SOL003", "HIGH", "Solidity low-level call", r"\.call\s*(?:\{|\()", "Check return values and reentrancy implications; prefer safer interfaces where possible.", ("Solidity",)),
    ("SOL004", "HIGH", "Solidity selfdestruct", r"\bselfdestruct\s*\(", "Review whether contract destruction is intended and properly access-controlled.", ("Solidity",)),
    ("PAS001", "MEDIUM", "Pascal pointer or untyped memory operation", r"\b(?:GetMem|ReallocMem|Move|FillChar)\s*\(", "Validate buffer sizes and pointer lifetimes around manual memory operations.", ("Pascal",)),
    ("SQL001", "HIGH", "Potential dynamic SQL construction", r"(?:EXEC(?:UTE)?\s*\(\s*['\"]?\s*\+|\b(?:CONCAT|CONCAT_WS)\s*\([^;]*(?:SELECT|UPDATE|INSERT|DELETE))", "Use parameterized statements and avoid concatenating untrusted values into SQL.", ("SQL",)),
    ("SH001", "HIGH", "Shell dynamic evaluation", r"\beval\s+['\"]?\$", "Avoid eval of expanded data; use arrays and explicit argument handling.", ("Shell",)),
    ("SH002", "HIGH", "Piped remote script execution", r"(?:curl|wget)[^\n|]*\|\s*(?:sh|bash)", "Do not pipe remote content directly into a shell; verify and inspect downloads first.", ("Shell",)),
    ("SH003", "MEDIUM", "World-writable permission command", r"\bchmod\s+(?:-R\s+)?777\b", "Grant only the minimum required permissions.", ("Shell",)),
    ("BAT001", "HIGH", "Batch dynamic command expansion", r"\bcall\s+%[^%]+%", "Review CALL with expanded variables; validate values and avoid constructing commands from untrusted input.", ("Batch",)),
    ("BAT002", "MEDIUM", "Batch delayed expansion enabled", r"(?i)\bsetlocal\s+enabledelayedexpansion\b", "Review exclamation-mark expansion where values may contain special characters.", ("Batch",)),
    ("CSS001", "HIGH", "Legacy CSS expression()", r"\bexpression\s*\(", "Remove legacy expression(); use standard CSS properties.", ("CSS",)),
    ("YAML001", "HIGH", "Potential Python object YAML tag", r"!!python/(?:object|object/new|module|name)", "Do not load untrusted YAML with constructors capable of creating Python objects.", ("YAML",)),
    ("XML001", "HIGH", "XML document type declaration", r"<!DOCTYPE", "If parsing untrusted XML, disable external entities and DTD processing.", ("XML",)),
    ("CFG001", "MEDIUM", "Debug mode enabled in configuration", r'(?i)["\']?(?:debug|debug_mode)["\']?\s*:\s*(?:true|1|["\']true["\'])', "Disable debug mode in production and keep detailed errors out of public responses.", ("JSON", "JSONC", "YAML")),
    ("CFG002", "MEDIUM", "Wildcard CORS configuration", r'(?i)["\']?(?:access-control-allow-origin|allow_origins|cors)["\']?\s*:\s*(?:\*|\[\s*["\']\*["\']\s*\])', "Restrict cross-origin access to the specific trusted origins required by the application.", ("JSON", "JSONC", "YAML")),
]


def _python_findings(source: str, relative: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [Finding("PARSE001", "INFO", "Python file could not be parsed", relative, exc.lineno or 1,
                        "Syntax error; Python AST checks were skipped.",
                        "Fix syntax errors before relying on static analysis.", "high")]
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            base = node.func.value
            if isinstance(base, ast.Name):
                name = f"{base.id}.{node.func.attr}"
        rule = None
        if name in {"eval", "exec"}:
            rule = ("PY001", "HIGH", "Dynamic code execution", "Avoid evaluating strings as code.")
        elif name in {"pickle.load", "pickle.loads", "pickle.Unpickler"}:
            rule = ("PY002", "HIGH", "Unsafe deserialization", "Do not deserialize untrusted data with pickle.")
        elif name == "yaml.load":
            safe_loader = any(k.arg == "Loader" and isinstance(k.value, ast.Attribute) and k.value.attr == "SafeLoader" for k in node.keywords)
            if not safe_loader:
                rule = ("PY004", "MEDIUM", "Potential unsafe YAML loading", "Use yaml.safe_load for untrusted YAML.")
        elif name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"}:
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                rule = ("PY003", "HIGH", "Subprocess with shell execution", "Pass an argument list with shell=False.")
        elif name in {"cursor.execute", "db.execute", "conn.execute", "connection.execute"} and node.args:
            arg = node.args[0]
            if isinstance(arg, (ast.JoinedStr, ast.BinOp)) or (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format"):
                rule = ("PY005", "HIGH", "Potential SQL query interpolation", "Use parameterized SQL queries.")
        if rule:
            findings.append(Finding(*rule[:3], relative, getattr(node, "lineno", 1), name, rule[3], "high"))
    return findings


def _validate_data_file(path: Path, source: str, relative: str) -> list[Finding]:
    findings: list[Finding] = []
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            json.loads(source)
        elif suffix == ".xml":
            ET.fromstring(source)
    except (ValueError, ET.ParseError) as exc:
        findings.append(Finding("DATA001", "INFO", "Data file parse error", relative, 1, str(exc)[:160],
                                "Validate the file with its official parser and correct the syntax.", "high"))
    # JSONC and YAML are scanned heuristically; no third-party parser is required.
    return findings


def analyze_source(root: str | Path) -> dict:
    base = Path(root).expanduser().resolve()
    if not base.exists() or not (base.is_file() or base.is_dir()):
        raise ValueError("Provide an existing source file or directory.")
    files = [base] if base.is_file() else [
        item for item in base.rglob("*")
        if item.is_file() and item.suffix.lower() in EXTENSIONS
        and not any(part in SKIP_DIRS for part in item.parts)
    ]
    findings: list[Finding] = []
    scanned = 0
    skipped_large = 0
    languages: dict[str, int] = {}
    for path in sorted(files):
        if path.suffix.lower() not in EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped_large += 1
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        language = EXTENSIONS[path.suffix.lower()]
        languages[language] = languages.get(language, 0) + 1
        relative = str(path.relative_to(base)) if base.is_dir() else path.name
        if path.suffix.lower() == ".py":
            findings.extend(_python_findings(source, relative))
        else:
            findings.extend(_validate_data_file(path, source, relative))
            for rule_id, severity, title, pattern, recommendation, supported in _RULES:
                if language not in supported:
                    continue
                compiled = re.compile(pattern)
                for match in compiled.finditer(source):
                    line = source.count("\n", 0, match.start()) + 1
                    lines = source.splitlines()
                    evidence = lines[line - 1].strip()[:180] if lines and line <= len(lines) else ""
                    findings.append(Finding(rule_id, severity, title, relative, line, evidence, recommendation))
    return {
        "scanner": "auto-find-bug-local-static-analyzer",
        "root": str(base),
        "files_scanned": scanned,
        "files_skipped_large": skipped_large,
        "language_file_counts": languages,
        "language_count": len(languages),
        "finding_count": len(findings),
        "findings": [asdict(item) for item in sorted(findings, key=lambda f: (f.file, f.line, f.rule_id))],
        "limitations": [
            "Coverage is extension-based and heuristic; language syntax and framework semantics are not fully parsed.",
            "Findings may be false positives or false negatives and require manual review.",
            "JSON and XML receive syntax validation; JSONC and YAML receive heuristic checks without full parser validation.",
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
        lines = ["# Static Source Code Review", "", f"- Root: {result['root']}",
                 f"- Files scanned: {result['files_scanned']}", f"- Languages detected: {result.get('language_count', 0)}",
                 f"- Findings: {result['finding_count']}", f"- Large files skipped: {result['files_skipped_large']}", "",
                 "## File counts by language", ""]
        lines.extend(f"- {name}: {count}" for name, count in sorted(result.get("language_file_counts", {}).items()))
        lines.append("")
        for item in result["findings"]:
            lines.extend([f"## {item['severity']} — {item['title']}", "",
                          f"- Rule: {item['rule_id']}", f"- Location: {item['file']}:{item['line']}",
                          f"- Confidence: {item['confidence']}", f"- Evidence: `{item['evidence']}`",
                          f"- Recommendation: {item['recommendation']}", ""])
        lines.extend(["## Limitations", *[f"- {item}" for item in result["limitations"]], ""])
        path.write_text("\n".join(lines), encoding="utf-8")
    return path
