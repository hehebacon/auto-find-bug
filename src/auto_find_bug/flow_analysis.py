from __future__ import annotations

"""Conservative, intraprocedural Python data-flow and route-guard review.

This module never executes project code. Results are candidate paths, not proof.
"""

import ast
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Taint:
    source_line: int
    source: str
    variables: tuple[str, ...] = ()


class FlowVisitor(ast.NodeVisitor):
    def __init__(self, source: str, relative: str):
        self.source = source
        self.relative = relative
        self.lines = source.splitlines()
        self.findings: list[dict] = []
        self.env: dict[str, Taint] = {}
        self.function_name = "<module>"

    def _expr_taint(self, node: ast.AST | None) -> Taint | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Call):
            name = self._call_name(node)
            if name in {"input", "request.args.get", "request.form.get", "request.values.get",
                        "request.json.get", "request.GET.get", "request.POST.get"}:
                return Taint(getattr(node, "lineno", 1), name)
            if name in {"int", "float", "bool"} and node.args:
                return self._expr_taint(node.args[0])
            if name in {"str", "repr"} and node.args:
                return self._expr_taint(node.args[0])
            if name.endswith(".format") and isinstance(node.func, ast.Attribute):
                return self._expr_taint(node.func.value) or next((self._expr_taint(arg) for arg in node.args if self._expr_taint(arg)), None)
            return next((self._expr_taint(child) for child in ast.iter_child_nodes(node) if self._expr_taint(child)), None)
        if isinstance(node, ast.Attribute):
            dotted = self._dotted(node)
            if dotted in {"request.args", "request.form", "request.values", "request.json",
                          "request.GET", "request.POST", "request.data"}:
                return Taint(getattr(node, "lineno", 1), dotted)
            return self._expr_taint(node.value)
        if isinstance(node, ast.Subscript):
            dotted = self._dotted(node.value)
            if dotted in {"request.args", "request.form", "request.values", "request.json",
                          "request.GET", "request.POST", "request.data"}:
                return Taint(getattr(node, "lineno", 1), dotted + "[...]")
            return self._expr_taint(node.value) or self._expr_taint(node.slice)
        if isinstance(node, ast.JoinedStr):
            return next((self._expr_taint(value) for value in node.values if self._expr_taint(value)), None)
        if isinstance(node, ast.FormattedValue):
            return self._expr_taint(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_taint(node.left) or self._expr_taint(node.right)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return next((self._expr_taint(item) for item in node.elts if self._expr_taint(item)), None)
        if isinstance(node, ast.Dict):
            return next((self._expr_taint(item) for item in [*node.keys, *node.values] if self._expr_taint(item)), None)
        if isinstance(node, ast.IfExp):
            return self._expr_taint(node.body) or self._expr_taint(node.orelse)
        return None

    @staticmethod
    def _dotted(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = FlowVisitor._dotted(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        return FlowVisitor._dotted(node.func)

    def _emit(self, rule: str, severity: str, title: str, node: ast.AST,
              taint: Taint, sink: str, recommendation: str) -> None:
        line = getattr(node, "lineno", 1)
        evidence = self.lines[line - 1].strip()[:220] if 0 < line <= len(self.lines) else sink
        self.findings.append({
            "rule_id": rule, "severity": severity, "title": title,
            "file": self.relative, "line": line,
            "evidence": evidence,
            "recommendation": recommendation,
            "confidence": "medium",
            "flow": {
                "source": taint.source, "source_line": taint.source_line,
                "source_evidence": self.lines[taint.source_line - 1].strip()[:220] if 0 < taint.source_line <= len(self.lines) else taint.source,
                "variables": list(taint.variables),
                "sink": sink, "sink_line": line,
                "function": self.function_name,
                "trace": [f"{self.relative}:{taint.source_line} source {taint.source}",
                          f"{self.relative}:{line} sink {sink}"],
            },
        })

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old_env, old_name = self.env, self.function_name
        self.env = {}
        self.function_name = node.name
        self.generic_visit(node)
        self.env, self.function_name = old_env, old_name

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        taint = self._expr_taint(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if taint:
                    self.env[target.id] = Taint(taint.source_line, taint.source, (*taint.variables, target.id))
                else:
                    self.env.pop(target.id, None)
        self.generic_visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        taint = self._expr_taint(node.value)
        if isinstance(node.target, ast.Name):
            if taint:
                self.env[node.target.id] = taint
            else:
                self.env.pop(node.target.id, None)
        if node.value:
            self.generic_visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        taint = self._expr_taint(node.target) or self._expr_taint(node.value)
        if isinstance(node.target, ast.Name) and taint:
            self.env[node.target.id] = taint
        self.generic_visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node)
        taint = self._expr_taint(node)
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and node.args:
            value_taint = self._expr_taint(node.args[0])
            if value_taint:
                self._emit("FLOW-PY-001", "HIGH", "Untrusted data reaches dynamic code execution",
                           node, value_taint, name, "Remove dynamic evaluation of request-controlled data; use explicit parsing and allowlisted operations.")
        elif name in {"os.system", "os.popen", "subprocess.run", "subprocess.Popen",
                      "subprocess.call", "subprocess.check_output"}:
            value_taint = next((self._expr_taint(arg) for arg in node.args if self._expr_taint(arg)), None)
            shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            if value_taint and (name.startswith("os.") or shell_true):
                self._emit("FLOW-PY-002", "HIGH", "Untrusted data reaches shell command execution",
                           node, value_taint, name, "Avoid shell command strings. Use fixed executables and validated argument arrays with shell=False.")
        elif name in {"cursor.execute", "db.execute", "conn.execute", "connection.execute"} and node.args:
            query_taint = self._expr_taint(node.args[0])
            if query_taint:
                self._emit("FLOW-PY-003", "HIGH", "Untrusted data may reach dynamically constructed SQL",
                           node, query_taint, name, "Use parameter placeholders and pass values separately; verify the driver’s parameter binding.")
        elif name in {"render_template_string", "Markup"} and node.args:
            value_taint = self._expr_taint(node.args[0])
            if value_taint:
                self._emit("FLOW-PY-004", "HIGH", "Untrusted data reaches a raw HTML rendering sink",
                           node, value_taint, name, "Use a fixed template with context escaping; avoid marking request-controlled content as trusted HTML.")
        self.generic_visit(node)


def _route_guard_findings(source: str, relative: str) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    results = []
    sensitive = ("admin", "delete", "update", "manage", "payment", "account", "user", "role", "permission")
    guards = ("login_required", "auth_required", "permission_required", "roles_required",
              "jwt_required", "is_authenticated", "current_user", "authorize", "require_auth",
              "Depends", "permission_classes", "IsAuthenticated")
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = [ast.unparse(item) if hasattr(ast, "unparse") else "" for item in node.decorator_list]
        route = any(any(marker in dec.lower() for marker in ("route(", "get(", "post(", "put(", "patch(", "delete(", "api_view", "router.")) for dec in decorators)
        if not route:
            continue
        identity = (node.name + " " + " ".join(decorators)).lower()
        if not any(word in identity for word in sensitive):
            continue
        body_text = (ast.get_source_segment(source, node) or "") + " " + " ".join(decorators)
        if any(marker.lower() in body_text.lower() for marker in guards):
            continue
        line = node.lineno
        evidence = lines[line - 1].strip()[:220] if 0 < line <= len(lines) else node.name
        results.append({
            "rule_id": "ACCESS-PY-001", "severity": "LOW",
            "title": "Sensitive-looking route has no recognizable local authorization guard",
            "file": relative, "line": line, "evidence": evidence,
            "recommendation": "Trace the complete authorization path, including middleware, router dependencies, decorators, and service-layer checks. Add explicit object- and role-level authorization where required.",
            "confidence": "low",
            "flow": {"source": "route declaration", "source_line": line,
                     "sink": "sensitive route handler", "sink_line": line,
                     "function": node.name, "trace": [f"{relative}:{line} route {node.name}", "No recognized in-function guard token found"]},
        })
    return results


def analyze_python_flows(root: str | Path) -> dict:
    base = Path(root).expanduser().resolve()
    if not base.exists():
        raise ValueError("Provide an existing source file or directory.")
    if base.is_file() and base.suffix.lower() != ".py":
        return {"engine": "python-intraprocedural-dataflow-v1", "files_analyzed": 0, "finding_count": 0, "findings": [], "limitations": ["Deep data-flow analysis currently supports Python source files; other languages retain their existing heuristic static checks."]}
    files = [base] if base.is_file() else [
        p for p in base.rglob("*.py")
        if p.is_file() and not any(part in {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"} for part in p.parts)
    ]
    all_findings = []
    scanned = 0
    for path in sorted(files):
        try:
            if path.stat().st_size > 1_000_000:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(base)) if base.is_dir() else path.name
        try:
            ast.parse(source)
        except SyntaxError:
            continue
        scanned += 1
        visitor = FlowVisitor(source, relative)
        visitor.visit(ast.parse(source))
        all_findings.extend(visitor.findings)
        all_findings.extend(_route_guard_findings(source, relative))
    return {
        "engine": "python-intraprocedural-dataflow-v1",
        "files_analyzed": scanned,
        "finding_count": len(all_findings),
        "findings": all_findings,
        "limitations": [
            "Data-flow tracking is intraprocedural and conservative; it does not resolve dynamic dispatch, aliases, inter-file calls, framework middleware, or full control-flow/path conditions.",
            "Route guard checks recognize common guard tokens only and may miss external middleware or report false positives.",
            "No code is executed and no exploitability or runtime reachability is established.",
        ],
    }
