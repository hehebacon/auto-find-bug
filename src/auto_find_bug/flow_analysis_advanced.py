from __future__ import annotations

"""Bounded path-sensitive Python taint analysis.

The interpreter evaluates syntax only; it never imports or executes project code.
Unknown branch conditions are joined conservatively. Helper calls are resolved only
when a unique same-project Python function definition is available.
"""

import ast
import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .flow_analysis import _route_guard_findings

UNKNOWN = object()
MAX_FILES = 4000
MAX_FILE_BYTES = 1_000_000
MAX_CALL_DEPTH = 8
MAX_STEPS = 50_000


@dataclass
class Value:
    tainted: bool = False
    origins: tuple[tuple[str, int, str], ...] = ()
    trace: tuple[str, ...] = ()
    constant: Any = UNKNOWN
    items: list["Value"] | None = None
    mapping: dict[str, "Value"] | None = None

    def clone(self) -> "Value":
        return copy.deepcopy(self)


@dataclass
class State:
    env: dict[str, Value] = field(default_factory=dict)
    returned: Value | None = None
    terminated: bool = False


def _merge_value(left: Value, right: Value) -> Value:
    origins = tuple(dict.fromkeys((*left.origins, *right.origins)))
    trace = tuple(dict.fromkeys((*left.trace, *right.trace)))
    constant = left.constant if left.constant is not UNKNOWN and left.constant == right.constant else UNKNOWN
    items = None
    if left.items is not None and right.items is not None and len(left.items) == len(right.items):
        items = [_merge_value(a, b) for a, b in zip(left.items, right.items)]
    mapping = None
    if left.mapping is not None and right.mapping is not None:
        keys = set(left.mapping) | set(right.mapping)
        mapping = {
            key: _merge_value(left.mapping.get(key, Value()), right.mapping.get(key, Value()))
            for key in keys
        }
    return Value(bool(left.tainted or right.tainted), origins, trace, constant, items, mapping)


def _merge_states(states: list[State]) -> State:
    if not states:
        return State()
    keys = set().union(*(state.env for state in states))
    env: dict[str, Value] = {}
    for key in keys:
        values = [state.env.get(key, Value()) for state in states]
        merged = values[0].clone()
        for value in values[1:]:
            merged = _merge_value(merged, value)
        env[key] = merged
    return State(env=env, terminated=all(item.terminated for item in states))


def _literal(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return UNKNOWN


class Analyzer:
    def __init__(self, root: Path, files: list[Path]):
        self.root = root
        self.files = files
        self.functions: dict[str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, str]]] = {}
        self.sources: dict[str, list[str]] = {}
        self.findings: dict[tuple[str, int, str, int], dict[str, Any]] = {}
        self.route_findings: list[dict[str, Any]] = []
        self.steps = 0
        self.call_stack: list[str] = []
        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except (OSError, SyntaxError):
                continue
            rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
            self.sources[rel] = source.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions.setdefault(node.name, []).append((rel, node, source))

    @staticmethod
    def dotted(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = Analyzer.dotted(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def _source(self, name: str, line: int, rel: str) -> Value:
        return Value(True, ((rel, line, name),), (f"{rel}:{line} source {name}",))

    def _record(self, rule: str, node: ast.AST, rel: str, sink: str, value: Value) -> None:
        line = getattr(node, "lineno", 1)
        if not value.tainted or not value.origins:
            return
        for source_file, source_line, source_name in value.origins:
            key = (rule, rel, line, source_file, source_line)
            source_lines = self.sources.get(source_file, [])
            sink_lines = self.sources.get(rel, [])
            evidence = sink_lines[line - 1].strip()[:220] if 0 < line <= len(sink_lines) else sink
            source_evidence = source_lines[source_line - 1].strip()[:220] if 0 < source_line <= len(source_lines) else source_name
            trace = list(value.trace)
            trace.append(f"{rel}:{line} sink {sink}")
            self.findings[key] = {
                "rule_id": rule,
                "severity": "HIGH",
                "title": {
                    "FLOW-PY-001": "Untrusted data reaches dynamic code execution",
                    "FLOW-PY-002": "Untrusted data reaches shell command execution",
                    "FLOW-PY-003": "Untrusted data reaches dynamically constructed SQL",
                    "FLOW-PY-004": "Untrusted data reaches raw HTML rendering",
                }[rule],
                "file": rel,
                "line": line,
                "evidence": evidence,
                "recommendation": "Review input control, all propagation steps, context-specific validation/encoding, and the sink API before confirming impact.",
                "confidence": "medium",
                "flow": {
                    "source": source_name,
                    "source_line": source_line,
                    "source_file": source_file,
                    "source_evidence": source_evidence,
                    "sink": sink,
                    "sink_line": line,
                    "function": self.call_stack[-1] if self.call_stack else "<module>",
                    "variables": [],
                    "trace": trace[-24:],
                },
            }

    def _truth(self, node: ast.AST, state: State) -> bool | None:
        value = self.eval_expr(node, state, "<condition>", report=False)
        if value.constant is not UNKNOWN:
            try:
                return bool(value.constant)
            except Exception:
                return None
        return None

    def _assign(self, target: ast.AST, value: Value, state: State, rel: str) -> None:
        if isinstance(target, ast.Name):
            state.env[target.id] = value.clone()
        elif isinstance(target, (ast.Tuple, ast.List)):
            if value.items is not None and len(value.items) == len(target.elts):
                for child, item in zip(target.elts, value.items):
                    self._assign(child, item, state, rel)
            else:
                for child in target.elts:
                    self._assign(child, Value(value.tainted, value.origins, value.trace), state, rel)
        elif isinstance(target, ast.Subscript):
            container = self.eval_expr(target.value, state, rel, report=False)
            key_value = _literal(target.slice)
            key = str(key_value) if key_value is not UNKNOWN else None
            if isinstance(target.value, ast.Name):
                current = state.env.get(target.value.id, container).clone()
                if current.items is not None and isinstance(key_value, int) and -len(current.items) <= key_value < len(current.items):
                    current.items[key_value] = value.clone()
                elif current.mapping is not None and key is not None:
                    current.mapping[key] = value.clone()
                state.env[target.value.id] = current

    def eval_expr(self, node: ast.AST | None, state: State, rel: str, report: bool = True, depth: int = 0) -> Value:
        if node is None:
            return Value()
        if isinstance(node, ast.Constant):
            return Value(constant=node.value)
        if isinstance(node, ast.Name):
            return state.env.get(node.id, Value()).clone()
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = [self.eval_expr(item, state, rel, report, depth) for item in node.elts]
            return Value(any(v.tainted for v in values),
                         tuple(dict.fromkeys(o for v in values for o in v.origins)),
                         tuple(dict.fromkeys(t for v in values for t in v.trace)),
                         items=values)
        if isinstance(node, ast.Dict):
            mapping: dict[str, Value] = {}
            for key_node, val_node in zip(node.keys, node.values):
                key = _literal(key_node) if key_node is not None else UNKNOWN
                val = self.eval_expr(val_node, state, rel, report, depth)
                if key is not UNKNOWN:
                    mapping[str(key)] = val
            vals = list(mapping.values())
            return Value(any(v.tainted for v in vals),
                         tuple(dict.fromkeys(o for v in vals for o in v.origins)),
                         tuple(dict.fromkeys(t for v in vals for t in v.trace)),
                         mapping=mapping)
        if isinstance(node, ast.Subscript):
            dotted_base = self.dotted(node.value)
            if dotted_base in {"request.args", "request.form", "request.values", "request.json",
                               "request.GET", "request.POST", "request.data"}:
                return self._source(dotted_base + "[...]", getattr(node, "lineno", 1), rel)
            container = self.eval_expr(node.value, state, rel, report, depth)
            key = _literal(node.slice)
            if container.items is not None and isinstance(key, int) and -len(container.items) <= key < len(container.items):
                return container.items[key].clone()
            if container.mapping is not None and key is not UNKNOWN:
                return container.mapping.get(str(key), Value()).clone()
            return Value(container.tainted, container.origins, container.trace)
        if isinstance(node, ast.Attribute):
            base = self.eval_expr(node.value, state, rel, report, depth)
            return Value(base.tainted, base.origins, base.trace)
        if isinstance(node, ast.JoinedStr):
            parts = [self.eval_expr(item, state, rel, report, depth) for item in node.values]
            return Value(any(v.tainted for v in parts),
                         tuple(dict.fromkeys(o for v in parts for o in v.origins)),
                         tuple(dict.fromkeys(t for v in parts for t in v.trace)))
        if isinstance(node, ast.FormattedValue):
            return self.eval_expr(node.value, state, rel, report, depth)
        if isinstance(node, ast.BinOp):
            left = self.eval_expr(node.left, state, rel, report, depth)
            right = self.eval_expr(node.right, state, rel, report, depth)
            constant = UNKNOWN
            if left.constant is not UNKNOWN and right.constant is not UNKNOWN:
                try:
                    if isinstance(node.op, ast.Add): constant = left.constant + right.constant
                    elif isinstance(node.op, ast.Mod): constant = left.constant % right.constant
                except Exception:
                    pass
            return Value(left.tainted or right.tainted,
                         tuple(dict.fromkeys((*left.origins, *right.origins))),
                         tuple(dict.fromkeys((*left.trace, *right.trace))), constant)
        if isinstance(node, ast.BoolOp):
            vals = [self.eval_expr(v, state, rel, report, depth) for v in node.values]
            constant = UNKNOWN
            if all(v.constant is not UNKNOWN for v in vals):
                try:
                    raw = [v.constant for v in vals]
                    constant = all(raw) if isinstance(node.op, ast.And) else any(raw)
                except Exception:
                    pass
            return Value(any(v.tainted for v in vals),
                         tuple(dict.fromkeys(o for v in vals for o in v.origins)),
                         tuple(dict.fromkeys(t for v in vals for t in v.trace)), constant)
        if isinstance(node, ast.UnaryOp):
            value = self.eval_expr(node.operand, state, rel, report, depth)
            if value.constant is not UNKNOWN:
                try:
                    if isinstance(node.op, ast.Not): value.constant = not value.constant
                    elif isinstance(node.op, ast.USub): value.constant = -value.constant
                    elif isinstance(node.op, ast.UAdd): value.constant = +value.constant
                    elif isinstance(node.op, ast.Invert): value.constant = ~value.constant
                except Exception:
                    value.constant = UNKNOWN
            return value
        if isinstance(node, ast.IfExp):
            truth = self._truth(node.test, state)
            if truth is True: return self.eval_expr(node.body, state, rel, report, depth)
            if truth is False: return self.eval_expr(node.orelse, state, rel, report, depth)
            return _merge_value(self.eval_expr(node.body, state, rel, report, depth),
                                self.eval_expr(node.orelse, state, rel, report, depth))
        if isinstance(node, ast.Call):
            name = self.dotted(node.func)
            if name in {"input", "request.args.get", "request.form.get", "request.values.get",
                        "request.json.get", "request.GET.get", "request.POST.get"}:
                return self._source(name, getattr(node, "lineno", 1), rel)
            if name in {"int", "float", "bool", "str", "repr"} and node.args:
                inner = self.eval_expr(node.args[0], state, rel, report, depth)
                if name in {"int", "float", "bool"}:
                    literal = _literal(node.args[0])
                    if literal is not UNKNOWN:
                        try:
                            inner.constant = {"int": int, "float": float, "bool": bool}[name](literal)
                            inner.tainted = False
                            inner.origins = ()
                        except Exception:
                            pass
                return inner
            if name in {"list", "tuple", "set", "dict"}:
                if node.args:
                    return self.eval_expr(node.args[0], state, rel, report, depth)
                return Value(items=[] if name != "dict" else None, mapping={} if name == "dict" else None)
            if name.endswith(".append") or name.endswith(".extend") or name.endswith(".insert"):
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    var = node.func.value.id
                    container = state.env.get(var, Value(items=[])).clone()
                    if container.items is not None:
                        args = [self.eval_expr(a, state, rel, report, depth) for a in node.args]
                        if name.endswith(".append") and args: container.items.append(args[0])
                        elif name.endswith(".extend") and args and args[0].items is not None: container.items.extend(args[0].items)
                        elif name.endswith(".insert") and len(args) >= 2:
                            idx = args[0].constant
                            if isinstance(idx, int): container.items.insert(max(0, min(idx, len(container.items))), args[1])
                        container.tainted = any(v.tainted for v in container.items)
                        container.origins = tuple(dict.fromkeys(o for v in container.items for o in v.origins))
                        container.trace = tuple(dict.fromkeys(t for v in container.items for t in v.trace))
                        state.env[var] = container
                return Value()
            if name.endswith(".clear") or name.endswith(".pop") or name.endswith(".remove"):
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    var = node.func.value.id
                    container = state.env.get(var, Value()).clone()
                    if container.items is not None:
                        if name.endswith(".clear"): container.items.clear()
                        elif name.endswith(".pop") and container.items:
                            idx = node.args[0] if node.args else None
                            i = _literal(idx) if idx is not None else -1
                            if isinstance(i, int) and -len(container.items) <= i < len(container.items): container.items.pop(i)
                        elif name.endswith(".remove") and node.args:
                            rem = self.eval_expr(node.args[0], state, rel, report, depth)
                            if rem.constant is not UNKNOWN:
                                container.items = [v for v in container.items if v.constant != rem.constant]
                        container.tainted = any(v.tainted for v in container.items)
                        container.origins = tuple(dict.fromkeys(o for v in container.items for o in v.origins))
                        container.trace = tuple(dict.fromkeys(t for v in container.items for t in v.trace))
                        state.env[var] = container
                    elif container.mapping is not None:
                        if name.endswith(".clear"):
                            container.mapping.clear()
                        elif name.endswith(".pop") and node.args:
                            key_value = _literal(node.args[0])
                            if key_value is not UNKNOWN: container.mapping.pop(str(key_value), None)
                        container.tainted = any(v.tainted for v in container.mapping.values())
                        container.origins = tuple(dict.fromkeys(o for v in container.mapping.values() for o in v.origins))
                        container.trace = tuple(dict.fromkeys(t for v in container.mapping.values() for t in v.trace))
                        state.env[var] = container
                return Value()
            if name.endswith(".get") and isinstance(node.func, ast.Attribute):
                receiver = self.eval_expr(node.func.value, state, rel, report, depth)
                key_value = _literal(node.args[0]) if node.args else UNKNOWN
                if receiver.mapping is not None and key_value is not UNKNOWN:
                    found = receiver.mapping.get(str(key_value))
                    if found is not None: return found.clone()
                    if len(node.args) > 1: return self.eval_expr(node.args[1], state, rel, report, depth)
                    return Value()
            if name.endswith(".setdefault") and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                var = node.func.value.id
                container = state.env.get(var, Value(mapping={})).clone()
                key_value = _literal(node.args[0]) if node.args else UNKNOWN
                if container.mapping is not None and key_value is not UNKNOWN:
                    key = str(key_value)
                    if key not in container.mapping:
                        container.mapping[key] = self.eval_expr(node.args[1], state, rel, report, depth) if len(node.args) > 1 else Value()
                    state.env[var] = container
                    return container.mapping[key].clone()
            if name.endswith(".update") and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                var = node.func.value.id
                container = state.env.get(var, Value(mapping={})).clone()
                if container.mapping is not None and node.args:
                    other = self.eval_expr(node.args[0], state, rel, report, depth)
                    if other.mapping is not None: container.mapping.update(copy.deepcopy(other.mapping))
                    container.tainted = any(v.tainted for v in container.mapping.values())
                    container.origins = tuple(dict.fromkeys(o for v in container.mapping.values() for o in v.origins))
                    state.env[var] = container
                return Value()
            if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and node.args:
                val = self.eval_expr(node.args[0], state, rel, report, depth)
                if report: self._record("FLOW-PY-001", node, rel, name, val)
                return Value()
            if name in {"os.system", "os.popen", "subprocess.run", "subprocess.Popen",
                        "subprocess.call", "subprocess.check_output"}:
                vals = [self.eval_expr(a, state, rel, report, depth) for a in node.args]
                shell = any(k.arg == "shell" and _literal(k.value) is True for k in node.keywords)
                val = vals[0] if vals else Value()
                if report and val.tainted and (name.startswith("os.") or shell):
                    self._record("FLOW-PY-002", node, rel, name, val)
                return Value()
            if name in {"cursor.execute", "db.execute", "conn.execute", "connection.execute"} and node.args:
                val = self.eval_expr(node.args[0], state, rel, report, depth)
                # A constant query with a separate parameter tuple is not tainted SQL.
                if report and val.tainted:
                    self._record("FLOW-PY-003", node, rel, name, val)
                return Value()
            if name in {"render_template_string", "Markup"} and node.args:
                val = self.eval_expr(node.args[0], state, rel, report, depth)
                if report: self._record("FLOW-PY-004", node, rel, name, val)
                return Value()
            # Resolve only a unique same-project helper. Ambiguous names are not guessed.
            candidates = self.functions.get(name.rsplit(".", 1)[-1], [])
            if len(candidates) == 1 and depth < MAX_CALL_DEPTH:
                helper_rel, fn, _helper_source = candidates[0]
                identity = f"{helper_rel}:{fn.name}"
                if identity not in self.call_stack:
                    args = [self.eval_expr(a, state, rel, report, depth) for a in node.args]
                    local = State()
                    positional = list(fn.args.posonlyargs) + list(fn.args.args)
                    for arg_node, arg_value in zip(positional, args):
                        local.env[arg_node.arg] = arg_value.clone()
                    for kw in node.keywords:
                        if kw.arg:
                            local.env[kw.arg] = self.eval_expr(kw.value, state, rel, report, depth)
                    self.call_stack.append(identity)
                    self.exec_block(fn.body, local, helper_rel, depth + 1)
                    self.call_stack.pop()
                    return (local.returned or Value()).clone()
            children = [self.eval_expr(a, state, rel, report, depth) for a in node.args]
            return Value(any(v.tainted for v in children),
                         tuple(dict.fromkeys(o for v in children for o in v.origins)),
                         tuple(dict.fromkeys(t for v in children for t in v.trace)))
        if isinstance(node, ast.Compare):
            left = self.eval_expr(node.left, state, rel, report, depth)
            comparators = [self.eval_expr(v, state, rel, report, depth) for v in node.comparators]
            if left.constant is not UNKNOWN and all(v.constant is not UNKNOWN for v in comparators):
                try:
                    # Safe constant comparisons only.
                    result = left.constant
                    for op, val in zip(node.ops, comparators):
                        rhs = val.constant
                        if isinstance(op, ast.Eq): result = result == rhs
                        elif isinstance(op, ast.NotEq): result = result != rhs
                        elif isinstance(op, ast.Lt): result = result < rhs
                        elif isinstance(op, ast.LtE): result = result <= rhs
                        elif isinstance(op, ast.Gt): result = result > rhs
                        elif isinstance(op, ast.GtE): result = result >= rhs
                        else: return Value()
                    return Value(constant=result)
                except Exception:
                    pass
            return Value()
        return Value()

    def exec_block(self, body: list[ast.stmt], state: State, rel: str, depth: int = 0) -> State:
        for stmt in body:
            self.steps += 1
            if self.steps > MAX_STEPS or state.terminated:
                break
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(stmt, ast.Assign):
                value = self.eval_expr(stmt.value, state, rel, depth=depth)
                for target in stmt.targets: self._assign(target, value, state, rel)
            elif isinstance(stmt, ast.AnnAssign):
                value = self.eval_expr(stmt.value, state, rel, depth=depth)
                self._assign(stmt.target, value, state, rel)
            elif isinstance(stmt, ast.AugAssign):
                old = self.eval_expr(stmt.target, state, rel, depth=depth)
                new = self.eval_expr(stmt.value, state, rel, depth=depth)
                merged = _merge_value(old, new)
                self._assign(stmt.target, merged, state, rel)
            elif isinstance(stmt, ast.Expr):
                self.eval_expr(stmt.value, state, rel, depth=depth)
            elif isinstance(stmt, ast.If):
                truth = self._truth(stmt.test, state)
                if truth is True: self.exec_block(stmt.body, state, rel, depth)
                elif truth is False: self.exec_block(stmt.orelse, state, rel, depth)
                else:
                    left = self.exec_block(stmt.body, State(copy.deepcopy(state.env)), rel, depth)
                    right = self.exec_block(stmt.orelse, State(copy.deepcopy(state.env)), rel, depth)
                    merged = _merge_states([left, right])
                    state.env = merged.env
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(stmt, ast.While) and self._truth(stmt.test, state) is False:
                    self.exec_block(stmt.orelse, state, rel, depth)
                    continue
                before = State(copy.deepcopy(state.env))
                loop_state = State(copy.deepcopy(state.env))
                if isinstance(stmt, (ast.For, ast.AsyncFor)):
                    iterable = self.eval_expr(stmt.iter, state, rel, depth=depth)
                    first = iterable.items[0] if iterable.items else Value()
                    self._assign(stmt.target, first, loop_state, rel)
                self.exec_block(stmt.body, loop_state, rel, depth)
                state.env = _merge_states([before, loop_state]).env
                self.exec_block(stmt.orelse, state, rel, depth)
            elif isinstance(stmt, ast.Return):
                state.returned = self.eval_expr(stmt.value, state, rel, depth=depth)
                state.terminated = True
            elif isinstance(stmt, ast.Raise):
                state.terminated = True
            elif isinstance(stmt, ast.Try):
                branches = []
                normal = self.exec_block(stmt.body, State(copy.deepcopy(state.env)), rel, depth)
                branches.append(normal)
                for handler in stmt.handlers:
                    branches.append(self.exec_block(handler.body, State(copy.deepcopy(state.env)), rel, depth))
                merged = _merge_states(branches)
                state.env = merged.env
                if stmt.finalbody: self.exec_block(stmt.finalbody, state, rel, depth)
            else:
                # Evaluate nested expressions conservatively without pretending to
                # understand unsupported statement semantics.
                for child in ast.iter_child_nodes(stmt):
                    if isinstance(child, ast.expr): self.eval_expr(child, state, rel, depth=depth)
        return state

    def run(self) -> list[dict[str, Any]]:
        for path in self.files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except (OSError, SyntaxError):
                continue
            rel = path.relative_to(self.root).as_posix() if self.root.is_dir() else path.name
            self.route_findings.extend(_route_guard_findings(source, rel))
            # Analyze each function independently; same-file helper resolution is
            # shared, but caller state never leaks between unrelated functions.
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.call_stack = [f"{rel}:{node.name}"]
                    state = State()
                    for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
                        state.env[arg.arg] = Value()
                    self.exec_block(node.body, state, rel)
                    self.call_stack = []
                elif isinstance(node, ast.Expr):
                    self.eval_expr(node.value, State(), rel)
        return list(self.findings.values()) + self.route_findings


def analyze_python_flows(root: str | Path) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.exists():
        raise ValueError("Provide an existing source file or directory.")
    if base.is_file():
        files = [base] if base.suffix.lower() == ".py" else []
        root_dir = base.parent
    else:
        root_dir = base
        ignored = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", "vendor", "target"}
        files = []
        for path in base.rglob("*.py"):
            if path.is_symlink() or not path.is_file() or any(part in ignored for part in path.relative_to(base).parts):
                continue
            try:
                if path.stat().st_size <= MAX_FILE_BYTES:
                    files.append(path)
            except OSError:
                continue
            if len(files) >= MAX_FILES:
                break
    analyzer = Analyzer(root_dir, files)
    findings = analyzer.run()
    return {
        "engine": "python-path-sensitive-taint-v2",
        "files_analyzed": len(analyzer.sources),
        "finding_count": len(findings),
        "findings": findings,
        "limitations": [
            "Path conditions are evaluated only for safe constant expressions; unknown conditions are joined conservatively, not solved with a theorem prover.",
            "List, tuple, set, and dictionary tracking is bounded to literal structures and recognized mutations; aliasing, comprehensions, custom containers, and complex keys may be unresolved.",
            "Same-project helper resolution requires one unique statically named Python function; dynamic dispatch, decorators, imported aliases, cross-file imports, and method receiver semantics are not fully modeled.",
            "Sanitization is context-specific; generic transformations are not assumed safe. Findings are emitted only when a tracked source value reaches a recognized sink.",
            "The analyzer does not execute project code and cannot establish runtime reachability or exploitability.",
        ],
    }
