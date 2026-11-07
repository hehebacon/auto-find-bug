from __future__ import annotations

"""Bounded Java source-to-sink analysis using javalang ASTs.

This is a local static review engine. It does not execute project code. Unknown
branches are joined conservatively; unresolved dispatch is not guessed.
"""

import ast as py_ast
import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

UNKNOWN = object()
MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000
MAX_CALL_DEPTH = 8
MAX_STEPS = 100_000

SQL_SINKS = {
    "executeQuery", "executeUpdate", "execute", "prepareStatement", "prepareCall",
    "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "query",
    "update", "batchUpdate", "createNativeQuery", "executeBatch",
}
COMMAND_SINKS = {"exec"}
SOURCE_METHODS = {
    "getParameter", "getParameterValues", "getHeader", "getHeaders",
    "getQueryString", "getParameterMap", "getParameterNames",
}


@dataclass
class JValue:
    tainted: bool = False
    origins: tuple[tuple[str, int, str], ...] = ()
    trace: tuple[str, ...] = ()
    constant: Any = UNKNOWN
    items: list["JValue"] | None = None
    mapping: dict[str, "JValue"] | None = None

    def clone(self) -> "JValue":
        return copy.deepcopy(self)


@dataclass
class JState:
    env: dict[str, JValue] = field(default_factory=dict)
    returned: JValue | None = None
    terminated: bool = False


def _merge_value(a: JValue, b: JValue) -> JValue:
    origins = tuple(dict.fromkeys((*a.origins, *b.origins)))
    trace = tuple(dict.fromkeys((*a.trace, *b.trace)))
    constant = a.constant if a.constant is not UNKNOWN and a.constant == b.constant else UNKNOWN
    items = None
    if a.items is not None and b.items is not None and len(a.items) == len(b.items):
        items = [_merge_value(x, y) for x, y in zip(a.items, b.items)]
    mapping = None
    if a.mapping is not None and b.mapping is not None:
        mapping = {
            key: _merge_value(a.mapping.get(key, JValue()), b.mapping.get(key, JValue()))
            for key in set(a.mapping) | set(b.mapping)
        }
    return JValue(a.tainted or b.tainted, origins, trace, constant, items, mapping)


def _merge_states(states: list[JState]) -> JState:
    keys = set().union(*(s.env for s in states)) if states else set()
    env = {}
    for key in keys:
        values = [s.env.get(key, JValue()) for s in states]
        value = values[0].clone()
        for other in values[1:]:
            value = _merge_value(value, other)
        env[key] = value
    returned = [s.returned for s in states if s.returned is not None]
    if returned:
        if len(returned) != len(states): returned.append(JValue())
        merged_return = returned[0].clone()
        for value in returned[1:]: merged_return = _merge_value(merged_return, value)
    else:
        merged_return = None
    return JState(env=env, returned=merged_return, terminated=bool(states) and all(s.terminated for s in states))


def _node_line(node: Any) -> int:
    position = getattr(node, "position", None)
    return int(getattr(position, "line", 1) or 1)


class JavaFlowAnalyzer:
    def __init__(self, root: Path, files: list[Path]):
        try:
            import javalang
        except ImportError as exc:
            raise RuntimeError("Install the optional Java parser with the SAST extra.") from exc
        self.javalang = javalang
        self.root = root
        self.files = files
        self.sources: dict[str, list[str]] = {}
        self.methods: dict[str, list[tuple[str, str, Any]]] = {}
        self.method_owner: dict[int, str] = {}
        self.current_class = ""
        self.trees: list[tuple[str, Any]] = []
        self.findings: dict[tuple[str, str, int, int, int], dict[str, Any]] = {}
        self.steps = 0
        self.call_stack: list[str] = []
        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = javalang.parse.parse(source)
            except (OSError, self.javalang.parser.JavaSyntaxError, TypeError):
                continue
            rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
            self.sources[rel] = source.splitlines()
            self.trees.append((rel, tree))
            for _, class_node in tree.filter(self.javalang.tree.ClassDeclaration):
                for member in class_node.body or []:
                    if isinstance(member, self.javalang.tree.MethodDeclaration):
                        self.methods.setdefault(member.name, []).append((rel, class_node.name, member))
                        self.method_owner[id(member)] = class_node.name

    @staticmethod
    def _const(node: Any) -> Any:
        if node is None:
            return UNKNOWN
        name = type(node).__name__
        if name == "Literal":
            raw = str(getattr(node, "value", ""))
            if raw in {"true", "false"}: return raw == "true"
            if raw == "null": return None
            try: return py_ast.literal_eval(raw)
            except Exception:
                try: return int(raw, 0)
                except Exception: return UNKNOWN
        return UNKNOWN

    @staticmethod
    def _qualifier(node: Any) -> str:
        return str(getattr(node, "qualifier", "") or "")

    @staticmethod
    def _member(node: Any) -> str:
        return str(getattr(node, "member", "") or "")

    def _source(self, rel: str, node: Any, label: str) -> JValue:
        line = _node_line(node)
        return JValue(True, ((rel, line, label),), (f"{rel}:{line} source {label}",))

    def _record(self, rule: str, rel: str, node: Any, sink: str, value: JValue) -> None:
        if not value.tainted or not value.origins:
            return
        line = _node_line(node)
        sink_lines = self.sources.get(rel, [])
        evidence = sink_lines[line - 1].strip()[:220] if 0 < line <= len(sink_lines) else sink
        for source_file, source_line, source_name in value.origins:
            key = (rule, rel, line, source_file, source_line)
            source_lines = self.sources.get(source_file, [])
            source_evidence = source_lines[source_line - 1].strip()[:220] if 0 < source_line <= len(source_lines) else source_name
            trace = [*value.trace, f"{rel}:{line} sink {sink}"]
            self.findings[key] = {
                "rule_id": rule,
                "severity": "HIGH",
                "title": "Request-controlled data reaches a SQL query sink" if rule == "FLOW-JAVA-001" else "Request-controlled data reaches process execution",
                "file": rel,
                "line": line,
                "evidence": evidence,
                "recommendation": "Review the complete source-to-sink path, branch feasibility, collection state, helper return value, and API semantics before confirming impact.",
                "confidence": "medium",
                "flow": {
                    "source": source_name,
                    "source_file": source_file,
                    "source_line": source_line,
                    "source_evidence": source_evidence,
                    "sink": sink,
                    "sink_line": line,
                    "function": self.call_stack[-1] if self.call_stack else "<class>",
                    "variables": [x.split("->", 1)[1].strip() for x in trace if "propagation ->" in x],
                    "trace": trace[-30:],
                },
            }

    def _join(self, values: list[JValue]) -> JValue:
        if not values: return JValue()
        result = values[0].clone()
        for item in values[1:]: result = _merge_value(result, item)
        return result

    def _truth(self, node: Any, state: JState, rel: str, depth: int) -> bool | None:
        value = self.expr(node, state, rel, depth)
        if value.constant is not UNKNOWN:
            try: return bool(value.constant)
            except Exception: return None
        return None

    def _assign(self, target: Any, value: JValue, state: JState, rel: str) -> None:
        name = type(target).__name__
        if name == "MemberReference":
            variable = self._member(target)
            selectors = getattr(target, "selectors", None) or []
            if not selectors:
                assigned = value.clone()
                if assigned.tainted:
                    assigned.trace = (*assigned.trace, f"{rel}:{_node_line(target)} propagation -> {variable}")
                state.env[variable] = assigned
                return
            current = state.env.get(variable, JValue()).clone()
            for selector in selectors:
                if type(selector).__name__ == "ArraySelector":
                    key = self.expr(getattr(selector, "index", None), state, rel, 0).constant
                    if current.items is not None and isinstance(key, int) and -len(current.items) <= key < len(current.items):
                        current.items[key] = value.clone()
                    elif current.items is not None:
                        current.items = [ _merge_value(item, value) for item in current.items ]
            current.tainted = any(item.tainted for item in (current.items or []))
            current.origins = tuple(dict.fromkeys(o for item in (current.items or []) for o in item.origins))
            state.env[variable] = current
        elif name == "ArraySelector":
            pass

    def _apply_selectors(self, node: Any, base: JValue, state: JState, rel: str, depth: int, receiver_label: str) -> JValue:
        for selector in getattr(node, "selectors", None) or []:
            selector_name = type(selector).__name__
            if selector_name == "ArraySelector":
                index = self.expr(getattr(selector, "index", None), state, rel, depth).constant
                if base.items is not None and isinstance(index, int) and -len(base.items) <= index < len(base.items):
                    base = base.items[index].clone()
                elif base.tainted:
                    base = JValue(True, base.origins, base.trace)
                else:
                    base = JValue()
            elif selector_name == "MethodInvocation":
                member = self._member(selector)
                args = [self.expr(arg, state, rel, depth) for arg in (getattr(selector, "arguments", None) or [])]
                # Resolve fluent calls on freshly-created project objects, e.g.
                # new Helper().transform(input). Only execute a uniquely resolved
                # in-project method; library/dynamic dispatch remains unknown.
                candidates = self.methods.get(member, [])
                same_file_class = [item for item in candidates if item[0] == rel and item[1] == receiver_label]
                same_class = [item for item in candidates if item[1] == receiver_label]
                resolved = same_file_class if same_file_class else (same_class if len(same_class) == 1 else (candidates if len(candidates) == 1 else []))
                identity = f"{resolved[0][0]}:{resolved[0][1]}:{member}" if len(resolved) == 1 else ""
                if resolved and depth < MAX_CALL_DEPTH and identity not in self.call_stack:
                    helper_rel, helper_class, method = resolved[0]
                    local = JState()
                    for param, arg in zip(method.parameters or [], args):
                        bound = arg.clone()
                        if bound.tainted:
                            bound.trace = (*bound.trace, f"{rel}:{_node_line(selector)} propagation call {member} -> {param.name}")
                        local.env[param.name] = bound
                    previous_class = self.current_class
                    self.current_class = helper_class
                    self.call_stack.append(identity)
                    self.block(method.body or [], local, helper_rel, depth + 1)
                    self.call_stack.pop()
                    self.current_class = previous_class
                    base = (local.returned or JValue()).clone()
                    continue
                if member in SQL_SINKS:
                    receiver = receiver_label.lower()
                    generic = any(token in receiver for token in ("stmt", "statement", "jdbc", "query", "entitymanager", "session", "connection", "conn", "database", "db"))
                    strong = member in {"executeQuery", "executeUpdate", "prepareStatement", "prepareCall", "createNativeQuery", "queryForObject", "queryForList", "queryForMap", "queryForRowSet"}
                    if strong or generic:
                        value = args[0] if args else base
                        if value.tainted: self._record("FLOW-JAVA-001", rel, selector, f"{receiver_label}.{member}", value)
                        base = JValue()
                elif member == "exec" and any(token in receiver_label.lower() for token in ("runtime", "process")):
                    value = args[0] if args else base
                    if value.tainted: self._record("FLOW-JAVA-002", rel, selector, f"{receiver_label}.{member}", value)
                    base = JValue()
                elif member == "start" and base.tainted:
                    self._record("FLOW-JAVA-002", rel, selector, f"{receiver_label}.start", base)
                    base = JValue()
                elif member == "get":
                    key = args[0].constant if args else UNKNOWN
                    if base.mapping is not None and key is not UNKNOWN:
                        base = base.mapping.get(str(key), base.mapping.get("*", JValue())).clone()
                    elif base.items is not None and isinstance(key, int) and -len(base.items) <= key < len(base.items):
                        base = base.items[key].clone()
                    elif base.tainted:
                        base = JValue(True, base.origins, base.trace)
                    elif len(args) > 1:
                        base = args[1].clone()
                    else:
                        base = JValue()
                elif member == "command":
                    incoming = self._join(args)
                    if incoming.tainted:
                        base = JValue(True, incoming.origins, (*incoming.trace, f"{rel}:{_node_line(selector)} propagation -> ProcessBuilder.command"))
                else:
                    base = self._join([base, *args])
        return base

    def _collection_call(self, node: Any, state: JState, rel: str, depth: int) -> JValue | None:
        member = self._member(node)
        receiver = self._qualifier(node)
        if not receiver or receiver not in state.env:
            return None
        current = state.env[receiver].clone()
        args = [self.expr(arg, state, rel, depth) for arg in (getattr(node, "arguments", None) or [])]
        raw_args = getattr(node, "arguments", None) or []
        if member in {"add", "addElement"} and current.items is not None and args:
            current.items.append(args[-1].clone())
        elif member == "addBatch" and args:
            if current.items is None: current.items = []
            current.items.append(args[0].clone())
        elif member == "add" and current.items is None:
            current.items = [args[-1].clone()] if args else []
        elif member in {"put", "putIfAbsent"} and args:
            if current.mapping is None: current.mapping = {}
            key = args[0].constant
            current.mapping[str(key) if key is not UNKNOWN else "*"] = args[1].clone() if len(args) > 1 else JValue()
        elif member in {"get", "elementAt"}:
            if current.items is not None and args and isinstance(args[0].constant, int):
                index = args[0].constant
                if -len(current.items) <= index < len(current.items): return current.items[index].clone()
            if current.mapping is not None and args:
                key = args[0].constant
                found = current.mapping.get(str(key)) if key is not UNKNOWN else None
                if found is not None: return found.clone()
                if "*" in current.mapping: return current.mapping["*"].clone()
            if current.tainted: return JValue(True, current.origins, current.trace)
            return JValue()
        elif member in {"remove", "removeElementAt"}:
            if current.items is not None and args:
                index = args[0].constant
                if isinstance(index, int) and -len(current.items) <= index < len(current.items):
                    removed = current.items.pop(index)
                    state.env[receiver] = current
                    return removed
                if args[0].constant is not UNKNOWN:
                    current.items = [v for v in current.items if v.constant != args[0].constant]
            elif current.mapping is not None and args and args[0].constant is not UNKNOWN:
                current.mapping.pop(str(args[0].constant), None)
        elif member == "clear":
            if current.items is not None: current.items.clear()
            if current.mapping is not None: current.mapping.clear()
        elif member == "set":
            if current.items is not None and len(args) >= 2 and isinstance(args[0].constant, int):
                index = args[0].constant
                if -len(current.items) <= index < len(current.items): current.items[index] = args[1].clone()
        elif member == "putAll" and args and args[0].mapping is not None:
            if current.mapping is None: current.mapping = {}
            current.mapping.update(copy.deepcopy(args[0].mapping))
        else:
            return None
        all_values = (current.items or []) + (list(current.mapping.values()) if current.mapping else [])
        current.tainted = any(v.tainted for v in all_values)
        current.origins = tuple(dict.fromkeys(o for v in all_values for o in v.origins))
        current.trace = tuple(dict.fromkeys(t for v in all_values for t in v.trace))
        state.env[receiver] = current
        return JValue()

    def expr(self, node: Any, state: JState, rel: str, depth: int = 0) -> JValue:
        if node is None: return JValue()
        name = type(node).__name__
        if name == "Literal":
            return JValue(constant=self._const(node))
        if name == "MemberReference":
            value = state.env.get(self._member(node), JValue()).clone()
            selectors = getattr(node, "selectors", None) or []
            for selector in selectors:
                if type(selector).__name__ == "ArraySelector":
                    index = self.expr(getattr(selector, "index", None), state, rel, depth).constant
                    if value.items is not None and isinstance(index, int) and -len(value.items) <= index < len(value.items):
                        value = value.items[index].clone()
                    elif value.tainted:
                        value = JValue(True, value.origins, value.trace)
                    else:
                        value = JValue()
            return value
        if name in {"ArrayInitializer", "ArrayCreator"}:
            initializer = getattr(node, "initializers", None)
            if initializer is None:
                initializer = getattr(node, "initializer", None)
            if initializer is not None and type(initializer).__name__ == "ArrayInitializer":
                return self.expr(initializer, state, rel, depth)
            raw = getattr(node, "initializers", None)
            if raw is None and name == "ArrayCreator":
                raw = []
            values = [self.expr(x, state, rel, depth) for x in (raw or [])]
            return JValue(any(v.tainted for v in values),
                          tuple(dict.fromkeys(o for v in values for o in v.origins)),
                          tuple(dict.fromkeys(t for v in values for t in v.trace)),
                          items=values)
        if name == "Cast":
            return self.expr(getattr(node, "expression", None), state, rel, depth)
        if name == "BinaryOperation":
            left = self.expr(node.operandl, state, rel, depth)
            right = self.expr(node.operandr, state, rel, depth)
            constant = UNKNOWN
            if left.constant is not UNKNOWN and right.constant is not UNKNOWN:
                try:
                    op = node.operator
                    if op == "+": constant = left.constant + right.constant
                    elif op == "-": constant = left.constant - right.constant
                    elif op == "*": constant = left.constant * right.constant
                    elif op == "/": constant = left.constant / right.constant
                    elif op == "%": constant = left.constant % right.constant
                    elif op == "==": constant = left.constant == right.constant
                    elif op == "!=": constant = left.constant != right.constant
                    elif op == "<": constant = left.constant < right.constant
                    elif op == "<=": constant = left.constant <= right.constant
                    elif op == ">": constant = left.constant > right.constant
                    elif op == ">=": constant = left.constant >= right.constant
                    elif op == "&&": constant = bool(left.constant) and bool(right.constant)
                    elif op == "||": constant = bool(left.constant) or bool(right.constant)
                except Exception:
                    pass
            return JValue(left.tainted or right.tainted,
                          tuple(dict.fromkeys((*left.origins, *right.origins))),
                          tuple(dict.fromkeys((*left.trace, *right.trace))), constant)
        if name == "UnaryOperation":
            value = self.expr(getattr(node, "expression", None), state, rel, depth)
            operator = getattr(node, "operator", None)
            if value.constant is not UNKNOWN:
                try:
                    if operator == "!": value.constant = not value.constant
                    elif operator == "-": value.constant = -value.constant
                    elif operator == "+": value.constant = +value.constant
                except Exception: value.constant = UNKNOWN
            return value
        if name == "TernaryExpression":
            truth = self._truth(node.condition, state, rel, depth)
            if truth is True: return self.expr(node.if_true, state, rel, depth)
            if truth is False: return self.expr(node.if_false, state, rel, depth)
            return self._join([self.expr(node.if_true, state, rel, depth), self.expr(node.if_false, state, rel, depth)])
        if name == "Assignment":
            value = self.expr(node.value, state, rel, depth)
            self._assign(node.expressionl, value, state, rel)
            return value
        if name == "ClassCreator":
            args = [self.expr(x, state, rel, depth) for x in (getattr(node, "arguments", None) or [])]
            type_obj = getattr(node, "type", None)
            type_name = str(getattr(type_obj, "name", type_obj or ""))
            value = self._join(args)
            if "ProcessBuilder" in type_name and value.tainted:
                value = JValue(True, value.origins, (*value.trace, f"{rel}:{_node_line(node)} propagation -> ProcessBuilder"))
            return self._apply_selectors(node, value, state, rel, depth, type_name)
        if name == "MethodInvocation":
            member = self._member(node)
            receiver = self._qualifier(node)
            args_nodes = getattr(node, "arguments", None) or []
            args = [self.expr(arg, state, rel, depth) for arg in args_nodes]
            # Fold deterministic String operations used by branch/switch guards.
            receiver_value = state.env.get(receiver, JValue()) if receiver else JValue()
            if receiver_value.constant is not UNKNOWN:
                try:
                    if member == "charAt" and args and isinstance(args[0].constant, int):
                        return JValue(constant=receiver_value.constant[args[0].constant])
                    if member == "length" and not args:
                        return JValue(constant=len(receiver_value.constant))
                    if member == "isEmpty" and not args:
                        return JValue(constant=len(receiver_value.constant) == 0)
                    if member == "equals" and args and args[0].constant is not UNKNOWN:
                        return JValue(constant=receiver_value.constant == args[0].constant)
                    if member == "substring" and args and all(a.constant is not UNKNOWN for a in args):
                        start = args[0].constant
                        end = args[1].constant if len(args) > 1 else len(receiver_value.constant)
                        return JValue(constant=receiver_value.constant[start:end])
                except (IndexError, TypeError, ValueError):
                    pass
            if member in SOURCE_METHODS and any(x in receiver.lower() for x in ("request", "req")):
                value = self._source(rel, node, f"{receiver}.{member}")
                return self._apply_selectors(node, value, state, rel, depth, f"{receiver}.{member}")
            if member == "asList" and "Arrays" in receiver:
                return JValue(any(v.tainted for v in args),
                              tuple(dict.fromkeys(o for v in args for o in v.origins)),
                              tuple(dict.fromkeys(t for v in args for t in v.trace)),
                              items=[v.clone() for v in args])
            if member == "getValue" and "cookie" in receiver.lower():
                value = self._source(rel, node, f"{receiver}.getValue")
                return self._apply_selectors(node, value, state, rel, depth, f"{receiver}.getValue")
            if member == "nextElement" and receiver in state.env and state.env[receiver].tainted:
                return JValue(True, state.env[receiver].origins, state.env[receiver].trace)
            collection_value = self._collection_call(node, state, rel, depth)
            if collection_value is not None: return collection_value
            sql_receiver = receiver.lower()
            sql_generic_receiver = any(token in sql_receiver for token in (
                "stmt", "statement", "jdbc", "query", "entitymanager", "session",
                "connection", "conn", "database", "db",
            ))
            sql_strong = member in {
                "executeQuery", "executeUpdate", "prepareStatement", "prepareCall",
                "createNativeQuery", "queryForObject", "queryForList", "queryForMap",
                "queryForRowSet",
            }
            if member in SQL_SINKS and (sql_strong or sql_generic_receiver):
                val = args[0] if args else state.env.get(receiver, JValue())
                if member == "executeBatch" and not val.tainted:
                    val = state.env.get(receiver, JValue())
                if val.tainted: self._record("FLOW-JAVA-001", rel, node, f"{receiver}.{member}", val)
                return JValue()
            if member in COMMAND_SINKS and any(token in receiver.lower() for token in ("runtime", "process")):
                val = args[0] if args else JValue()
                if val.tainted: self._record("FLOW-JAVA-002", rel, node, f"{receiver}.{member}", val)
                return JValue()
            if member == "command" and receiver in state.env:
                current = state.env[receiver].clone()
                val = self._join(args)
                if val.tainted:
                    current.tainted, current.origins = True, val.origins
                    current.trace = (*val.trace, f"{rel}:{_node_line(node)} propagation -> {receiver}.command")
                state.env[receiver] = current
                return JValue()
            if member == "start" and receiver in state.env:
                val = state.env[receiver]
                if val.tainted: self._record("FLOW-JAVA-002", rel, node, f"{receiver}.start", val)
                return JValue()
            candidates = self.methods.get(member, [])
            same_class = [item for item in candidates if item[1] == self.current_class]
            resolved = same_class if same_class else (candidates if len(candidates) == 1 else [])
            if len(resolved) == 1 and depth < MAX_CALL_DEPTH:
                helper_rel, helper_class, method = resolved[0]
                identity = f"{helper_rel}:{helper_class}:{member}"
                if identity not in self.call_stack:
                    local = JState()
                    for param, arg in zip(method.parameters or [], args):
                        bound = arg.clone()
                        if bound.tainted:
                            bound.trace = (*bound.trace, f"{rel}:{_node_line(node)} propagation call {member} -> {param.name}")
                        local.env[param.name] = bound
                    previous_class = self.current_class
                    self.current_class = helper_class
                    self.call_stack.append(identity)
                    self.block(method.body or [], local, helper_rel, depth + 1)
                    self.call_stack.pop()
                    self.current_class = previous_class
                    returned = (local.returned or JValue()).clone()
                    return self._apply_selectors(node, returned, state, rel, depth, f"{receiver}.{member}")
            return self._apply_selectors(node, self._join(args), state, rel, depth, f"{receiver}.{member}")
        if name == "This":
            return JValue()
        return JValue()

    def statement(self, stmt: Any, state: JState, rel: str, depth: int) -> None:
        name = type(stmt).__name__
        if name == "BlockStatement":
            self.block(stmt.statements or [], state, rel, depth)
        elif name == "LocalVariableDeclaration":
            for declarator in stmt.declarators or []:
                value = self.expr(declarator.initializer, state, rel, depth)
                if value.tainted:
                    value.trace = (*value.trace, f"{rel}:{_node_line(declarator)} propagation -> {declarator.name}")
                state.env[declarator.name] = value.clone()
        elif name == "StatementExpression":
            self.expr(stmt.expression, state, rel, depth)
        elif name == "IfStatement":
            truth = self._truth(stmt.condition, state, rel, depth)
            if truth is True: self.statement(stmt.then_statement, state, rel, depth)
            elif truth is False:
                if stmt.else_statement: self.statement(stmt.else_statement, state, rel, depth)
            else:
                left = JState(copy.deepcopy(state.env))
                right = JState(copy.deepcopy(state.env))
                self.statement(stmt.then_statement, left, rel, depth)
                if stmt.else_statement: self.statement(stmt.else_statement, right, rel, depth)
                merged = _merge_states([left, right])
                state.env = merged.env
                state.returned = merged.returned
                state.terminated = merged.terminated
        elif name == "ReturnStatement":
            state.returned = self.expr(stmt.expression, state, rel, depth)
            state.terminated = True
        elif name in {"WhileStatement", "DoStatement"}:
            truth = self._truth(stmt.condition, state, rel, depth)
            if truth is False: return
            before = JState(copy.deepcopy(state.env))
            loop = JState(copy.deepcopy(state.env))
            self.statement(stmt.body, loop, rel, depth)
            state.env = _merge_states([before, loop]).env
        elif name == "ForStatement":
            before = JState(copy.deepcopy(state.env))
            loop = JState(copy.deepcopy(state.env))
            control = getattr(stmt, "control", None)
            if type(control).__name__ == "EnhancedForControl":
                iterable = self.expr(control.iterable, state, rel, depth)
                var = getattr(control.var, "declarators", None) or []
                if var:
                    loop.env[var[0].name] = (iterable.items[0].clone() if iterable.items else JValue(iterable.tainted, iterable.origins, iterable.trace))
            elif type(control).__name__ == "ForControl":
                init = getattr(control, "init", None)
                for item in init or []: self.statement(item, loop, rel, depth)
            self.statement(stmt.body, loop, rel, depth)
            state.env = _merge_states([before, loop]).env
        elif name == "SwitchStatement":
            selector = self.expr(stmt.expression, state, rel, depth)
            cases = stmt.cases or []
            selected = None
            if selector.constant is not UNKNOWN:
                for case in cases:
                    labels = [self._const(x) for x in (case.case or [])]
                    if selector.constant in labels or not labels:
                        selected = case
                        break
            if selected is not None:
                active = False
                for case in cases:
                    labels = [self._const(x) for x in (case.case or [])]
                    if not active and (selector.constant in labels or not labels):
                        active = True
                    if not active:
                        continue
                    stop = False
                    for item in case.statements or []:
                        if type(item).__name__ in {"BreakStatement", "ReturnStatement", "ThrowStatement"}:
                            if type(item).__name__ == "BreakStatement":
                                stop = True
                                break
                            self.statement(item, state, rel, depth)
                            stop = True
                            break
                        self.statement(item, state, rel, depth)
                    if stop:
                        break
            else:
                branches = []
                for case in cases:
                    branch = JState(copy.deepcopy(state.env))
                    for item in case.statements or []: self.statement(item, branch, rel, depth)
                    branches.append(branch)
                if branches: state.env = _merge_states(branches).env
        elif name == "TryStatement":
            branches = []
            normal = JState(copy.deepcopy(state.env))
            self.block(stmt.block or [], normal, rel, depth)
            branches.append(normal)
            for catch in stmt.catches or []:
                branch = JState(copy.deepcopy(state.env))
                self.block(catch.block or [], branch, rel, depth)
                branches.append(branch)
            state.env = _merge_states(branches).env
            self.block(stmt.finally_block or [], state, rel, depth)
        elif name == "ThrowStatement":
            state.terminated = True

    def block(self, statements: list[Any], state: JState, rel: str, depth: int) -> None:
        for stmt in statements:
            self.steps += 1
            if self.steps > MAX_STEPS or state.terminated: break
            self.statement(stmt, state, rel, depth)

    def run(self) -> list[dict[str, Any]]:
        for rel, tree in self.trees:
            for _, method in tree.filter(self.javalang.tree.MethodDeclaration):
                self.current_class = self.method_owner.get(id(method), "")
                self.steps = 0
                self.call_stack = [f"{rel}:{self.current_class}:{method.name}"]
                state = JState()
                for param in method.parameters or []:
                    state.env[param.name] = JValue()
                self.block(method.body or [], state, rel, 0)
                self.call_stack = []
            self.current_class = ""
        return list(self.findings.values())


def analyze_java_flows(root: str | Path) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.exists(): raise ValueError("Provide an existing source file or directory.")
    if base.is_file():
        files = [base] if base.suffix.lower() == ".java" else []
        root_dir = base.parent
    else:
        root_dir = base
        ignored = {".git", ".venv", "venv", "node_modules", "target", "build", "dist", "__pycache__"}
        files = []
        for path in base.rglob("*.java"):
            if path.is_symlink() or not path.is_file() or any(part in ignored for part in path.relative_to(base).parts):
                continue
            try:
                if path.stat().st_size <= MAX_FILE_BYTES: files.append(path)
            except OSError:
                continue
            if len(files) >= MAX_FILES: break
    try:
        analyzer = JavaFlowAnalyzer(root_dir, files)
    except RuntimeError as exc:
        return {"available": False, "engine": "java-ast-flow-v1", "files_analyzed": 0, "finding_count": 0,
                "findings": [], "note": str(exc), "limitations": ["Java AST engine is optional; install the SAST extra."]}
    findings = analyzer.run()
    parsed = set(analyzer.sources)
    discovered = [
        path.relative_to(root_dir).as_posix() if root_dir.is_dir() else path.name
        for path in files
    ]
    return {
        "available": True,
        "engine": "java-ast-flow-v1",
        "files_discovered": len(discovered),
        "files_analyzed": len(parsed),
        "analyzed_files": sorted(parsed),
        "unparsed_files": sorted(set(discovered) - parsed),
        "finding_count": len(findings),
        "findings": findings,
        "note": "Java findings are retained only when the bounded AST model traces a recognized request source through assignments, supported collection state or a uniquely resolved helper to a recognized sink.",
        "limitations": [
            "Constant branch evaluation supports a bounded subset of literals and arithmetic/comparison expressions; unknown branches are conservatively joined.",
            "List, Map, and array tracking covers literal contents and selected add/put/get/remove/clear/set operations; aliases, custom collections, streams, iterators and complex key expressions remain incomplete.",
            "Helper calls require a unique statically named method in the scanned project and bounded call depth; overloads, dynamic dispatch, reflection, imported library behavior and receiver-state semantics are not fully modeled.",
            "The Java parser may reject newer or nonstandard language syntax; unparsed files are not counted as analyzed.",
            "No source is executed; findings are review leads, not proof of runtime reachability or exploitability.",
        ],
    }
