"""Bounded AST details for evidence acquisition, never semantic proof.

Queries inspect one authorized function. Field receivers, guards and argument
expressions retain their source spelling; candidates are function references,
not resolved callback targets, resource identities or lifecycle effects.
"""
import re
from bisect import bisect_right

from ..semantic_discovery.tools import _walk, _text
from .value_flow import body_tree

VERSION = "bounded-source-detail-queries-v3"
DETAIL_LIMIT = 512
CONTEXT_LIMIT = 6


def compact(text):
    return re.sub(r"\s+", "", text)


class SourceDetails:
    def __init__(self, snapshot, fid):
        self.snapshot, self.function = snapshot, snapshot.functions[fid]
        self.source, self.body = body_tree(self.function)
        if not self.function.get("defined") or self.body is None or self.body.has_error:
            raise ValueError("source_details_require_parseable_definition")
        self.nodes = list(_walk(self.body))
        # py-tree-sitter 0.26.0 Point.row returns a borrowed PyLong. Accessing
        # node.start_point.row can destroy its temporary Point before using the
        # integer, corrupting the heap for non-immortal rows. Stay on byte
        # offsets; this also retains exact UTF-8 and CRLF line coordinates.
        self.line_starts = [0] + [i + 1 for i, byte in enumerate(self.source) if byte == 10]
        self.first_line = self.function["end_line"] - self.function["body"].count("\n")
        self.shadows = {p["name"] for p in self.function.get("parameters", [])}
        self.local_shadows = set()
        for node in self.nodes:
            if node.type != "declaration":
                continue
            for declarator in node.named_children:
                if declarator.type == "init_declarator":
                    declarator = declarator.child_by_field_name("declarator")
                if declarator.type in {"identifier", "pointer_declarator", "array_declarator",
                                       "function_declarator", "parenthesized_declarator"}:
                    declared_names = {_text(n, self.source) for n in _walk(declarator)
                                      if n.type == "identifier"}
                    self.shadows.update(declared_names)
                    self.local_shadows.update(declared_names)

    def text(self, node):
        return _text(node, self.source) if node is not None else ""

    def line(self, offset):
        return self.first_line + bisect_right(self.line_starts, offset) - 1

    def candidates(self, node):
        while node is not None and node.type in {"parenthesized_expression", "pointer_expression"}:
            if node.type == "pointer_expression" and not self.text(node).lstrip().startswith("&"):
                return []
            node = node.named_children[-1] if len(node.named_children) == 1 else None
        if node is None or node.type != "identifier" or self.text(node) in self.shadows:
            return []
        name = self.text(node)
        matches = [f for f in self.snapshot.functions.values() if f["name"] == name and f.get("defined")]
        local = [f for f in matches if f["file"] == self.function["file"]]
        return sorted(f["id"] for f in (local if len(local) == 1 else matches))

    def callback_userdata_feedback(self, limit):
        """Exact callback argument spelling, never a resource/lifetime proof."""
        from .callbacks import callback_declarations
        declarations = callback_declarations(self.function, self.snapshot)
        parameters = {p["name"] for p in self.function.get("parameters", [])}
        rows = []
        for declaration in declarations:
            owner = declaration["parameter"]
            if owner in self.local_shadows:
                continue
            callee = owner
            if declaration.get("field"):
                callee += "." + declaration.get("field_path", declaration["field"])
            for node in self.nodes:
                if node.type != "call_expression" or compact(self.text(node.child_by_field_name("function"))).replace("->", ".") != callee:
                    continue
                arguments = node.child_by_field_name("arguments")
                for position, argument in enumerate(arguments.named_children):
                    types = declaration["parameter_types"]
                    if position >= len(types) or compact(types[position]) not in {"void*", "constvoid*"}:
                        continue
                    identity = compact(self.text(argument)).replace("->", ".")
                    source_parameter = identity.split(".", 1)[0]
                    if (argument.type not in {"identifier", "field_expression"}
                            or source_parameter not in parameters or source_parameter in self.local_shadows):
                        continue
                    row = {"callback_parameter": owner, "callback_field": declaration.get("field"),
                           "callee_expression": callee, "argument_index": position,
                           "userdata_identity": identity,
                           "userdata_parameter": identity if argument.type == "identifier" else None,
                           "line": self.line(node.start_byte), "syntactic_only": True}
                    if row not in rows:
                        rows.append(row)
        return {"candidates": rows[:limit], "truncated": len(rows) > limit,
                "rule": "Use exact source parameter/member identity for callback userdata, not a resource ID. These callback-argument spellings do not prove aliasing, resource ownership, release or lifetime; ambiguous or missing relationships remain unresolved."}

    def contexts(self, node):
        contexts = []
        child, parent = node, node.parent
        while parent is not None and parent != self.body:
            kind = parent.type
            item = None
            if kind == "if_statement":
                condition = parent.child_by_field_name("condition")
                if child == parent.child_by_field_name("consequence"):
                    item = {"kind": "if", "branch": "then", "condition": self.text(condition)}
                elif child == parent.child_by_field_name("alternative"):
                    item = {"kind": "if", "branch": "else", "condition": self.text(condition)}
            elif kind == "conditional_expression":
                item = {"kind": "conditional_expression", "condition": self.text(parent.child_by_field_name("condition")),
                        "branch": "then" if child == parent.child_by_field_name("consequence") else
                                  "else" if child == parent.child_by_field_name("alternative") else "condition"}
            elif kind == "binary_expression" and child == parent.child_by_field_name("right"):
                operator = self.text(parent.child_by_field_name("operator"))
                if operator in {"&&", "||"}:
                    item = {"kind": "short_circuit", "operator": operator,
                            "condition": self.text(parent.child_by_field_name("left"))}
            elif kind in {"while_statement", "for_statement", "do_statement", "switch_statement"}:
                item = {"kind": kind.removesuffix("_statement"),
                        "condition": self.text(parent.child_by_field_name("condition"))}
            elif kind == "case_statement":
                item = {"kind": "case", "value": self.text(parent.child_by_field_name("value")) or "default"}
            elif kind.startswith("preproc_"):
                item = {"kind": "preprocessor", "condition": self.text(parent.child_by_field_name("condition"))}
            if item:
                item["line"] = self.line(parent.start_byte)
                contexts.append(item)
            child, parent = parent, parent.parent
        return list(reversed(contexts))

    def record(self, node, **details):
        content = self.text(node)
        contexts = self.contexts(node)
        truncated = len(contexts) > CONTEXT_LIMIT or any(len(str(v)) > DETAIL_LIMIT
            for item in contexts for v in item.values())
        contexts = [{k: v[:DETAIL_LIMIT] if isinstance(v, str) else v for k, v in c.items()}
                    for c in contexts[-CONTEXT_LIMIT:]]
        return {"function_id": self.function["id"], "function": self.function["name"],
                "source": self.function["file"], "line_start": self.line(node.start_byte),
                "line_end": self.line(node.end_byte), "content": content,
                "origin": "phase1_syntactic_detail", "syntactic_only": True,
                "control_context": contexts, "control_context_kind": "lexical_ancestors_only",
                "control_context_truncated": truncated, **details}

    def calls(self, callee, limit):
        matches = []
        for node in self.nodes:
            if node.type != "call_expression":
                continue
            target = node.child_by_field_name("function")
            text = self.text(target)
            leaf = self.text(target.child_by_field_name("field")) if target.type == "field_expression" else text
            if callee != "*" and compact(callee) not in {compact(text), compact(leaf)}:
                continue
            matches.append((node, target))
        records = []
        for node, target in matches[:limit]:
            arguments = node.child_by_field_name("arguments").named_children
            candidates = self.candidates(target)
            direct = target.type == "identifier" and self.text(target) not in self.shadows
            expressions = [self.text(arg) for arg in arguments]
            records.append(self.record(node, callee_expression=self.text(target)[:DETAIL_LIMIT],
                dispatch_kind="direct_syntax" if direct else "indirect_syntax",
                argument_expressions=[a[:DETAIL_LIMIT] for a in expressions[:16]],
                arguments_truncated=len(expressions) > 16 or any(len(a) > DETAIL_LIMIT for a in expressions),
                possible_callee_ids=candidates[:limit], target_candidates_truncated=len(candidates) > limit))
        return records, len(matches)

    def writes(self, field, limit):
        matches = []
        for node in self.nodes:
            if node.type == "assignment_expression":
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                if left.type != "field_expression":
                    continue
                leaf = self.text(left.child_by_field_name("field"))
                receiver = self.text(left.child_by_field_name("argument"))
                operator = self.text(node.child_by_field_name("operator"))
            elif node.type == "initializer_pair":
                designator = node.child_by_field_name("designator")
                if designator is None or designator.type != "field_designator":
                    continue
                left, right = designator, node.child_by_field_name("value")
                leaf = self.text(designator).lstrip(".")
                owner = node.parent
                while owner is not None and owner.type != "init_declarator":
                    owner = owner.parent
                receiver = self.text(owner.child_by_field_name("declarator")) if owner else ""
                operator = "designated_initializer"
            else:
                continue
            if compact(field) not in {compact(self.text(left)), compact(leaf)}:
                continue
            matches.append((node, right, receiver, leaf, operator))
        records = []
        for node, right, receiver, leaf, operator in matches[:limit]:
            candidates = self.candidates(right) if operator in {"=", "designated_initializer"} else []
            records.append(self.record(node, receiver_expression=receiver[:DETAIL_LIMIT], field=leaf[:DETAIL_LIMIT],
                assigned_expression=self.text(right)[:DETAIL_LIMIT], operator=operator,
                expressions_truncated=any(len(t) > DETAIL_LIMIT for t in (receiver, leaf, self.text(right))),
                possible_callee_ids=candidates[:limit], target_candidates_truncated=len(candidates) > limit))
        return records, len(matches)

    def at_line(self, line):
        if not self.first_line <= line <= self.function["end_line"]:
            raise ValueError("line_outside_authorized_body")
        statements = [n for n in self.nodes if n.type in {"declaration", "case_statement"}
            or n.type.endswith("_statement") and n.type != "compound_statement"]
        containing = [n for n in statements if self.line(n.start_byte) <= line
                      <= self.line(n.end_byte)]
        if not containing:
            return [], 0
        node = min(containing, key=lambda n: (n.end_byte - n.start_byte, n.start_byte))
        return [self.record(node, statement_kind=node.type)], 1
