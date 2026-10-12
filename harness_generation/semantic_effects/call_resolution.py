"""Bounded, strategy-scoped function-pointer field binding observations.

These records prove a target binding, not an allocation/release contract.  Only
issued complete function bodies and authenticated, issued declarations are
examined. Unsupported control flow and intervening unknown calls invalidate
bindings. No signature or familiar hook name is itself a release proof.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_c

from ..harness_context.callbacks import exact_signature, function_callback_abi
from ..harness_context.evidence import callback_abis
from ..harness_context.value_flow import body_tree, complete_bodies, unique_callee
from ..semantic_discovery.models import canonical, digest
from ..semantic_discovery.tools import _text, _walk
from ..source_paths import SourcePathResolver
from ..source_snapshot import authenticated_c_source
from .conditions import evaluate_condition, scalar_value, source_precondition, strategy_conditions

VERSION = "strategy-call-resolution-v1.1-source-parameter"
_INTRINSIC_SIGNATURES = {
    "free": "void free(void *pointer)",
    "malloc": "void *malloc(size_t size)",
    "calloc": "void *calloc(size_t count, size_t size)",
    "realloc": "void *realloc(void *pointer, size_t size)",
}


def _records(evidence):
    if isinstance(evidence, dict) and "records" not in evidence:
        return evidence
    records = evidence.get("records", []) if isinstance(evidence, dict) else evidence
    return {r["evidence_id"]: r for r in records if isinstance(r, dict) and "evidence_id" in r}


def _authenticated_records(snapshot, evidence):
    """Reject relabelled/modified records before any body or ABI observation."""
    authenticated = {}
    for eid, record in _records(evidence).items():
        if not isinstance(record, dict):
            continue
        raw = {key: value for key, value in record.items() if key != "evidence_id"}
        try:
            expected_eid = "ev_" + digest({"snapshot": snapshot.source_fingerprint, "record": raw})[:32]
        except (ValueError, TypeError):
            continue
        source_hash = snapshot.artifacts.source_hashes.get(record.get("source"))
        if (record.get("evidence_id") == eid == expected_eid and source_hash
                and record.get("source_sha256") == source_hash):
            authenticated[eid] = record
    return authenticated


@dataclass
class _State:
    bindings: dict = field(default_factory=dict)
    env: dict = field(default_factory=dict)
    conditions: list = field(default_factory=list)
    reasons: set = field(default_factory=set)
    ended: bool = False


class _Resolver:
    def __init__(self, strategy, snapshot, evidence, max_depth, max_paths, project_root=None, authorized_ids=None):
        self.strategy, self.snapshot = strategy, snapshot
        self.evidence = _authenticated_records(snapshot, evidence)
        self.authorized = set(snapshot.functions) if authorized_ids is None else set(authorized_ids)
        self.bodies = {fid: eids for fid, eids in complete_bodies(snapshot, self.evidence).items()
            if fid in self.authorized}
        self.max_depth, self.max_paths = max_depth, max_paths
        self.project_root = Path(project_root).resolve() if project_root is not None else None
        self.rows, self.tables, self.global_names, self.macros = [], {}, set(), set()
        self.declarations, self.initializers, self.file_cache = [], {}, {}
        self.step_id = ""
        self.step_conditions = []
        self._declarations()

    def _owned_source(self, record):
        filename = record.get("source")
        expected = self.snapshot.artifacts.source_hashes.get(filename)
        if (record.get("tool") != "read_source_range" or record.get("truncated")
                or record.get("origin") != "owned_live_source" or not expected
                or record.get("source_sha256") != expected):
            return None
        # Raw hash labels alone cannot authenticate arbitrary supplied content.
        # Only compare the already-issued range; do not analyze hidden bytes.
        if filename not in self.file_cache:
            try:
                project = self.project_root or Path(self.snapshot.artifacts.project)
                if not project.is_absolute():
                    return None
                path = SourcePathResolver(project).resolve(filename)
                with path.open("rb") as stream:
                    data = stream.read(2 * 1024 * 1024 + 1)
                self.file_cache[filename] = (authenticated_c_source(self.snapshot.artifacts, filename, data)
                    if len(data) <= 2 * 1024 * 1024 else None)
            except (ValueError, OSError, UnicodeError):
                self.file_cache[filename] = None
        text = self.file_cache[filename]
        start, end = record.get("line_start"), record.get("line_end")
        if (text is None or type(start) is not int or type(end) is not int or start < 1 or end < start
                or "".join(text.splitlines(keepends=True)[start - 1:end]) != record.get("content")):
            return None
        return record["content"].encode()

    def _declarations(self):
        parser = Parser(Language(tree_sitter_c.language()))
        type_evidence = {}
        for struct in self.snapshot.artifacts.structs:
            eids = {eid for eid, record in self.evidence.items()
                if record.get("tool") == "get_type_definition" and not record.get("truncated")
                and record.get("source") == struct["file"]
                and struct["declaration"] in record.get("content", "")}
            if eids:
                type_evidence[(struct["file"], struct["name"])] = eids
        for eid, record in sorted(self.evidence.items()):
            source = self._owned_source(record)
            if source is None:
                continue
            root = parser.parse(source).root_node
            if root.has_error:
                continue
            filename = record["source"]
            for node in _walk(root):
                if node.type in {"preproc_def", "preproc_function_def"}:
                    name = node.child_by_field_name("name")
                    if name is not None:
                        self.macros.add((filename, _text(name, source)))
            for struct in self.snapshot.artifacts.structs:
                if struct["file"] == filename and struct["declaration"] in record["content"]:
                    type_evidence.setdefault((filename, struct["name"]), set()).add(eid)
            # Only translation-unit declarations, never locals or preprocessor
            # alternatives, can initialize a global field binding.
            for declaration in root.named_children:
                if declaration.type != "declaration":
                    continue
                self.declarations.append((filename, declaration, source, eid))
                for item in declaration.named_children:
                    decl = item.child_by_field_name("declarator") if item.type == "init_declarator" else item
                    if decl and decl.type == "identifier":
                        self.global_names.add((filename, _text(decl, source)))
        for filename, declaration, source, eid in self.declarations:
            dtype = declaration.child_by_field_name("type")
            if dtype is None:
                continue
            type_name = _text(dtype, source)
            structs = [s for s in self.snapshot.artifacts.structs
                if type_name in {s["name"], *s.get("aliases", [])}]
            local = [s for s in structs if s["file"] == filename]
            structs = local if len(local) == 1 else structs
            if len(structs) != 1:
                continue
            struct = structs[0]
            witnesses = type_evidence.get((struct["file"], struct["name"]), set())
            if not witnesses:
                continue
            struct_source = struct["declaration"].encode()
            struct_root = parser.parse(struct_source).root_node
            fields = []
            for node in _walk(struct_root):
                if node.type != "field_declaration":
                    continue
                names = [n for n in _walk(node.child_by_field_name("declarator"))
                    if n.type == "field_identifier"] if node.child_by_field_name("declarator") else []
                if len(names) != 1:
                    fields.append((None, None))
                    continue
                signature = exact_signature(_text(node, struct_source), self.snapshot.artifacts.callback_typedefs)
                fields.append((_text(names[0], struct_source), signature))
            for item in declaration.named_children:
                value = item.child_by_field_name("value") if item.type == "init_declarator" else None
                decl = item.child_by_field_name("declarator") if item.type == "init_declarator" else item
                if decl is None or decl.type != "identifier":
                    continue
                owner = _text(decl, source)
                for name, signature in fields:
                    if name and signature:
                        self.tables[(filename, owner, name)] = {
                            "abi": callback_abis(signature["signature"]), "evidence_ids": sorted(witnesses | {eid})}
                if value is None or value.type != "initializer_list":
                    continue
                for position, entry in enumerate(value.named_children):
                    if entry.type == "initializer_pair":
                        designator = entry.child_by_field_name("designator")
                        names = [n for n in _walk(designator) if n.type == "field_identifier"] if designator else []
                        name = _text(names[0], source) if len(names) == 1 else None
                        initial = entry.child_by_field_name("value")
                    else:
                        name = fields[position][0] if position < len(fields) else None
                        initial = entry
                    key = (filename, owner, name)
                    if key in self.tables:
                        target = self._target(initial, source, {"file": filename}, {})
                        binding = self._binding(target, witnesses | {eid}, "__initial_state__", [])
                        previous = self.initializers.get(key)
                        if previous and previous["targets"] != binding["targets"]:
                            binding["known"] = False
                            binding["reasons"] = ["ambiguous_global_initializer"]
                            binding["targets"] = sorted(set(previous["targets"] + binding["targets"]))
                        self.initializers[key] = binding

    def _target(self, node, source, function, env):
        if node is None:
            return None
        if node.type == "parenthesized_expression" and len(node.named_children) == 1:
            return self._target(node.named_children[0], source, function, env)
        if node.type == "pointer_expression" and _text(node, source).strip().startswith("&"):
            return self._target(node.named_children[-1], source, function, env)
        if node.type != "identifier":
            return None
        name = _text(node, source)
        if (name in env or (function["file"], name) in self.global_names
                or any(macro_name == name for _, macro_name in self.macros)):
            return None
        callee = unique_callee(self.snapshot, name, function)
        if callee:
            return callee["id"] if callee["id"] in self.bodies else None
        if any(f["name"] == name and f.get("defined") for f in self.snapshot.functions.values()):
            return None
        if name in _INTRINSIC_SIGNATURES and any(f["name"] == name and
                function_callback_abi(f["signature"]) != function_callback_abi(_INTRINSIC_SIGNATURES[name])
                for f in self.snapshot.functions.values()):
            return None
        return "intrinsic:" + name if name in _INTRINSIC_SIGNATURES else None

    @staticmethod
    def _binding(target, evidence_ids, after_step, source_functions):
        return {"targets": [target] if target else [], "known": target is not None,
            "evidence_ids": sorted(evidence_ids), "after_step_id": after_step,
            "source_function_ids": sorted(source_functions),
            "reasons": [] if target else ["unknown_function_pointer_value"]}

    def _field(self, node, source, function, env):
        if node is None or node.type != "field_expression":
            return None, None
        argument, member = node.child_by_field_name("argument"), node.child_by_field_name("field")
        if argument is None or member is None or argument.type != "identifier":
            return None, None
        owner, name = _text(argument, source), _text(member, source)
        if any(macro_name in {owner, name} for _, macro_name in self.macros):
            return None, None
        if owner in env:
            return None, {"kind": "field", "base": {"kind": "parameter", "name": owner}, "path": [name]}
        return (function["file"], owner, name), {
            "kind": "field", "base": {"kind": "global", "name": owner, "source": function["file"]}, "path": [name]}

    @staticmethod
    def _invalidate(state, reason, key=None):
        keys = [key] if key is not None else list(state.bindings)
        for identity in keys:
            if identity not in state.bindings:
                state.bindings[identity] = _Resolver._binding(None, (), "", ())
            state.bindings[identity]["known"] = False
            state.bindings[identity]["reasons"] = sorted(set(state.bindings[identity]["reasons"]) | {reason})
        state.reasons.add(reason)

    def _abi(self, key, target):
        table = self.tables.get(key)
        if not table:
            return False, "callback_abi_unavailable"
        if target.startswith("intrinsic:"):
            signature = _INTRINSIC_SIGNATURES.get(target.removeprefix("intrinsic:"))
        else:
            signature = self.snapshot.functions[target]["signature"]
        return (True, "") if signature and table["abi"] == function_callback_abi(signature) else (
            False, "callback_abi_mismatch")

    def _record_call(self, node, source, body, function, state, invocation):
        target = node.child_by_field_name("function")
        key, subject = self._field(target, source, function, state.env)
        parameter_binding = None
        if target is not None and target.type == "identifier":
            name = _text(target, source)
            actual = state.env.get(name)
            if isinstance(actual, dict) and set(actual) == {"source_callback"} and any(
                    parameter["name"] == name for parameter in function.get("parameters", [])):
                parameter_binding = actual["source_callback"]
                subject = {"kind": "parameter", "name": name}
        binding = parameter_binding or state.bindings.get(key, self._binding(None, (), "", ()))
        reasons = set(binding["reasons"])
        known = binding["known"] and len(binding["targets"]) == 1
        table_evidence = self.tables.get(key, {}).get("evidence_ids", [])
        if known and parameter_binding is None:
            known, reason = self._abi(key, binding["targets"][0])
            if reason:
                reasons.add(reason)
        if state.reasons & {"unsupported_control_flow", "recursion_limit", "call_resolution_path_limit"}:
            known = False
            reasons.update(state.reasons)
        targets = binding["targets"]
        conditions = deepcopy([*state.conditions, *self.step_conditions])
        if subject and targets and len(targets) == 1:
            conditions.extend([
                {"kind": "function_target", "subject": deepcopy(subject), "target": targets[0]},
                {"kind": "unchanged_state", "subject": deepcopy(subject),
                    "after_step_id": binding["after_step_id"], "before_step_id": self.step_id},
            ])
        row = {"function_id": function["id"], "call_site": {"function_id": function["id"],
            "offset": node.start_byte - body.start_byte, "callee_expression": _text(target, source)},
            "invocation": {"strategy_id": self.strategy.get("strategy_id"), "step_id": self.step_id,
                "invocation_sites": list(invocation)}, "subject": subject,
            "targets": targets, "resolution_status": "exact" if known else "unknown",
            "modality": "may" if state.reasons & {"unknown_branch_condition", "unknown_strategy_guard"} else "must",
            "preconditions": sorted({canonical(c): c for c in conditions}.values(), key=canonical),
            "evidence_ids": sorted(set(self.bodies[function["id"]]) | set(binding["evidence_ids"]) | set(table_evidence)),
            "binding_evidence_ids": sorted(set(binding["evidence_ids"]) | set(table_evidence)),
            "source_function_ids": sorted({function["id"], *binding["source_function_ids"]}),
            "unresolved_reasons": sorted(reasons), "semantic_effect_certified": False,
            "allocator_pairing": "unverified", "source_fingerprint": self.snapshot.source_fingerprint,
            "strategy_digest": self.strategy.get("strategy_digest")}
        row["resolution_id"] = "call_resolution_" + digest(row)[:24]
        self.rows.append(row)
        # An unknown/custom indirect target may mutate the table. Exact libc
        # calls cannot assign fields of this static global object.
        if not known or not targets[0].startswith("intrinsic:"):
            self._invalidate(state, "unknown_indirect_call_mutation")

    def _expression(self, node, source, body, function, state, invocation, stack):
        if node is None:
            return [state]
        if node.type == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            key, _ = self._field(left, source, function, state.env)
            if right is not None and any(n.type in {"call_expression", "assignment_expression", "update_expression"} for n in _walk(right)):
                self._invalidate(state, "hidden_assignment_side_effect")
            if key:
                operator = _text(node.child_by_field_name("operator"), source)
                target = self._target(right, source, function, state.env) if operator == "=" else None
                state.bindings[key] = self._binding(target, self.bodies[function["id"]], self.step_id, [function["id"]])
            elif left is not None and left.type == "identifier" and _text(left, source) in state.env:
                state.env[_text(left, source)] = scalar_value(right, source, state.env)
            else:
                self._invalidate(state, "untracked_memory_write")
            return [state]
        if node.type == "call_expression":
            target = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            args = arguments.named_children if arguments else []
            if any(n.type in {"call_expression", "assignment_expression", "update_expression"} for arg in args for n in _walk(arg)):
                self._invalidate(state, "hidden_call_argument_side_effect")
            callback_binding = state.env.get(_text(target, source)) if target is not None and target.type == "identifier" else None
            if target is not None and (target.type == "field_expression" or
                    isinstance(callback_binding, dict) and set(callback_binding) == {"source_callback"}):
                self._record_call(node, source, body, function, state, invocation)
                return [state]
            if target is None or target.type != "identifier" or _text(target, source) in state.env:
                self._invalidate(state, "unknown_indirect_call_mutation")
                return [state]
            name = _text(target, source)
            # The raw indexed function is not the preprocessed callee when
            # an issued macro shares its spelling. Its expansion may mutate
            # any tracked callback table; do not reuse the raw helper body.
            if any(macro_name == name for _, macro_name in self.macros):
                self._invalidate(state, "macro_call_state_mutation")
                return [state]
            callee = unique_callee(self.snapshot, name, function)
            intrinsic = self._target(target, source, function, state.env)
            if intrinsic and intrinsic.startswith("intrinsic:"):
                return [state]
            if not callee or callee["id"] not in self.bodies or len(args) != len(callee["parameters"]):
                self._invalidate(state, "unknown_call_state_mutation")
                return [state]
            env = {p["name"]: scalar_value(arg, source, state.env) for p, arg in zip(callee["parameters"], args)}
            site = function["id"] + ":" + str(node.start_byte - body.start_byte)
            return self._function(callee, state, env, (*invocation, site), stack)
        if node.type in {"update_expression", "conditional_expression", "comma_expression"}:
            self._invalidate(state, "unsupported_expression_mutation")
        elif any(n.type in {"call_expression", "assignment_expression", "update_expression"} for n in _walk(node)):
            self._invalidate(state, "hidden_expression_side_effect")
        return [state]

    def _statement(self, node, source, body, function, state, invocation, stack):
        if state.ended:
            return [state]
        if node.type in {"compound_statement", "else_clause"}:
            declared = set()
            if node.type == "compound_statement":
                for child in node.named_children:
                    if child.type != "declaration":
                        continue
                    for item in child.named_children:
                        decl = item.child_by_field_name("declarator") if item.type == "init_declarator" else item
                        names = [n for n in _walk(decl) if n.type == "identifier"] if decl else []
                        if len(names) == 1:
                            declared.add(_text(names[0], source))
            outer = {name: value for name, value in state.env.items() if name in declared}
            states = [state]
            for child in node.named_children:
                states = [result for current in states for result in self._statement(
                    child, source, body, function, current, invocation, stack)]
                if len(states) > self.max_paths:
                    collapsed = deepcopy(states[0])
                    self._invalidate(collapsed, "call_resolution_path_limit")
                    return [collapsed]
            for current in states:
                for name in declared:
                    current.env.pop(name, None)
                current.env.update(outer)
            return states
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            truth = evaluate_condition(condition, source, state.env)
            if any(n.type in {"call_expression", "assignment_expression", "update_expression"} for n in _walk(condition)):
                self._invalidate(state, "condition_side_effect")
                truth = None
            result = []
            for expected, branch in ((True, node.child_by_field_name("consequence")), (False, node.child_by_field_name("alternative"))):
                if truth is not None and truth != expected:
                    continue
                selected = deepcopy(state)
                if truth is None:
                    selected.reasons.add("unknown_branch_condition")
                predicate = source_precondition(condition, source, function, expected=expected)
                if any(n.type == "null" for n in _walk(condition)) and "NULL" in state.env:
                    predicate = None
                if predicate:
                    selected.conditions.append(predicate)
                elif truth is None:
                    selected.reasons.add("unprojectable_source_condition")
                result.extend(self._statement(branch, source, body, function, selected, invocation, stack) if branch else [selected])
            return result
        if node.type == "expression_statement":
            return self._expression(node.named_children[0] if node.named_children else None,
                source, body, function, state, invocation, stack)
        if node.type == "return_statement":
            results = self._expression(node.named_children[0] if node.named_children else None,
                source, body, function, state, invocation, stack)
            for current in results:
                current.ended = True
            return results
        if node.type == "declaration":
            for child in node.named_children:
                if child.type == "init_declarator":
                    decl, value = child.child_by_field_name("declarator"), child.child_by_field_name("value")
                else:
                    decl, value = child, None
                names = [n for n in _walk(decl) if n.type == "identifier"] if decl else []
                if len(names) == 1:
                    state.env[_text(names[0], source)] = scalar_value(value, source, state.env)
                if value is not None and any(n.type in {"call_expression", "assignment_expression", "update_expression"} for n in _walk(value)):
                    self._invalidate(state, "declaration_side_effect")
            return [state]
        if node.type in {"comment", "empty_statement"}:
            return [state]
        self._invalidate(state, "unsupported_control_flow")
        # Diagnostic potential calls in a loop/recursive body cannot become
        # exact merely because its current table value happens to be known.
        for call in _walk(node):
            if call.type == "call_expression" and call.child_by_field_name("function").type == "field_expression":
                self._record_call(call, source, body, function, state, invocation)
        return [state]

    def _function(self, function, state, env, invocation, stack):
        fid = function["id"]
        if fid in stack or len(stack) > self.max_depth:
            self._invalidate(state, "recursion_limit")
            return [state]
        if fid not in self.bodies:
            self._invalidate(state, "function_body_not_issued")
            return [state]
        source, body = body_tree(function)
        if body is None or body.has_error:
            self._invalidate(state, "function_parse_error")
            return [state]
        prior_env, prior_conditions, prior_reasons = state.env, state.conditions, set(state.reasons)
        if any(name == "NULL" for _, name in self.macros):
            env = {**env, "NULL": None}
        state.env = env
        # Formal parameter subjects belong to a function, and the Effect IR
        # deliberately does not imply that a caller's parameter is a callee's
        # equally-spelled parameter. Nested caller guards cannot be relabelled.
        if stack:
            state.conditions = []
            if prior_conditions:
                state.reasons.add("caller_path_condition_unprojected")
        results = self._statement(body, source, body, function, state, invocation, (*stack, fid))
        for current in results:
            current.env = deepcopy(prior_env)
            current.conditions = deepcopy(prior_conditions)
            current.ended = False
            # Unknown local branch selection only affects call modality inside
            # this function; differing resulting bindings still survive paths.
            if "unknown_branch_condition" not in prior_reasons:
                current.reasons.discard("unknown_branch_condition")
        return results

    def run(self):
        states = [_State(bindings=deepcopy(self.initializers))]
        values, guards = {}, {}
        for step in self.strategy.get("steps", []):
            sid, kind = step.get("step_id"), step.get("kind")
            if kind == "construct":
                values[step["value_id"]] = 0 if step.get("pointer_depth", 0) > 0 and step.get("storage") == "zeroed" else None
            elif kind in {"capture", "transform_input"}:
                values[step["value_id"]] = None
            elif kind == "guard":
                guards[sid] = step["condition"]
            if kind not in {"call", "cleanup"}:
                continue
            self.step_id = sid
            self.step_conditions = []
            resources = {r["value_id"]: r for r in self.strategy.get("resources", [])}
            for guard in strategy_conditions(self.strategy, step):
                condition = guard["condition"]
                resource = resources.get(condition.get("value_id"))
                if resource is None:
                    continue
                subject = {"kind": "resource", "resource_id": resource["resource_id"],
                    "strategy_id": self.strategy.get("strategy_id"), "call_step_id": sid}
                if condition["kind"] == "nonnull":
                    self.step_conditions.append({"kind": "nonnull", "subject": subject})
                elif condition["kind"] == "status":
                    self.step_conditions.append({"kind": "equals_integer" if condition["comparison"] == "zero"
                        else "not_equals_integer", "subject": subject, "value": 0})
            function = self.snapshot.functions.get(step.get("function_id"))
            if function is None or function["id"] not in self.authorized:
                for state in states:
                    self._invalidate(state, "strategy_function_unavailable" if function is None
                        else "strategy_function_outside_authorized_scope")
                continue
            env = {}
            for parameter in function.get("parameters", []):
                expression = step.get("arguments", {}).get(parameter["name"], {})
                env[parameter["name"]] = (0 if expression.get("kind") == "null" else expression.get("value")
                    if expression.get("kind") == "integer" else values.get(expression.get("value_id"))
                    if expression.get("kind") == "value" else None)
                if expression.get("kind") == "source_function":
                    target_id = expression.get("function_id")
                    eids = set(expression.get("evidence_ids", []))
                    complete = set(self.bodies.get(target_id, []))
                    target = self.snapshot.functions.get(target_id, {})
                    from ..harness_context.api_closure import callable_status
                    valid = (set(expression) == {"kind", "function_id", "evidence_ids"}
                        and target_id in self.authorized and bool(eids & complete)
                        and eids <= self.evidence.keys() and callable_status(target) == "external_definition"
                        and all(target_id == self.evidence[eid].get("function_id") for eid in eids))
                    env[parameter["name"]] = {"source_callback": self._binding(target_id if valid else None,
                        eids if valid else (), sid, [function["id"], target_id] if valid else [])}
            # A conditional reset cannot initialize the skipped strategy path.
            conditional = bool(strategy_conditions(self.strategy, step))
            next_states = [deepcopy(state) for state in states] if conditional else []
            for state in states:
                current = deepcopy(state)
                if conditional:
                    current.reasons.add("unknown_strategy_guard")
                next_states.extend(self._function(function, current, env, (), ()))
            states = next_states
            if len(states) > self.max_paths:
                states = [deepcopy(states[0])]
                self._invalidate(states[0], "call_resolution_path_limit")
        return self._report()

    def _report(self):
        groups = {}
        for row in self.rows:
            key = (row["invocation"]["step_id"], row["function_id"], row["call_site"]["offset"],
                tuple(row["invocation"]["invocation_sites"]))
            groups.setdefault(key, []).append(row)
        merged = []
        for key, rows in sorted(groups.items()):
            row = deepcopy(rows[0])
            row["targets"] = sorted({target for item in rows for target in item["targets"]})
            exact = all(item["resolution_status"] == "exact" for item in rows) and len(row["targets"]) == 1
            row["resolution_status"] = "exact" if exact else "unknown"
            for field_name in ("evidence_ids", "binding_evidence_ids", "source_function_ids", "unresolved_reasons"):
                row[field_name] = sorted({value for item in rows for value in item[field_name]})
            if len(row["targets"]) > 1:
                row["unresolved_reasons"] = sorted(set(row["unresolved_reasons"]) | {"ambiguous_function_pointer_targets"})
            if any(item["modality"] == "may" for item in rows):
                row["modality"] = "may"
            # Conjunction of mutually exclusive branch predicates is invalid.
            common = set.intersection(*(set(canonical(c) for c in item["preconditions"]) for item in rows))
            row["preconditions"] = [c for c in row["preconditions"] if canonical(c) in common]
            row.pop("resolution_id", None)
            row["resolution_id"] = "call_resolution_" + digest(row)[:24]
            merged.append(row)
        return {"schema_version": 1, "policy_version": VERSION, "strategy_id": self.strategy.get("strategy_id"),
            "strategy_digest": self.strategy.get("strategy_digest"), "source_fingerprint": self.snapshot.source_fingerprint,
            "functions_fingerprint": self.snapshot.functions_fingerprint, "resolutions": merged,
            "authorized_function_ids": sorted(self.authorized),
            "analysis_budget": {"max_depth": self.max_depth, "max_paths": self.max_paths},
            "generation_allowed": False, "semantic_effect_certified": False}


def resolve_strategy_calls(strategy, snapshot, evidence, *, max_depth=2, max_paths=16, project_root=None,
                           authorized_ids=None):
    """Replay relevant global table state across a bounded selected strategy."""
    if type(max_depth) is not int or not 0 <= max_depth <= 8:
        raise ValueError("max_depth must be an integer in 0..8")
    if type(max_paths) is not int or not 1 <= max_paths <= 64:
        raise ValueError("max_paths must be an integer in 1..64")
    return _Resolver(strategy, snapshot, evidence, max_depth, max_paths, project_root, authorized_ids).run()


def discover_call_targets(function, snapshot, evidence, *, project_root=None, authorized_ids=None):
    """Report only issued source candidates; a possible target is no binding."""
    records = _authenticated_records(snapshot, evidence)
    bodies = complete_bodies(snapshot, records)
    if function["id"] not in bodies:
        return []
    if authorized_ids is not None and function["id"] not in set(authorized_ids):
        return []
    resolver = _Resolver({"steps": []}, snapshot, records, 2, 16, project_root, authorized_ids)
    source, body = body_tree(function)
    if body is None or body.has_error:
        return []
    observations = []
    for node in _walk(body):
        if node.type != "call_expression" or node.child_by_field_name("function").type != "field_expression":
            continue
        target = node.child_by_field_name("function")
        key, subject = resolver._field(target, source, function, {p["name"]: None for p in function.get("parameters", [])})
        binding = resolver.initializers.get(key, {})
        observations.append({"function_id": function["id"], "call_offset": node.start_byte - body.start_byte,
            "subject": subject, "targets": list(binding.get("targets", [])), "exact": False,
            "evidence_ids": sorted(set(bodies[function["id"]]) | set(binding.get("evidence_ids", []))),
            "blockers": ["strategy_state_not_established"], "semantic_effect_certified": False})
    return observations


class StrategyCallResolver:
    """Adapter for extractor/verifier; ambiguous invocation rows stay unknown."""
    def __init__(self, report):
        self.report = deepcopy(report)

    def resolve_call(self, function_id, call_offset, step_id=None):
        rows = [r for r in self.report["resolutions"] if r["function_id"] == function_id
            and r["call_site"]["offset"] == call_offset
            and (step_id is None or r["invocation"]["step_id"] == step_id)]
        if len(rows) != 1:
            return {"targets": sorted({t for r in rows for t in r["targets"]}), "exact": False,
                "preconditions": [], "evidence_ids": sorted({eid for r in rows for eid in r["evidence_ids"]}),
                "source_function_ids": sorted({fid for r in rows for fid in r["source_function_ids"]}),
                "blockers": ["callsite_invocation_ambiguous" if rows else "callsite_resolution_unavailable"]}
        row = rows[0]
        return {"targets": list(row["targets"]), "exact": row["resolution_status"] == "exact",
            "preconditions": deepcopy(row["preconditions"]), "evidence_ids": list(row["evidence_ids"]),
            "source_function_ids": list(row["source_function_ids"]), "blockers": list(row["unresolved_reasons"]),
            "resolution_id": row["resolution_id"], "allocator_pairing": "unverified"}
