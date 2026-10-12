"""Ordered Strategy IR checks. Structural acceptance never grants semantic proof."""
from __future__ import annotations

from copy import deepcopy
import re

from ..harness_context.api_closure import callable_status
from ..harness_context.evidence import record_functions
from ..harness_context.resource_identity import allocated_export_proof, allocated_return
from ..harness_context.value_flow import body_tree, complete_bodies
from ..semantic_discovery.models import canonical
from ..semantic_discovery.tools import _text, _walk
from .models import StrategyBudget, validate_proposal
from .normalization import normalize_strategy


_INTEGERS = frozenset({"char", "signed char", "unsigned char", "short", "short int",
    "unsigned short", "unsigned short int", "int", "unsigned", "unsigned int", "long",
    "long int", "unsigned long", "unsigned long int", "long long", "long long int",
    "unsigned long long", "unsigned long long int", "size_t", "ssize_t", "ptrdiff_t",
    "bool", "_Bool", "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t",
    "uint32_t", "uint64_t", "intptr_t", "uintptr_t"})
_BYTES = frozenset({"char", "signed char", "unsigned char", "uint8_t", "int8_t"})
_FIXED_WIDTHS = {"char": 1, "signed char": 1, "unsigned char": 1, "int8_t": 1, "uint8_t": 1,
    "int16_t": 2, "uint16_t": 2, "int32_t": 4, "uint32_t": 4, "int64_t": 8, "uint64_t": 8}


def _base(value):
    return " ".join(re.sub(r"\b(const|volatile|restrict|struct|enum|union)\b|\*", "", value or "").split())


def _may_export_fresh_out(function, parameter, snapshot, bodies):
    """Recognize a known allocation on an out-success path, never award proof.

    All-path export proof intentionally rejects creators whose failure path
    leaves the out slot untouched. That rejection cannot justify calling their
    successful allocation borrowed or dropping its proposed cleanup.
    """
    if allocated_export_proof(function, snapshot, bodies, parameter=parameter):
        return True
    if function["id"] not in bodies:
        return False
    from ..harness_context.proof_grounding import analyze
    source, body = body_tree(function)
    if body is None or body.has_error:
        return False
    allocation_names = {name for name in ("malloc", "calloc") if not any(
        f["name"] == name and f.get("defined") for f in snapshot.functions.values())}
    origins = {"local:" + function["id"] + ":" + str(n.start_byte) for n in _walk(body)
        if n.type == "call_expression" and _text(n.child_by_field_name("function"), source) in allocation_names}
    summary = analyze(function, snapshot, bodies)
    return any(path["outputs"].get("parameter:" + parameter) in origins for path in summary["paths"])


class StrategyValidator:
    """Validate one normalized proposal using this run's issued source records.

    Input paths describe possible links in the submitted strategy. Transfers
    through a callee or shared state remain pending source semantics; this class
    cannot turn a hypothesis, a matching type, or a score into a certificate.
    """

    def __init__(self, ft, snapshot, evidence, authorized_ids, *, budget=None):
        self.ft, self.snapshot = ft, snapshot
        self.evidence = evidence if isinstance(evidence, dict) else {
            r["evidence_id"]: r for r in evidence if isinstance(r, dict) and "evidence_id" in r}
        if "records" in self.evidence:
            self.evidence = {r["evidence_id"]: r for r in self.evidence["records"]
                if isinstance(r, dict) and "evidence_id" in r}
        self.authorized = set(authorized_ids) - set(ft.get("excluded_functions", []))
        self.budget = budget or StrategyBudget()

    def validate(self, strategy):
        errors, pending, input_paths = [], [], []

        def fail(code, step_id="", detail=""):
            row = {"code": code, "step_id": step_id, "detail": str(detail)}
            if row not in errors:
                errors.append(row)

        def question(kind, subject_id, detail):
            row = {"kind": kind, "subject_id": subject_id, "detail": detail, "source_proven": False}
            if row not in pending:
                pending.append(row)

        def report(metrics=None):
            return {"valid": not errors, "status": "invalid" if errors else "structurally_valid",
                "errors": errors, "pending_semantic_checks": pending, "input_paths": input_paths,
                "metrics": metrics or {}, "generation_allowed": False}

        if not isinstance(strategy, dict):
            fail("invalid_strategy_schema", detail="strategy must be an object")
            return report()
        proposal = {key: strategy.get(key) for key in ("steps", "hypotheses", "open_questions")}
        try:
            validate_proposal(proposal, self.budget)
        except (ValueError, TypeError, KeyError) as exc:
            fail("invalid_strategy_schema", detail=str(exc))
            return report()
        expected = normalize_strategy(proposal, self.ft, self.snapshot, budget=self.budget)
        identity_fields = ("ft_id", "ft_digest", "source_fingerprint", "functions_fingerprint",
            "anchor_function_id", "core_function_ids")
        for key in identity_fields:
            if strategy.get(key) != expected.get(key):
                fail("strategy_identity_mismatch", detail=key)
        if canonical(strategy) != canonical(expected):
            fail("strategy_envelope_mismatch", detail="normalized envelope, digest or resource origins differ")
        if strategy.get("generation_allowed") is not False:
            fail("strategy_authority_claim", detail="proposals cannot allow harness generation")

        steps = proposal["steps"]
        for field, rows in (("step_id", steps), ("value_id", [s for s in steps if "value_id" in s]),
                ("hypothesis_id", proposal["hypotheses"])):
            identities = [row[field] for row in rows]
            if len(identities) != len(set(identities)):
                fail("duplicate_strategy_identity", detail=field)
        if errors:
            return report()
        all_steps = {s["step_id"]: s for s in steps}
        all_values = {s["value_id"] for s in steps if "value_id" in s}
        hypotheses = {h["hypothesis_id"]: h for h in proposal["hypotheses"]}
        resources = {r["value_id"]: r for r in expected["resources"]}
        parameter_subjects = {prefix + ":" + parameter for s in steps if s["kind"] in {"call", "cleanup"}
            for prefix in (s["step_id"], s["function_id"]) for parameter in s["arguments"]}
        known_types = set(_INTEGERS) | {"void", "float", "double", "long double"}
        for function in self.snapshot.functions.values():
            known_types.add(_base(function.get("return_base_type", function.get("return_type"))))
            known_types.update(_base(p.get("base_type", p.get("type"))) for p in function.get("parameters", []))
        for struct in self.snapshot.artifacts.structs:
            known_types.add(_base(struct["name"]))
            known_types.update(_base(a) for a in struct.get("aliases", []))

        for hypothesis in hypotheses.values():
            subject = hypothesis["subject_id"]
            if subject not in all_steps and subject not in all_values and subject not in self.authorized and subject not in parameter_subjects:
                fail("unknown_hypothesis_subject", detail=subject)
            for eid in hypothesis["evidence_ids"]:
                if eid not in self.evidence:
                    fail("unissued_strategy_evidence", detail=eid)
            question("hypothesis:" + hypothesis["kind"], subject, hypothesis["description"])

        values, calls, guards, origins = {}, {}, {}, set()
        slot_writers, slot_captures = {}, {}
        consumed, captured_calls, captured_out, core_calls = {}, set(), set(), []
        body_records = complete_bodies(self.snapshot, self.evidence)
        fresh_values = set()
        cited_eids = set()
        supported_steps = 0
        path_projection_truncated = False

        def bounded_paths(paths):
            nonlocal path_projection_truncated
            unique = {canonical(path): path for path in paths}
            ordered = sorted(unique.values(), key=lambda path: (path["source"] != "fuzz_bytes", canonical(path)))
            limit = min(128, max(2, self.budget.max_steps * 2))
            if len(ordered) > limit:
                path_projection_truncated = True
            return ordered[:limit]

        def provenance(step, function_id=None, type_name=None):
            nonlocal supported_steps
            valid_hypotheses = []
            subjects = {step["step_id"], step.get("value_id"), step.get("resource_value_id"), function_id}
            if "arguments" in step:
                subjects.update(prefix + ":" + parameter for prefix in (step["step_id"], function_id or "")
                    for parameter in step["arguments"])
            for hid in step["hypothesis_ids"]:
                hypothesis = hypotheses.get(hid)
                if hypothesis is None:
                    fail("unknown_strategy_hypothesis", step["step_id"], hid)
                elif hypothesis["subject_id"] not in subjects:
                    fail("unrelated_strategy_hypothesis", step["step_id"], hid)
                else:
                    valid_hypotheses.append(hypothesis)
            relevant = False
            for eid in step["evidence_ids"]:
                record = self.evidence.get(eid)
                if record is None:
                    fail("unissued_strategy_evidence", step["step_id"], eid)
                    continue
                cited_eids.add(eid)
                if function_id and function_id in record_functions(record, self.snapshot):
                    relevant = True
                elif type_name and _base(type_name) in {
                        _base(record.get("type", "")), _base(record.get("name", "")),
                        *(_base(a) for a in record.get("aliases", []))}:
                    relevant = True
                elif type_name and record.get("tool") == "get_function" and _base(type_name) in {
                        _base(record.get("return_type", "")),
                        *(_base(p.get("base_type", p.get("type"))) for p in record.get("parameters", []))}:
                    relevant = True
                elif not function_id and not type_name:
                    relevant = True
            if relevant:
                supported_steps += 1
            elif not valid_hypotheses:
                fail("ungrounded_strategy_choice", step["step_id"], "cite relevant issued evidence or an explicit hypothesis")
            return valid_hypotheses

        def get_value(value_id, step_id, guard_ids=None):
            value = values.get(value_id)
            if value is None:
                fail("forward_or_unknown_value", step_id, value_id)
                return {"type": "", "depth": -1, "paths": [], "guards": set(), "storage": "unknown"}
            if value_id in consumed:
                fail("use_after_cleanup", step_id, value_id)
            if guard_ids is not None and not value["guards"] <= set(guard_ids):
                fail("missing_creation_guard", step_id, value_id)
            return value

        def expression(expr, step, guard_ids):
            kind, sid = expr["kind"], step["step_id"]
            if kind == "fuzz_bytes":
                return {"type": "unsigned char", "depth": 1, "paths": [{"source": "fuzz_bytes", "steps": []}], "readonly": True}
            if kind == "fuzz_size":
                return {"type": "size_t", "depth": 0, "paths": [{"source": "fuzz_size", "steps": []}]}
            if kind == "integer":
                return {"type": "int", "depth": 0, "paths": []}
            if kind == "null":
                return {"type": "void", "depth": 1, "paths": [], "null": True}
            if kind == "source_function":
                fid = expr["function_id"]
                function = self.snapshot.functions.get(fid)
                if fid not in self.authorized:
                    fail("strategy_callback_not_authorized", sid, fid)
                if function is None:
                    fail("strategy_callback_unknown", sid, fid)
                elif callable_status(function) != "external_definition":
                    fail("strategy_callback_not_callable", sid, fid)
                cited_eids.update(expr["evidence_ids"])
                if not set(expr["evidence_ids"]) & set(body_records.get(fid, [])):
                    fail("strategy_callback_complete_source_not_cited", sid, fid)
                for eid in expr["evidence_ids"]:
                    if eid not in self.evidence or fid not in record_functions(self.evidence[eid], self.snapshot):
                        fail("strategy_callback_evidence_unrelated_or_unissued", sid, eid)
                question("callback_signature_and_userdata_lifetime", sid + ":" + fid,
                         "The exact source function prototype and synchronous userdata lifetime need live Clang/source verification")
                return {"type": "source_function", "depth": 1, "paths": [], "callback_function_id": fid}
            value = get_value(expr["value_id"], sid, guard_ids)
            if kind == "length":
                producer = all_steps.get(resources.get(expr["value_id"], {}).get("introduced_by"), {})
                if producer.get("kind") != "transform_input" or producer.get("operation") == "decode_integer":
                    fail("length_requires_input_buffer", sid, expr["value_id"])
                if expr["include_terminator"] and producer.get("operation") != "nul_terminate":
                    fail("length_terminator_unavailable", sid, expr["value_id"])
                return {"type": "size_t", "depth": 0, "paths": [{"source": "fuzz_size", "steps": [producer.get("step_id", "")]}]}
            result = deepcopy(value)
            if kind == "value" and value["storage"] == "out_slot":
                fail("out_slot_requires_capture", sid, expr["value_id"])
            if kind == "value" and value.get("known_zero") and value["depth"] > 0:
                result["null"] = True
            if kind == "address":
                if value["storage"] not in {"zeroed", "out_slot"}:
                    fail("address_requires_constructed_storage", sid, expr["value_id"])
                result["depth"] += 1
                result.pop("known_zero", None)
            return result

        def call_step(step):
            sid, fid = step["step_id"], step["function_id"]
            function = self.snapshot.functions.get(fid)
            provenance(step, fid)
            if fid not in self.authorized:
                fail("strategy_api_not_authorized", sid, fid)
            if function is None:
                fail("strategy_api_unknown", sid, fid)
                return None, {}, []
            if callable_status(function) != "external_definition":
                fail("strategy_api_not_callable", sid, fid)
            guard_ids = set(step["guard_ids"])
            for gid in guard_ids:
                if gid not in guards:
                    fail("forward_or_unknown_guard", sid, gid)
                elif not guards[gid]["guards"] <= guard_ids:
                    fail("missing_guard_prerequisite", sid, gid)
            lower, upper, status_constraints = 0, self.budget.max_input_bytes, {}
            for gid in guard_ids:
                condition = guards.get(gid, {}).get("condition", {})
                if condition.get("kind") == "size":
                    lower, upper = max(lower, condition["minimum"]), min(upper, condition["maximum"])
                elif condition.get("kind") == "status":
                    status_constraints.setdefault(condition["value_id"], set()).add(condition["comparison"])
                if condition.get("kind") in {"nonnull", "status"} and values.get(condition.get("value_id"), {}).get("known_zero") and (
                        condition["kind"] == "nonnull" or condition.get("comparison") == "nonzero"):
                    fail("incompatible_call_guards", sid, "a selected predicate is false for known zeroed storage")
            if lower > upper or any(len(choices) > 1 for choices in status_constraints.values()):
                fail("incompatible_call_guards", sid, "the selected guard conjunction is unreachable")
            parameters = {p["name"]: p for p in function.get("parameters", [])}
            if set(step["arguments"]) != set(parameters):
                fail("strategy_parameter_mismatch", sid, "argument names must match the indexed signature")
            evaluated = {name: expression(expr, step, guard_ids) for name, expr in step["arguments"].items()}
            paths = []
            for name, actual in evaluated.items():
                parameter = parameters.get(name)
                if parameter is None:
                    continue
                base = _base(parameter.get("base_type", parameter.get("type")))
                depth = parameter.get("pointer_depth", int(parameter.get("is_pointer", False)))
                compatible = depth == actual["depth"] and (
                    base == actual["type"] or depth == 0 and base in _INTEGERS and actual["type"] in _INTEGERS
                    or depth == 1 and (base == "void" or actual["type"] == "void"
                        or base in _BYTES and actual["type"] in _BYTES))
                if actual.get("callback_function_id"):
                    # Source function references have their own Clang ABI check.
                    # Pointer depth never grants callback compatibility.
                    from ..source_analysis.callback_compatibility import is_callback_parameter
                    compatible = is_callback_parameter(self.snapshot, parameter)
                if actual.get("null"):
                    compatible = depth > 0
                    source_inspected = bool(set(step["evidence_ids"]) & set(body_records.get(fid, [])))
                    null_hypothesis = any(hypotheses.get(hid, {}).get("kind") == "nullability" and
                        hypotheses[hid]["subject_id"] in {sid, fid, sid + ":" + name, fid + ":" + name}
                        for hid in step["hypothesis_ids"])
                    if not source_inspected and not null_hypothesis:
                        fail("null_requires_source_or_nullability_hypothesis", sid, name)
                    question("nullability", sid + ":" + name, "NULL admissibility requires source semantics")
                if not compatible:
                    fail("strategy_argument_type_mismatch", sid, name)
                if actual.get("readonly") and depth and not parameter.get("is_const", "const" in parameter.get("type", "")):
                    fail("mutable_parameter_requires_copy", sid, name)
                for path in actual["paths"]:
                    paths.append({**path, "steps": [*path["steps"], sid], "parameter": name})
            return function, evaluated, bounded_paths(paths)

        for step in steps:
            sid, kind = step["step_id"], step["kind"]
            if kind in {"construct", "transform_input"}:
                provenance(step, type_name=step["type_name"])
                base = _base(step["type_name"])
                if base not in known_types or base == "void":
                    fail("strategy_type_unknown", sid, step["type_name"])
                resource = resources[step["value_id"]]
                if kind == "transform_input":
                    if (step["operation"] == "decode_integer" and step["width"] == 0
                            or step["operation"] != "decode_integer" and step["width"] != 0):
                        fail("invalid_transform_width", sid, step["width"])
                    if step["operation"] == "decode_integer" and base not in _INTEGERS:
                        fail("decode_requires_integer_type", sid, base)
                    if step["operation"] == "decode_integer" and base in _FIXED_WIDTHS and step["width"] > _FIXED_WIDTHS[base]:
                        fail("decode_width_exceeds_type", sid, base)
                    elif step["operation"] == "decode_integer" and base not in _FIXED_WIDTHS:
                        question("integer_representation", step["value_id"], "Decode width must fit the target ABI; signed decoding also requires a defined representation")
                    if step["operation"] != "decode_integer" and base not in _BYTES:
                        fail("copy_requires_byte_type", sid, base)
                    paths = [{"source": "fuzz_bytes", "steps": [sid]}]
                else:
                    paths = []
                    if step["storage"] == "out_slot" and step["pointer_depth"] < 1:
                        fail("out_slot_requires_pointer_storage", sid, step["value_id"])
                    question("construction", step["value_id"], "Storage initialization does not prove an API state precondition")
                values[step["value_id"]] = {"type": base, "depth": resource["pointer_depth"], "paths": paths,
                    "guards": set(), "storage": resource["storage"]}
                if kind == "construct" and (step["pointer_depth"] > 0 or base in _INTEGERS):
                    values[step["value_id"]]["known_zero"] = True
            elif kind == "call":
                function, evaluated, paths = call_step(step)
                calls[sid] = {"step": step, "function": function, "evaluated": evaluated, "paths": paths}
                if function:
                    # Passing an address may overwrite local storage. Its
                    # initial zero is no longer a known constant after this
                    # unknown effect; captured results retain explicit origins.
                    for argument in step["arguments"].values():
                        if argument["kind"] == "address" and argument["value_id"] in values:
                            values[argument["value_id"]].pop("known_zero", None)
                    written_slots = []
                    for parameter in function.get("parameters", []):
                        argument = step["arguments"].get(parameter["name"], {})
                        if parameter.get("pointer_depth", 0) < 2 or argument.get("kind") != "address":
                            continue
                        slot = argument["value_id"]
                        if values.get(slot, {}).get("storage") != "out_slot":
                            continue
                        if slot in written_slots:
                            fail("aliased_out_parameters", sid, slot)
                        written_slots.append(slot)
                        if slot in slot_writers:
                            previous = slot_writers[slot]
                            captured = slot_captures.get((previous, slot))
                            if captured is None or captured not in consumed:
                                fail("out_slot_overwrite_without_cleanup", sid, slot)
                        slot_writers[slot] = sid
                    question("call_preconditions", sid, "Signature compatibility does not prove call preconditions")
                    if function["id"] in {r["function_id"] for r in self.ft["core_functions"]}:
                        core_calls.append(sid)
                    # Possible writes into shared storage are a strategy graph
                    # edge only. Phase 3 must prove the exact source transfer.
                    if paths:
                        for name, expr in step["arguments"].items():
                            if expr["kind"] in {"value", "address"} and evaluated[name]["depth"] > 0:
                                value = values.get(expr["value_id"])
                                if value is not None:
                                    value["paths"] = bounded_paths([*value["paths"], *deepcopy(paths)])
                                    question("input_to_shared_state", expr["value_id"], "Argument-to-state transfer is proposed, not source proven")
            elif kind == "capture":
                call = calls.get(step["call_step_id"])
                fid = call["step"]["function_id"] if call else None
                provenance(step, fid)
                if call is None or call["function"] is None:
                    fail("forward_or_unknown_call", sid, step["call_step_id"])
                    continue
                function, resource = call["function"], resources[step["value_id"]]
                origin = canonical(resource["origin"])
                if origin in origins:
                    fail("duplicate_resource_origin", sid, step["value_id"])
                origins.add(origin)
                base, depth = _base(resource["type_name"]), resource["pointer_depth"]
                if step["source"] == "return":
                    if step["parameter"]:
                        fail("return_capture_parameter_must_be_empty", sid, step["parameter"])
                    if base == "void" and depth == 0:
                        fail("capture_void_return", sid, fid)
                    captured_calls.add(step["call_step_id"])
                    if depth > 0 and allocated_return(function, self.snapshot):
                        fresh_values.add(step["value_id"])
                else:
                    captured_out.add((step["call_step_id"], step["parameter"]))
                    parameter = next((p for p in function.get("parameters", []) if p["name"] == step["parameter"]), None)
                    argument = call["step"]["arguments"].get(step["parameter"], {})
                    if parameter is None or parameter.get("pointer_depth", 0) < 2 or argument.get("kind") != "address":
                        fail("invalid_out_pointee_capture", sid, step["parameter"])
                    elif values.get(argument["value_id"], {}).get("storage") != "out_slot":
                        fail("out_capture_requires_out_slot", sid, argument["value_id"])
                    else:
                        slot = argument["value_id"]
                        if slot_writers.get(slot) != step["call_step_id"]:
                            fail("out_capture_origin_overwritten", sid, slot)
                        slot_captures[(step["call_step_id"], slot)] = step["value_id"]
                    if _may_export_fresh_out(function, step["parameter"], self.snapshot, body_records):
                        fresh_values.add(step["value_id"])
                    question("out_parameter_write", step["value_id"], "Creator must establish the out value on the selected status path")
                values[step["value_id"]] = {"type": base, "depth": depth, "paths": deepcopy(call["paths"]),
                    "guards": set(call["step"]["guard_ids"]), "storage": "captured"}
                if call["paths"]:
                    question("input_to_captured_value", step["value_id"], "Argument-to-result transfer requires source semantics")
                if depth > 0:
                    question("ownership", step["value_id"], "Export ownership and lifetime require source semantics")
            elif kind == "guard":
                condition = step["condition"]
                subject_resource = resources.get(condition.get("value_id"), {})
                provenance(step, subject_resource.get("origin", {}).get("function_id") or
                    (self.ft["anchor_function_id"] if condition["kind"] == "size" else None),
                    subject_resource.get("type_name"))
                dependencies = set()
                if condition["kind"] != "size":
                    value = get_value(condition["value_id"], sid)
                    dependencies = value["guards"]
                    if condition["kind"] == "nonnull" and value["depth"] <= 0:
                        fail("nonnull_guard_requires_pointer", sid, condition["value_id"])
                    if condition["kind"] == "status" and (value["depth"] != 0 or value["type"] not in _INTEGERS):
                        fail("status_guard_requires_integer", sid, condition["value_id"])
                elif condition["minimum"] > condition["maximum"]:
                    fail("invalid_size_guard_range", sid, "minimum exceeds maximum")
                guards[sid] = {"condition": condition, "guards": dependencies}
                question("guard_semantics", sid, "Predicate shape does not prove that this is the API success condition")
            elif kind == "cleanup":
                function, evaluated, paths = call_step(step)
                target = step["resource_value_id"]
                resource = resources.get(target)
                value = get_value(target, sid, step["guard_ids"])
                if resource is None or value["depth"] <= 0 or resource["storage"] != "captured":
                    fail("cleanup_requires_captured_resource", sid, target)
                if not any(expr["kind"] == "value" and expr.get("value_id") == target for expr in step["arguments"].values()):
                    fail("cleanup_resource_mismatch", sid, target)
                if target in consumed:
                    fail("double_cleanup", sid, target)
                consumed[target] = sid
                question("cleanup_consumption", sid, "The exact parameter must release this origin on the selected path")

        anchor_id = self.ft["anchor_function_id"]
        called_ids = {calls[sid]["step"]["function_id"] for sid in core_calls}
        for row in self.ft["core_functions"]:
            if row["function_id"] not in called_ids:
                fail("strategy_core_not_called", detail=row["function_id"])
        anchor_calls = [sid for sid in core_calls if calls[sid]["step"]["function_id"] == anchor_id]
        if not anchor_calls:
            fail("strategy_anchor_not_called", detail=anchor_id)
        for sid in anchor_calls:
            paths = calls[sid]["paths"]
            input_paths.extend({"core_call_step_id": sid, "core_function_id": calls[sid]["step"]["function_id"],
                **path, "source_proven": False} for path in paths)
        if not any(path["source"] == "fuzz_bytes" for path in input_paths):
            fail("strategy_input_does_not_reach_anchor", detail="An unrelated call or length alone cannot establish the fuzz byte path")

        for value_id, value in values.items():
            resource = resources[value_id]
            if resource["origin"]["kind"] not in {"return", "out_pointee"} or value["depth"] <= 0:
                continue
            ownership_hypothesis = any(h["kind"] == "ownership" and h["subject_id"] == value_id
                for h in hypotheses.values())
            if value_id not in consumed and (value_id in fresh_values or not ownership_hypothesis):
                fail("resource_cleanup_missing", resource["introduced_by"], value_id)
            if value_id not in consumed and ownership_hypothesis:
                question("borrowed_export_unverified", value_id, "Cleanup omission depends on an explicit unresolved ownership hypothesis")
        for sid, call in calls.items():
            function = call["function"]
            if function and function.get("return_pointer_depth", 0) > 0 and allocated_return(function, self.snapshot) and sid not in captured_calls:
                fail("fresh_return_not_captured", sid, function["id"])
            if function:
                for parameter in function.get("parameters", []):
                    if parameter.get("pointer_depth", 0) >= 2 and (sid, parameter["name"]) not in captured_out and _may_export_fresh_out(
                            function, parameter["name"], self.snapshot, body_records):
                        fail("fresh_out_value_not_captured", sid, parameter["name"])

        pending.extend({"kind": "open_question", "subject_id": "", "detail": value, "source_proven": False}
            for value in proposal["open_questions"])
        metrics = {"step_count": len(steps), "resource_count": len(resources), "core_call_count": len(core_calls),
            "cited_evidence_count": len(cited_eids), "evidence_supported_steps": supported_steps,
            "hypothesis_count": len(hypotheses), "pending_semantic_count": len(pending),
            "input_path_count": len(input_paths), "source_proven_input_paths": 0,
            "input_path_projection_truncated": path_projection_truncated}
        return report(metrics)
