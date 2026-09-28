"""Deterministic hard/soft missing checks. Model confidence is not a gate."""
from ..semantic_discovery.models import digest, canonical
from .api_closure import APIClosureValidator, callable_status
from .evidence import HarnessContextValidator
from .models import POLICY_VERSION


class HarnessContextCompletenessValidator:
    def validate(self, context, closure, ft, snapshot, requirements, resolutions, state):
        from .requirements import HarnessRequirementBuilder
        from .loop import expand_requirements
        allowed = {r["function_id"] for r in ft["core_functions"] + ft["support_candidates"]} | set(state.discoveries)
        errors = HarnessContextValidator().validate(context, ft, snapshot, requirements, state.evidence, allowed)
        errors += APIClosureValidator().validate(closure, ft, snapshot, requirements, resolutions, state)
        expected = HarnessRequirementBuilder().build(ft, snapshot)["requirements"]
        expand_requirements(ft, snapshot, expected, closure)
        descriptors = lambda rows: {row["requirement_id"]: {k: v for k, v in row.items() if k not in {"status", "evidence_ids"}} for row in rows}
        if descriptors(requirements) != descriptors(expected) or len(requirements) != len(descriptors(requirements)):
            errors.append({"code": "requirement_universe_changed"})
        for req in requirements:
            result = resolutions.get(req["requirement_id"])
            if req["status"] not in {"open", "unresolved", "resolved", "not_applicable"} or (
                    req["status"] != "open" and (not result or result["status"] != req["status"])):
                errors.append({"code": "requirement_status_without_validated_resolution"})
            if result and req["evidence_ids"] != sorted({eid for fact in result["facts"] for eid in fact["evidence_ids"]}):
                errors.append({"code": "requirement_evidence_projection_mismatch"})
        if context["dependencies"] != closure["unresolved_api_dependencies"]:
            errors.append({"code": "context_dependency_projection_mismatch"})
        core = set(context["core_apis"])
        callable_ids = core | {r["function_id"] for r in closure["required_support_apis"]}
        hard, soft = {}, []
        reqs = {(r["subject_function_id"], r["kind"]): r for r in requirements}
        def missing(fid, kind, code, rid=None):
            req = reqs.get((fid, kind))
            if req is None and kind == "lifecycle":
                # A consumed SUPPORT parameter references its caller's resource.
                # Fix its existing construction/ownership contract rather than
                # emitting an unaddressable task or recursively creating it.
                fallback = "argument_construction" if code.startswith("argument_") else "ownership"
                req = reqs.get((fid, fallback))
                if req is not None:
                    kind = fallback
            rid = rid or (req["requirement_id"] if req else None)
            item = {"requirement_id": rid, "subject_function_id": fid, "kind": kind, "code": code,
                    "question": req["question"] if req else "Resolve this explicit missing contract."}
            hard[digest(item)] = item
        for req in requirements:
            if req["status"] in {"open", "unresolved"}:
                if req["mandatory"]:
                    missing(req["subject_function_id"], req["kind"], "mandatory_requirement_unresolved", req["requirement_id"])
                else:
                    soft.append({"requirement_id": req["requirement_id"], "kind": req["kind"], "code": "soft_unknown"})
        for fid in core:
            if callable_status(snapshot.functions[fid]) != "external_definition":
                missing(fid, "input_binding", "core_api_accessibility_unresolved")
        bindings = context["input_contract"]["bindings"]
        paths = {b["function_id"] for b in bindings if b["source"] == "fuzz_data" and b["parameter"] is not None}
        for _ in range(len(core)):
            paths |= {b["function_id"] for b in bindings if b["source"] in {"context", "derived"} and b["via_function_id"] in paths}
        for fid in core - paths:
            missing(fid, "input_binding", "core_fuzz_input_path_unresolved")
        for binding in bindings:
            parameter = next((p for p in snapshot.functions[binding["function_id"]].get("parameters", []) if p["name"] == binding["parameter"]), {})
            if (binding["source"] == "fuzz_data" and parameter.get("is_pointer")
                    and (binding["alignment"] == "unknown" or binding["binary_zero_allowed"] is None)):
                missing(binding["function_id"], "input_binding", "input_constraints_unresolved")
        arguments = context["argument_contract"]["arguments"]
        resources = context["lifecycle_contract"]["resources"]
        resource_keys = {r["resource_id"] for r in resources}
        for fid in core:
            for parameter in snapshot.functions[fid].get("parameters", []):
                if (parameter.get("is_struct_like") or parameter.get("is_opaque_handle")) and not any(
                        r["function_id"] == fid and r["subject_parameter"] == parameter["name"] for r in resources):
                    missing(fid, "lifecycle", "context_lifecycle_unresolved")
        for fid in callable_ids:
            function = snapshot.functions[fid]
            values = {a["parameter"]: a for a in arguments if a["function_id"] == fid}
            for parameter in function.get("parameters", []):
                name = parameter["name"]
                argument = values.get(name)
                if not argument or argument["construction"] == "unknown":
                    missing(fid, "argument_construction", "argument_construction_unresolved")
                    continue
                if argument["construction"] in {"creator_api", "callback"} and argument["api"] not in callable_ids:
                    missing(fid, "argument_construction", "required_argument_api_unresolved")
                if (argument["resource_id"] is not None and argument["resource_id"] not in resource_keys
                        and (parameter.get("is_struct_like") or parameter.get("is_opaque_handle")
                             or argument["construction"] not in {"input", "derived"})):
                    missing(fid, "lifecycle", "argument_resource_lifecycle_unresolved")
                if parameter.get("is_opaque_handle") and argument["construction"] in {"stack", "zero_init"}:
                    missing(fid, "argument_construction", "opaque_layout_unresolved")
        owned = context["ownership_contract"]["entries"]
        for fid in callable_ids:
            function = snapshot.functions[fid]
            entries = [entry for entry in owned if entry["function_id"] == fid]
            for parameter in [p["name"] for p in function.get("parameters", []) if p.get("is_pointer")]:
                if not any(e["parameter"] == parameter and not e["return_value"] and e["field"] is None for e in entries):
                    missing(fid, "ownership", "parameter_ownership_unresolved")
            if function.get("return_pointer_depth", 0) and not any(e["return_value"] for e in entries):
                missing(fid, "ownership", "return_ownership_unresolved")
        for entry in owned:
            if entry["ownership"] == "unknown" or entry["lifetime"] == "unknown":
                missing(entry["function_id"], "ownership", "ownership_unresolved")
            if entry["ownership"] == "owned" and entry["release_api"] not in callable_ids:
                missing(entry["function_id"], "lifecycle", "mandatory_cleanup_unresolved")
            if entry["return_value"] and entry["ownership"] == "owned" and entry["resource_id"] not in resource_keys:
                missing(entry["function_id"], "lifecycle", "owned_return_lifecycle_unresolved")
        for resource in resources:
            fid = resource["function_id"]
            if resource["creation"]["kind"] == "unknown" or resource["reuse"] == "unknown":
                missing(fid, "lifecycle", "resource_creation_unresolved")
            if resource["creation"]["kind"] == "creator_api" and resource["creation"]["api"] not in callable_ids:
                missing(fid, "lifecycle", "creator_api_unresolved")
            for action, code in (("initialization", "required_context_initialization_unresolved"), ("cleanup", "mandatory_cleanup_unresolved")):
                if resource[action]["mandatory"] and resource[action]["api"] not in callable_ids:
                    missing(fid, "lifecycle", code)
        for precondition in context["state_contract"]["preconditions"]:
            if precondition["kind"] == "unknown" or precondition["kind"] != "none" and precondition["api"] not in callable_ids:
                missing(precondition["function_id"], "state", "state_precondition_unresolved")
        for gap in closure["unresolved_api_dependencies"]:
            if gap["mandatory"]:
                rid = gap.get("requirement_id") or next(iter(gap.get("requirement_ids", [])), None)
                req = next((r for r in requirements if r["requirement_id"] == rid), None)
                missing(req["subject_function_id"] if req else ft["anchor_function_id"], req["kind"] if req else "lifecycle",
                        "required_api_unresolved", rid)
            else:
                soft.append({"function_id": gap.get("function_id"), "code": "optional_api_unknown"})
        links = context["buffer_length_contract"]["links"]
        for fid in core:
            function = snapshot.functions[fid]
            pointer_names = {p["name"] for p in function.get("parameters", []) if p.get("is_pointer")}
            for binding in [b for b in bindings if b["function_id"] == fid and b["source"] == "fuzz_data" and b["parameter"] in pointer_names]:
                matching = [link for link in links if link["function_id"] == fid and link["buffer_parameter"] == binding["parameter"]]
                if not matching or any(link["relation"] == "unknown" or link["binary_zero_allowed"] is None for link in matching):
                    missing(fid, "buffer_length", "length_relation_unresolved")
                elif not any(link["length_parameter"] == binding["size_parameter"] and (
                    link["relation"] == binding["size_relation"] or link["relation"] in {"capacity", "derived"})
                    and link["requires_nul_termination"] == binding["nul_terminated"] for link in matching):
                    missing(fid, "buffer_length", "binding_length_contract_mismatch")
        for callback in context["callback_contract"]["callbacks"]:
            if callback["mandatory"] and (not callback["signature"] or callback["lifetime"] == "unknown"
                    or callback["null_allowed"] is None or callback["setup_api"] is not None and callback["setup_api"] not in callable_ids):
                missing(callback["function_id"], "callback", "mandatory_callback_abi_unresolved")
        for req in requirements:
            if req["kind"] == "callback" and not any(row["function_id"] == req["subject_function_id"] for row in context["callback_contract"]["callbacks"]):
                missing(req["subject_function_id"], "callback", "callback_contract_unresolved")
        returns = context["return_contract"]["functions"]
        for fid in callable_ids:
            function = snapshot.functions[fid]
            if function.get("return_type", "void").strip() == "void":
                continue
            matching = [row for row in returns if row["function_id"] == fid]
            if not matching or any(row["success"] == "unknown" or function.get("return_pointer_depth", 0)
                    and any(row[key] is None for key in ("nullable", "owned", "error_cleanup")) for row in matching):
                missing(fid, "return_semantics", "return_semantics_unresolved")
            if matching and any(row["owned"] is True for row in matching) and not any(e["function_id"] == fid and e["return_value"] and e["ownership"] == "owned" for e in owned):
                missing(fid, "ownership", "owned_return_contract_mismatch")
        constraints = context["ordering_contract"]["constraints"]
        edges = {(row["before"], row["after"]) if row["kind"] == "must_precede" else (row["after"], row["before"])
                 for row in constraints if row["kind"] in {"must_precede", "must_follow"} and row["after"] is not None}
        reach = set(edges)
        for _ in range(len(callable_ids)):
            reach |= {(a, c) for a, b in reach for b2, c in reach if b == b2}
        if any(a == b for a, b in reach):
            errors.append({"code": "contradictory_call_order_cycle"})
        for support in closure["required_support_apis"]:
            for parent in support["required_by"]:
                for reason in support["reasons"]:
                    pair = (parent, support["function_id"]) if reason == "cleanup" else (support["function_id"], parent)
                    if reason in {"creation", "initialization", "cleanup", "callback", "allocator"} and pair not in reach:
                        missing(parent, "call_order", "required_support_order_unresolved")
        for precondition in context["state_contract"]["preconditions"]:
            if precondition["kind"] in {"initialized", "input_fed", "reset"} and precondition["api"] is not None and precondition["api"] != precondition["function_id"]:
                if (precondition["api"], precondition["function_id"]) not in reach:
                    missing(precondition["function_id"], "call_order", "state_precondition_order_unresolved")
        hard_rows = sorted(hard.values(), key=canonical)
        hard_kinds = {row["kind"] for row in hard_rows}
        return {"schema_version": 1, "artifact_kind": "harness_context_completeness", "policy_version": POLICY_VERSION,
            "ft_id": ft["ft_id"], "status": "invalid" if errors else "incomplete" if hard_rows else "complete",
            "generation_allowed": not errors and not hard_rows, "hard_missing": hard_rows,
            "soft_unknowns": sorted(soft, key=canonical), "validation_errors": errors,
            "resolved_requirements": sorted(r["requirement_id"] for r in requirements if r["status"] in {"resolved", "not_applicable"}),
            "unresolved_requirements": sorted(r["requirement_id"] for r in requirements if r["status"] in {"open", "unresolved"}),
            "api_closure_complete": not any(row["code"] == "required_api_unresolved" for row in hard_rows) and not errors,
            "lifecycle_complete": "lifecycle" not in hard_kinds and not errors,
            "input_binding_complete": not {"input_binding", "buffer_length"} & hard_kinds and not errors,
            "ownership_complete": "ownership" not in hard_kinds and not errors,
            "ordering_sufficient": "call_order" not in hard_kinds and not errors,
            "callback_complete": "callback" not in hard_kinds and not errors}


CompletenessValidator = HarnessContextCompletenessValidator


def missing_requirement_tasks(report):
    return [{"task_id": "task_" + digest(row)[:24], **row} for row in report["hard_missing"]]
