"""Evaluate local semantic predicates for obligation proofs; never decide generation."""
from ..semantic_discovery.models import digest, canonical
from .api_closure import APIClosureValidator, callable_status
from .evidence import HarnessContextValidator


class SemanticProofEvaluator:
    def evaluate(self, context, closure, ft, snapshot, requirements, resolutions, state):
        from .requirements import HarnessRequirementBuilder
        from .loop import expand_requirements
        allowed = {r["function_id"] for r in ft["core_functions"] + ft["support_candidates"]} | set(state.discoveries)
        errors = HarnessContextValidator().validate(context, ft, snapshot, requirements, state.evidence, allowed)
        errors += APIClosureValidator().validate(closure, ft, snapshot, requirements, resolutions, state)
        expected = HarnessRequirementBuilder().build(ft, snapshot)["requirements"]
        expand_requirements(ft, snapshot, expected, closure)
        descriptors = lambda rows: {row["requirement_id"]: {k: v for k, v in row.items() if k not in {"status", "evidence_ids", "resolution_attempt_failed"}} for row in rows}
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
        framework_satisfied = {r["requirement_id"] for r in context["framework_satisfied_requirements"]}
        def missing(fid, kind, code, rid=None, parameter=None, detail=None):
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
            if detail is not None:
                item["detail"] = detail
            if parameter is not None:
                item["subject_parameter"] = parameter
            if code == "argument_input_binding_unresolved":
                item["question"] = f"Parameter {parameter} is marked input but has no direct fuzz binding or length relation. The fuzzer receives only bytes/size, not an external context. Resolve its construction using exact declaration/body evidence and update the corresponding lifecycle contract. Unknown creator/layout remains unresolved."
            if code == 'shared_resource_identity_unresolved':
                item['question'] = (f'Correct the input_binding for exact parameter {parameter}: prove its actual '
                    'source and via API with an explicit consumer lifecycle or the certified erased callback resource '
                    'reference. Do not repair an already proved ownership fact or invent another lifecycle.')
            hard[digest(item)] = item
        for req in requirements:
            if req["status"] in {"open", "unresolved"}:
                if req["mandatory"] and req["requirement_id"] not in framework_satisfied:
                    missing(req["subject_function_id"], req["kind"], "mandatory_requirement_unresolved", req["requirement_id"])
                elif not req["mandatory"]:
                    soft.append({"requirement_id": req["requirement_id"], "kind": req["kind"], "code": "soft_unknown"})
        for fid in core:
            if callable_status(snapshot.functions[fid]) != "external_definition":
                missing(fid, "input_binding", "core_api_accessibility_unresolved")
        from .proof_grounding import contradictions, field_proofs, cleanup_checks
        source_fields = field_proofs(context, snapshot, state.evidence, closure)
        for conflict in contradictions(context, snapshot, state.evidence):
            missing(conflict["function_id"], conflict["kind"], conflict["code"], parameter=conflict["parameter"], detail=conflict.get("detail"))
        for check in cleanup_checks(context, snapshot, state.evidence):
            if check["status"] == "missing":
                missing(check["function_id"], check["kind"], check["code"], parameter=check["parameter"])
        from .repairs import fact_conflicts
        for conflict in fact_conflicts(context["facts"]):
            missing(conflict["subject_function_id"], conflict["kind"], conflict["code"], conflict["requirement_id"], conflict["subject_parameter"])
        bindings = context["input_contract"]["bindings"]
        paths = set(context["external_input_flow"]["reachable_functions"])
        for fid in core - paths:
            observed = [{key: binding.get(key) for key in
                ('parameter', 'source', 'transform', 'via_function_id', 'size_parameter')}
                for binding in bindings if binding['function_id'] == fid]
            missing(fid, "input_binding", "core_fuzz_input_path_unresolved",
                parameter=observed[0]['parameter'] if len(observed) == 1 else None,
                detail={'observed_bindings': observed,
                    'missing_contract': 'source_proven_fuzz_input_path',
                    'repair_rule': 'A context input must name its exact source-proven input feeding API or field producer and preserve the same-object byte path. A creator alone is not an input feeder. Do not turn the context into fuzz_data or default a via API; remain unresolved without the source relationship.'})
        for binding in bindings:
            parameter = next((p for p in snapshot.functions[binding["function_id"]].get("parameters", []) if p["name"] == binding["parameter"]), {})
            if (binding["source"] == "fuzz_data" and parameter.get("is_pointer")
                    and (binding["alignment"] == "unknown" or binding["binary_zero_allowed"] is None)):
                missing(binding["function_id"], "input_binding", "input_constraints_unresolved",
                    parameter=binding["parameter"], detail={"unknown_fields": [key for key in
                        ("alignment", "binary_zero_allowed") if binding.get(key) in (None, "unknown")],
                        "observed_constraints": {key: binding.get(key) for key in
                            ("alignment", "binary_zero_allowed", "mutable", "nul_terminated")}})
        arguments = context["argument_contract"]["arguments"]
        resources = context["lifecycle_contract"]["resources"]
        resource_keys = {r["resource_id"] for r in resources}
        from .input_contracts import VERSION as INPUT_VERSION
        for fid in core:
            for parameter in snapshot.functions[fid].get("parameters", []):
                if (parameter.get("is_struct_like") or parameter.get("is_opaque_handle")) and not any(
                        r["function_id"] == fid and r["subject_parameter"] == parameter["name"] for r in resources):
                    missing(fid, "lifecycle", "context_lifecycle_unresolved")
        for fid in callable_ids:
            function = snapshot.functions[fid]
            canonical_parameters = {r["parameter"]:r for r in context["canonical_construction"]["parameters"] if r["function_id"]==fid}
            for parameter in function.get("parameters", []):
                selection=canonical_parameters.get(parameter["name"])
                if selection is None or selection["status"]!="resolved":
                    missing(fid,"argument_construction", "construction_contract_conflict" if selection and selection["status"]=="conflict"
                        else "canonical_construction_unresolved", parameter=parameter["name"])
            values = {a["parameter"]: a for a in arguments if a["function_id"] == fid}
            for parameter in function.get("parameters", []):
                name = parameter["name"]
                argument = values.get(name)
                if not argument or argument["construction"] == "unknown":
                    missing(fid, "argument_construction", "argument_construction_unresolved")
                    continue
                if argument["construction"] == "input" and not any(b["function_id"] == fid and (
                    b["parameter"] == name and (b["source"] == "fuzz_data" or b.get('derived_by') == INPUT_VERSION) or b["size_parameter"] == name) for b in bindings):
                    missing(fid, "argument_construction", "argument_input_binding_unresolved", parameter=name)
                    if any(r["function_id"] == fid and r["subject_parameter"] == name and r["creation"]["kind"] == "input" for r in resources):
                        missing(fid, "lifecycle", "input_resource_without_binding", parameter=name)
                lifetimes = [r for r in resources if r["function_id"] == fid and r["subject_parameter"] == name]
                if argument["construction"] in {"stack", "zero_init"} and lifetimes and any(r["creation"]["kind"] != "stack" for r in lifetimes):
                    missing(fid, "lifecycle", "argument_resource_creation_mismatch")
                callback_stub = argument["construction"] == "callback" and argument["api"] is None and any(
                    c["function_id"] == fid and c["parameter"] == name and c.get("declaration_identity") for c in context["callback_contract"]["callbacks"])
                if argument["construction"] in {"creator_api", "callback"} and argument["api"] not in callable_ids and not callback_stub:
                    missing(fid, "argument_construction", "required_argument_api_unresolved")
                if argument["resource_id"] is not None and argument["resource_id"] not in resource_keys:
                    missing(fid, "lifecycle", "argument_resource_lifecycle_unresolved")
                if parameter.get("is_opaque_handle") and argument["construction"] in {"stack", "zero_init"}:
                    missing(fid, "argument_construction", "opaque_layout_unresolved")
        owned = context["ownership_contract"]["entries"]
        for fid in callable_ids:
            function = snapshot.functions[fid]
            entries = [entry for entry in owned if entry["function_id"] == fid]
            for parameter in [p["name"] for p in function.get("parameters", []) if p.get("is_pointer")]:
                if not any(e["parameter"] == parameter and not e["return_value"] and e["field"] is None
                        and e.get('subject_kind', 'PointerParameter') == 'PointerParameter' for e in entries):
                    missing(fid, "ownership", "parameter_ownership_unresolved")
            from .proposals import ownership_subjects
            for subject in ownership_subjects(fid, snapshot):
                if subject['subject_kind'] == 'OutParameterPointee' and not any(
                        e.get('subject_kind') == 'OutParameterPointee' and e['parameter'] == subject['parameter'] for e in entries):
                    missing(fid, 'ownership', 'out_pointee_ownership_unresolved')
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
            from .callbacks import field_initialization_complete
            field_setup = precondition["kind"] == "initialized" and precondition["api"] is None and field_initialization_complete(context, precondition, snapshot)
            if precondition["kind"] == "unknown" or precondition["kind"] != "none" and precondition["api"] not in callable_ids and not field_setup:
                missing(precondition["function_id"], "state", "state_precondition_unresolved",
                    parameter=precondition['parameter'], detail={
                        'observed_kind': precondition['kind'], 'observed_api': precondition['api'],
                        'missing_contract': 'state_kind' if precondition['kind'] == 'unknown' else 'source_proven_state_api_or_field_effect',
                        'repair_rule': 'Prove the exact precondition on this parameter and the API or field effect that establishes it on the same object. For input_fed identify the actual input feeder, not an allocator/creator. Do not default an API or discard the precondition when evidence is missing.'})
        for req in requirements:
            if req["kind"] != "state" or not req["mandatory"]:
                continue
            for parameter in snapshot.functions[req["subject_function_id"]].get("parameters", []):
                if (parameter.get("is_struct_like") or parameter.get("is_opaque_handle")) and not any(
                        row["function_id"] == req["subject_function_id"] and row["parameter"] == parameter["name"]
                        for row in context["state_contract"]["preconditions"]):
                    missing(req["subject_function_id"], "state", "state_precondition_unresolved", parameter=parameter["name"])
        for gap in closure["unresolved_api_dependencies"]:
            if gap["mandatory"]:
                rid = gap.get("requirement_id") or next(iter(gap.get("requirement_ids", [])), None)
                req = next((r for r in requirements if r["requirement_id"] == rid), None)
                missing(req["subject_function_id"] if req else ft["anchor_function_id"], req["kind"] if req else "lifecycle",
                        "required_api_unresolved", rid)
            else:
                soft.append({"function_id": gap.get("function_id"), "code": "optional_api_unknown"})
        links = context["buffer_length_contract"]["links"]
        for diagnostic in context['input_length_binding']['diagnostics']:
            missing(diagnostic['function_id'], 'buffer_length', diagnostic['code'], parameter=diagnostic['buffer_parameter'])
        for fid in core:
            function = snapshot.functions[fid]
            pointer_names = {p["name"] for p in function.get("parameters", []) if p.get("is_pointer")}
            for binding in [b for b in bindings if b["function_id"] == fid and b["source"] == "fuzz_data" and b["parameter"] in pointer_names]:
                if binding["transform"] == "nul_terminate" and binding["size_parameter"] is None and binding.get("input_kind") != "nul_terminated_string":
                    missing(fid, "input_binding", "nul_string_semantics_unproven")
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
            if callback["mandatory"] and not callback.get("declaration_identity"):
                missing(callback["function_id"], "callback", "callback_declaration_identity_unresolved")
            if callback["userdata"] and not callback.get("userdata_binding", {}).get("source_verified"):
                missing(callback["function_id"], "callback", "callback_userdata_relationship_unresolved")
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
        graph = context["ordering_graph"]
        edges = {(row["before"], row["after"]) for row in graph["edges"] if row["strength"] == "hard"}
        reach = set(edges)
        for _ in range(len(callable_ids)):
            reach |= {(a, c) for a, b in reach for b2, c in reach if b == b2}
        if any(a == b for a, b in reach):
            errors.append({"code": "contradictory_call_order_cycle", "cycle_edges": graph["hard_cycles"]})
        for edge in graph["soft_cycle_edges"]:
            if edge["strength"] == "soft":
                soft.append({"code": "soft_order_cycle_ignored", "edge": edge})
        for item in context["resource_identity"]["unresolved"]:
            if item["reason"] in {"multiple_runtime_origins", "creator_invocation_multiplicity"} and item["function_id"] in callable_ids:
                missing(item["function_id"], "lifecycle", "resource_identity_multiple_origins")
        for binding in bindings:
            if binding["source"] != "context" or not binding["via_function_id"]:
                continue
            consumer = {r["resource_id"] for r in resources if r["function_id"] == binding["function_id"] and r["subject_parameter"] == binding["parameter"]}
            producer = {r["resource_id"] for r in resources if r["function_id"] == binding["via_function_id"]}
            if len(consumer) != 1 or not consumer <= producer:
                from .callback_resources import prove_callback_resource_reference
                proof = prove_callback_resource_reference(context, binding, snapshot, state.evidence)
                retained = [p for p in context.get('callback_resource_references', [])
                    if p['function_id'] == binding['function_id'] and p['parameter'] == binding['parameter']]
                if proof is None or retained != [proof]:
                    missing(binding['function_id'], 'input_binding', 'shared_resource_identity_unresolved',
                            parameter=binding['parameter'])
        for support in closure["required_support_apis"]:
            for parent in support["required_by"]:
                for reason in support["reasons"]:
                    pair = (parent, support["function_id"]) if reason == "cleanup" else (support["function_id"], parent)
                    callback_binding = reason == 'callback' and any(d['function_id'] == support['function_id']
                        and d['via_function_id'] == parent for d in context['argument_graph'].get('callback_dispatches',[]))
                    if reason in {"creation", "initialization", "cleanup", "callback", "allocator"} and pair not in reach and not callback_binding:
                        missing(parent, "call_order", "required_support_order_unresolved")
        for precondition in context["state_contract"]["preconditions"]:
            if precondition["kind"] in {"initialized", "input_fed", "reset"} and precondition["api"] is not None and precondition["api"] != precondition["function_id"]:
                if (precondition["api"], precondition["function_id"]) not in reach:
                    missing(precondition["function_id"], "call_order", "state_precondition_order_unresolved")
        for obligation in context["invocation_contract"]["preconditions"]:
            if obligation["source"] != "lifecycle_initialization":
                continue
            before, after = obligation["api"], obligation["function_id"]
            if obligation["phase"] == "before_call" and before == after:
                missing(after, "lifecycle", "self_initialization_obligation_unresolved", parameter=obligation["parameter"])
            if before is not None and before != after and (before, after) not in reach:
                missing(after, "call_order", "invocation_initialization_order_unresolved", parameter=obligation["parameter"])
        hard_rows = sorted(hard.values(), key=canonical)
        graph = context.get("argument_graph", {})
        holes = graph.get("dependency_graph", {}).get("unresolved_parameters", [])
        for item in hard_rows:
            matching = [hole for hole in holes if hole["function_id"] == item["subject_function_id"]
                and (item.get("subject_parameter") is None or hole["parameter"] == item["subject_parameter"])]
            if item["kind"] in {"argument_construction", "lifecycle", "ownership", "state", "input_binding"}:
                item["graph_holes"] = matching
                if matching:
                    item["question"] += " Target graph holes: " + canonical(matching)
        return {"failures": hard_rows, "soft_unknowns": sorted(soft, key=canonical),
            "source_field_proofs": source_fields,
            "validation_errors": sorted(errors, key=canonical),
            "framework_satisfied_requirements": sorted(framework_satisfied),
            "argument_graph_version": graph.get("version"),
            "graph_failure_taxonomy": sorted({hole["code"] for hole in holes} |
                {row["code"] for row in graph.get("diagnostics", [])})}
