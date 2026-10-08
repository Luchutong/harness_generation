"""Proof agendas and submission rehearsal over existing facts and tools.

This is an agent-side projection, not a certificate or a completeness decision.
Queries are suggestions within the current scope; only issued evidence proves
anything. No new tool or semantic contract is defined here.
"""
from copy import deepcopy

from ..semantic_discovery.models import canonical

VERSION = "proof-focused-investigation-v10"
COLLECTIONS = {"argument_construction": "arguments", "ownership": "entries", "lifecycle": "resources",
    "state": "preconditions", "callback": "callbacks", "input_binding": "bindings", "buffer_length": "links"}
QUESTIONS = {
    "argument_construction": "Which issued origin/recipe constructs this exact parameter, including producer arguments?",
    "ownership": "Does this exact pointer subject allocate, borrow, transfer or escape, and who releases it on which paths?",
    "lifecycle": "Which exact object is created, additionally initialized, reused and released, and is each action mandatory?",
    "state": "Which field/state does this invocation require, which API establishes it on the same object, and on which paths?",
    "callback": "Which declared callback and userdata are passed/stored, what constructs userdata, and how long can it be retained?",
    "input_binding": "Which exact input/extent path carries fuzzer bytes to this API?",
    "buffer_length": "What extent, units, bounds and NUL/binary-zero behavior match this exact buffer?",
    "return_semantics": "Which source return paths establish success, failure, nullability, ownership and error cleanup?",
    "call_order": "Which proved object/state dependency requires this order; is an apparent order only a caller preference?",
    "support_decision": "Which source effect on the exact parent subject makes this candidate necessary, optional or irrelevant?",
}


def established(kind, row):
    """Reject visibly incomplete rows; this shape check never establishes proof."""
    def unknown(value):
        if isinstance(value, dict):
            return any(unknown(v) for v in value.values())
        if isinstance(value, list):
            return any(unknown(v) for v in value)
        return value == "unknown"
    if unknown(row):
        return False
    if kind == "lifecycle" and any(row[action]["mandatory"] and row[action]["api"] is None
            for action in ("initialization", "cleanup")):
        return False
    if (kind == "ownership" and row.get("ownership") == "owned"
            and row.get("lifetime") == "until_release" and row.get("release_api") is None):
        return False
    if kind == "callback" and row.get("mandatory") and (row.get("null_allowed") is None or not row.get("signature")):
        return False
    return True


def retained_rows(requirement, facts, *, obligation_graph=None, preview=None):
    """Retain only unchanged rows with an exact existing full-row certificate.

    A resolved proposal, a non-unknown value or an aggregate proved sibling is
    not a memory certificate. Uncovered proposals stay in observed_proposals.
    Missing graph/projection inputs intentionally grant no established memory.
    """
    field = COLLECTIONS.get(requirement["kind"])
    if not field or not obligation_graph or not preview:
        return []
    from .prompt_projection import proposal_view
    retained = {}
    subjects = [fact for fact in facts if fact.get("requirement_id") == requirement["requirement_id"]
        and fact.get("function_id") == requirement["subject_function_id"]
        and fact.get("predicate") == requirement["kind"] and fact.get("fact_id")]
    for fact in proposal_view(subjects, obligation_graph, preview):
        proofs = {p["field_path"]: p for p in fact["claim_proofs"]}
        for index, row in enumerate(fact["value"].get(field, [])):
            proof = proofs.get("value." + field + "[" + str(index) + "]", {})
            if (established(requirement["kind"], row) and proof.get("proof_status") == "proved"
                    and set(proof.get("covered_fields", [])) == set(row)
                    and proof.get("obligation_ids") and proof.get("evidence_ids")):
                retained[canonical(row)] = deepcopy(row)
    return sorted(retained.values(), key=canonical)


def _candidate_roles(kind, focused, *, return_cleanup_focus=False):
    """Project only action choices accepted by this slot, without proof claims."""
    roles = {
        "argument_construction": {"creation", "callback"}, "ownership": {"cleanup"},
        "lifecycle": {"creation", "initialization", "cleanup"},
        "state": {"initialization", "other"}, "callback": {"callback"},
    }.get(kind, set())
    if kind != "lifecycle":
        return roles
    actions = set()
    for task in focused:
        for item in task.get("closure_feedback", {}).get("items", []):
            for target in item.get("correction_targets", []):
                if target.get("requirement_id") != task.get("requirement_id"):
                    continue
                for path in target.get("field_paths", []):
                    actions.update(action for action in roles if "." + action in path)
        for proof in task.get("missing_proofs", []):
            for diagnostic in proof.get("diagnostics", []):
                code = diagnostic.get("code", "")
                actions.update(action for action in roles if action in code)
    return actions or ({"cleanup"} if return_cleanup_focus else roles)


def _repair_subjects(requirement, focused):
    """Read exact existing repair keys; never invent subject or resource IDs."""
    subjects = []
    for task in focused:
        for item in task.get("closure_feedback", {}).get("items", []):
            for target in item.get("correction_targets", []):
                if target.get("requirement_id") != requirement["requirement_id"]:
                    continue
                key = target.get("subject_key", [])
                kind = requirement["kind"]
                if kind == "ownership" and len(key) == 4:
                    subjects.append({"parameter": key[0], "return_value": key[1],
                        "field": key[2], "subject_kind": key[3]})
                elif kind == "lifecycle" and len(key) == 2:
                    subjects.append({"parameter": key[0], "return_value": key[1]})
                elif kind in {"argument_construction", "state", "callback"} and len(key) == 1:
                    subjects.append({"parameter": key[0]})
    return subjects


def _focused_candidates(requirement, candidates, roles, parameters, *, return_cleanup_focus=False, subjects=()):
    """Keep signed identity intact while narrowing its displayed subjects."""
    fid, kind = requirement["subject_function_id"], requirement["kind"]
    selected = []
    for candidate in candidates:
        if kind == "support_decision":
            if (candidate["function_id"] == fid
                    and candidate["required_by"] in requirement["required_by"]):
                selected.append(deepcopy(candidate))
            continue
        if candidate["required_by"] != fid or candidate["reason"] not in roles:
            continue
        bindings = [deepcopy(binding) for binding in candidate["subject_bindings"]
            if (not parameters or binding.get("parameter") in parameters
                or any(binding.get("parameter") == subject["parameter"] for subject in subjects))
            and (not return_cleanup_focus or parameters or subjects
                 or binding.get("subject_kind") == "PointerReturn")
            and (not subjects or any(binding.get("parameter") == subject["parameter"]
                and (not subject.get("subject_kind") or binding.get("subject_kind") == subject["subject_kind"])
                and (not subject.get("return_value") or binding.get("subject_kind") == "PointerReturn")
                and (not subject.get("field") or subject["field"] in binding.get("fields", []))
                for subject in subjects))]
        if bindings:
            selected.append({**deepcopy(candidate), "subject_bindings": bindings})
    return selected


def _return_cleanup_queries(details, snapshot, signed, *, excluded=()):
    """Find exact query spellings in this body before applying a display cap.

    The body is already authorized and completely issued by the caller. These
    AST/signature observations are search hints only: no source is issued here,
    no target ID is returned and no release, alias or ownership is certified.
    """
    returned = {details.text(node.named_children[0]) for node in details.nodes
        if node.type == "return_statement" and node.named_children
        and node.named_children[0].type == "identifier"}
    if not returned:
        return []
    cleanup_ids = {candidate["function_id"] for candidate in signed["support_candidates"]
        if candidate["required_by"] == details.function["id"] and candidate["reason"] == "cleanup"
        and any(binding.get("subject_kind") == "PointerReturn" for binding in candidate["subject_bindings"])}
    base, depth = details.function.get("return_base_type"), details.function.get("return_pointer_depth")
    queries = {}
    for node in details.nodes:
        if node.type != "call_expression":
            continue
        target, arguments = node.child_by_field_name("function"), node.child_by_field_name("arguments")
        if target is None or arguments is None:
            continue
        # Follow the exact returned local expression; unrelated same-type APIs
        # elsewhere in the project are outside this bounded source projection.
        returned_positions = [index for index, argument in enumerate(arguments.named_children)
            if details.text(argument) in returned]
        if not returned_positions:
            continue
        targets = details.candidates(target)
        if targets and all(target_id in excluded for target_id in targets):
            continue
        direct = target.type == "identifier" and details.text(target) not in details.shadows
        cleanup_shaped = any(target_id not in excluded and (
            target_id in cleanup_ids or (
                snapshot.functions[target_id].get("return_type", "").strip() == "void"
                and any(index in returned_positions and parameter.get("base_type") == base
                        and parameter.get("pointer_depth") == depth
                        for index, parameter in enumerate(snapshot.functions[target_id].get("parameters", [])))))
            for target_id in targets)
        if direct and not cleanup_shaped:
            continue
        spelling = details.text(target)
        # An indirect expression needs scoped callback investigation; its source
        # spelling grants no callable handler or resolved cleanup choice.
        if spelling and spelling not in queries:
            public = any(target_id not in excluded and "static" not in snapshot.functions[target_id].get("storage", [])
                for target_id in targets)
            priority = (0 if any(target_id in cleanup_ids for target_id in targets) else
                        1 if direct and public else 2 if not direct else 3)
            queries[spelling] = (priority, len(queries))
    return sorted(queries, key=queries.get)


def proof_agenda(requirements, facts, tasks, tools, signed, semantic_view, canonical_view,
                 *, obligation_graph=None, preview=None):
    """Small per-slot proof questions, scoped evidence memory and next queries."""
    slots = []
    available = {s["function"]["name"] for s in tools.schemas}
    inventory = [{"evidence_id": eid, "tool": row["tool"], "query": deepcopy(row.get("arguments", {})),
        "function_id": row.get("function_id"),
        "caller_id": row.get("caller_id"), "source": row.get("source"),
        "line_start": row.get("line_start"), "line_end": row.get("line_end"),
        "truncated": bool(row.get("truncated"))}
        for eid in sorted(tools.visible_ids) for row in [tools.evidence[eid]]]
    from .value_flow import complete_bodies
    complete = set(complete_bodies(tools.snapshot, {eid: tools.evidence[eid] for eid in tools.visible_ids}))
    for number, req in enumerate(requirements):
        kind, fid, rid = req["kind"], req["subject_function_id"], req["requirement_id"]
        focused = [t for t in tasks if t.get("requirement_id") == rid]
        gaps = [p for t in focused for p in t.get("missing_proofs", [])]
        diagnoses = [d for p in gaps for d in p.get("diagnostics", [])]
        parameters = sorted({p.get("subject_parameter") for p in gaps if p.get("subject_parameter")} |
            {d.get("subject_parameter") for d in diagnoses if d.get("subject_parameter")})
        if kind == "argument_construction":
            parameters = sorted(set(parameters) | {r["parameter"] for r in canonical_view["parameters"]
                if r.get("function_id", fid) == fid and r["status"] != "resolved"})
        function = tools.snapshot.functions[fid]
        return_owners = [row for fact in facts if fact.get('function_id') == fid
            and fact.get('predicate') == 'ownership'
            for row in fact['value']['entries'] if row.get('return_value')]
        # This is query priority, not a certificate or a selection of ownership.
        return_cleanup_focus = (kind in {'ownership', 'lifecycle'}
            and bool(function.get('return_pointer_depth'))
            and (not return_owners or any(row['ownership'] == 'owned' for row in return_owners)))
        roles = _candidate_roles(kind, focused, return_cleanup_focus=return_cleanup_focus)
        return_cleanup_focus = return_cleanup_focus and "cleanup" in roles
        subjects = _repair_subjects(req, focused)
        parameters = sorted(set(parameters) | {subject["parameter"] for subject in subjects if subject["parameter"]})
        if subjects and not any(subject.get("return_value") for subject in subjects):
            return_cleanup_focus = False
        candidates = _focused_candidates(req, signed["support_candidates"], roles, parameters,
            return_cleanup_focus=return_cleanup_focus, subjects=subjects)
        relevant = [n for group in ("proved", "missing_evidence", "blocked") for n in semantic_view[group]
            if n["requirement_id"] == rid]
        queries = []
        scope_blockers = []
        userdata_feedback = None
        length_feedback = None
        def suggest(name, arguments, why):
            if name == "find_cleanup_candidates":
                feedback = tools.cleanup_scope_feedback(arguments["type"])
                if feedback and feedback["all_cleanup_shaped_signatures_excluded"]:
                    blocker = {"query": arguments, "diagnostic": feedback,
                               "next_action": "Do not repeat this structural cleanup query. If the exact required release effect is unavailable because of upstream exclusion, report that scope blocker as unresolved; do not alter the frozen FT, ownership, resource IDs or merge competing resource origins."}
                    if blocker not in scope_blockers:
                        scope_blockers.append(blocker)
                    return
            item = {"tool": name, "arguments": arguments, "purpose": why}
            already_issued = any(r["tool"] == name and r["query"] == arguments and not r["truncated"]
                for r in inventory)
            duplicate = any(query["tool"] == name and query["arguments"] == arguments for query in queries)
            if name in available and not duplicate and not already_issued:
                queries.append(item)
        order_endpoints = None
        if kind == "call_order":
            # The signed registry alone supplies terminal before/after IDs.
            # An authorized CORE or proved required parent can be investigated,
            # but authorization never adds an endpoint to that signed registry.
            authorized = set(tools.scope_ids) & set(tools.snapshot.functions) - set(tools.excluded)
            issued = set(signed["issued_function_ids"]) & authorized & complete
            proved_parents = {node["subject_function_id"] for node in semantic_view["proved"]
                if node.get("proof_status") == "proved" and node.get("predicate") == "api_invocation_proved"
                and node["subject_function_id"] in req["required_by"]}
            needed = ((set(tools.core_ids) | proved_parents) & authorized) - complete
            order_endpoints = {"issued_function_ids": sorted(issued),
                "needed_authorized_function_ids": sorted(needed),
                "rule": "Use only issued_function_ids for before/after. Needed authorized IDs are exact source-read choices, not proved order edges. Read their complete bodies before proposing a source-proved relation; missing proof remains unresolved."}
            for endpoint in sorted(needed, key=lambda candidate: (candidate not in req["required_by"], candidate)):
                suggest("get_function", {"function": endpoint},
                    "read this authorized CORE or proved required-parent endpoint so its exact ID can be source-issued; cached evidence adds no source charge, and the read does not prove an order edge")
        # Inspect the already issued subject's full AST for returned-object
        # call spellings before the generic six-reference discovery cap. Only
        # scoped query suggestions leave this projection, never callable IDs.
        if (return_cleanup_focus and fid in complete and fid in tools.scope_ids
                and fid not in tools.excluded):
            from .source_queries import SourceDetails
            try:
                cleanup_details = SourceDetails(tools.snapshot, fid)
                for spelling in _return_cleanup_queries(cleanup_details, tools.snapshot, signed,
                        excluded=tools.excluded):
                    suggest("get_call_sites", {"function": fid, "callee": spelling},
                        "inspect this exact returned-local call before creator internals; the complete subject "
                        "and declared pointer relation are search hints only, not cleanup, ownership or alias proof")
            except ValueError:
                pass
        if return_cleanup_focus and not any(candidate['reason'] == 'cleanup'
                and any(binding['parameter'] is None and binding.get('subject_kind') == 'PointerReturn'
                        for binding in candidate['subject_bindings']) for candidate in candidates):
            suggest('find_cleanup_candidates', {'type': function['return_base_type']},
                'discover the exact returned-object release boundary before creator internals; '
                'inspect one public source-issued candidate first, then only its exact delegated release calls; '
                'signatures and names do not prove cleanup')
        # These AST observations guide a narrow read. They never enter the
        # evidence inventory, semantic proposals or the Gate as proof.
        if (kind in {"ownership", "lifecycle", "callback", "state", "support_decision"}
                and not return_cleanup_focus
                and fid in complete and fid in tools.scope_ids and fid not in tools.excluded):
            from .source_queries import SourceDetails
            try:
                details = SourceDetails(tools.snapshot, fid)
                if kind == "callback":
                    userdata_feedback = details.callback_userdata_feedback(tools.state.budget.max_references_per_query)
                calls, _ = details.calls("*", tools.state.budget.max_references_per_query)
                for call in calls:
                    if call["dispatch_kind"] == "indirect_syntax":
                        suggest("get_call_sites", {"function": fid, "callee": call["callee_expression"]},
                            "inspect exact callback arguments and control syntax; the target remains unproved")
                    elif any(target not in tools.scope_ids for target in call["possible_callee_ids"]):
                        suggest("get_call_sites", {"function": fid, "callee": call["callee_expression"]},
                            "discover exact direct helper references before attempting an out-of-scope definition read")
                fields = sorted({details.text(n.child_by_field_name("left").child_by_field_name("field"))
                    for n in details.nodes if n.type == "assignment_expression"
                    and n.child_by_field_name("left").type == "field_expression"})
                for field in fields[:tools.state.budget.max_references_per_query]:
                    suggest("find_field_writes", {"function": fid, "field": field},
                        "inspect exact receiver, assigned value and branch context without inferring a lifecycle role")
            except ValueError:
                pass
        if kind in {"buffer_length", "input_binding", "argument_construction"}:
            from .callbacks import callback_declarations
            callback_parameters = {d["parameter"] for d in callback_declarations(function, tools.snapshot)}
            scalars = [{"parameter": p["name"], "declared_type": p.get("type", p.get("base_type"))}
                       for p in function.get("parameters", [])
                       if not p.get("is_pointer") and p.get("base_type") != "void"
                       and p["name"] not in callback_parameters]
            links = [{k: row.get(k) for k in ("buffer_parameter", "length_parameter", "relation")}
                     for fact in facts if fact.get("function_id") == fid and fact.get("predicate") == "buffer_length"
                     for row in fact["value"]["links"]]
            bindings = [{k: row.get(k) for k in ("parameter", "size_parameter", "size_relation")}
                        for fact in facts if fact.get("function_id") == fid and fact.get("predicate") == "input_binding"
                        for row in fact["value"]["bindings"]]
            limit = tools.state.budget.max_references_per_query
            length_feedback = {"declared_scalar_parameters": scalars[:limit],
                               "submitted_buffer_length_links": links[:limit],
                               "submitted_input_extent_bindings": bindings[:limit],
                               "truncated": any(len(rows) > limit for rows in (scalars, links, bindings)),
                               "rule": "A derived scalar argument alone does not establish a buffer/extent relationship. Inspect the complete declaration and source access/call path; if proved, use the exact declared scalar name as length_parameter and keep input_binding.size_parameter consistent. A null length_parameter does not link an existing extent. Scalar names/types are candidates only, not proof that a scalar measures bytes; never fabricate a length contract or replace a flag with fuzz_size."}
        # Reuse complete candidate bodies. Discovery results or signatures alone
        # cannot be substituted for inspecting their effect on the subject.
        for candidate in candidates:
            if kind == "call_order":
                # Optional support choices are not missing required endpoints.
                continue
            if candidate["function_id"] not in complete and candidate["function_id"] in tools.scope_ids:
                suggest("get_function", {"function": candidate["function_id"]}, "inspect exact candidate body")
        if kind in {"argument_construction", "state", "lifecycle", "callback"}:
            observed = any(r["tool"] == "find_resource_flows" and tools.evidence[r["evidence_id"]].get("arguments", {}).get("function") == fid for r in inventory)
            if not observed:
                suggest("find_resource_flows", {"function": fid}, "prove exact object identity, creator/consumer/cleanup and state sequence")
        from ..semantic_slicing.frontier import function_types
        types = sorted(function_types(tools.snapshot.functions[fid]))
        if parameters:
            types = sorted({p["base_type"] for p in function.get("parameters", []) if p["name"] in parameters})
        if return_cleanup_focus:
            types = [function["return_base_type"]]
        role = ("cleanup" if kind == "ownership" or return_cleanup_focus or roles == {"cleanup"} else
                "creation" if kind == "argument_construction" or kind == "lifecycle" and "creation" in roles else
                "initialization")
        if kind in {"ownership", "argument_construction", "lifecycle", "state"} and not any(c["reason"] == role for c in candidates):
            for type_name in types:
                if type_name in {s["name"] for s in tools.snapshot.artifacts.structs} or any(
                        p["base_type"] == type_name and (p.get("is_opaque_handle") or p.get("is_struct_like"))
                        for p in tools.snapshot.functions[fid]["parameters"]):
                    suggest("find_cleanup_candidates" if role == "cleanup" else "find_initializers", {"type": type_name},
                        "discover a structural candidate; then inspect its complete source and exact subject effect")
        if kind == "callback":
            declarations = {row.get("arguments", {}).get("type") for row in tools.evidence.values()
                if row["evidence_id"] in tools.visible_ids and row["tool"] == "get_type_definition" and not row.get("truncated")}
            for type_name in types:
                if type_name in {s["name"] for s in tools.snapshot.artifacts.structs}:
                    if type_name not in declarations:
                        suggest("get_type_definition", {"type": type_name}, "inspect exact callback owner layout and userdata fields")
                    if not any(c["reason"] == "callback" for c in candidates):
                        suggest("find_type_usages", {"type": type_name}, "find the registration/assignment effect for this exact callback owner")
        retained = retained_rows(req, facts, obligation_graph=obligation_graph, preview=preview)
        if kind == "ownership":
            # The wire format accepts signed IDs, not expanded parameter/field
            # descriptors. A copyable memory must obey the same terminal schema.
            retained = [{k: v for k, v in row.items() if k in
                {"subject_id", "resource_id", "ownership", "release_api", "lifetime"}} for row in retained]
        slots.append({"slot": "r" + str(number), "requirement_id": rid, "kind": kind,
            "proof_question": QUESTIONS[kind], "target_parameters": parameters,
            "missing_proofs": gaps, "existing_local_proofs": [n["obligation_id"] for n in relevant if n["proof_status"] == "proved"],
            "retained_entries": retained, "snapshot_rule": "retained_entries contains only unchanged full rows covered "
                "by exact existing graph/source certificates; other old values are observed_proposals, not established "
                "memory. Repair the named subjects and let the framework recompute proof. A non-unknown or resolved "
                "proposal is not proof, and an owned/until_release/null-release row is incomplete. Preserve separately "
                "certified fields and distinct runtime origins; contradictions block closure. Ownership entries use "
                "signed subject_id without expanded descriptor fields.",
            "unresolved_template": {"status": "unresolved", "facts": [], "discovered_api_dependencies": [],
                "open_questions": ["Subject " + fid + (" parameters " + ", ".join(parameters) if parameters else "")
                    + ": <missing effect or relationship>; inspected issued evidence IDs: <IDs>; next existing-tool query: <query or why none is available in scope>."]},
            "candidate_effects": [{k: c[k] for k in ("candidate_id", "function_id", "reason", "subject_bindings", "evidence_ids", "necessity_proven")} for c in candidates],
            "query_options": queries[:tools.state.budget.max_references_per_query],
            **({'closure_feedback': next(t['closure_feedback'] for t in focused if t.get('closure_feedback'))}
                if any(t.get('closure_feedback') for t in focused) else {}),
            **({"upstream_scope_blockers": scope_blockers} if scope_blockers else {}),
            **({"callback_userdata_feedback": userdata_feedback} if userdata_feedback is not None else {}),
            **({"length_link_feedback": length_feedback} if length_feedback is not None else {}),
            **({"ordering_endpoints": order_endpoints} if order_endpoints is not None else {}),
            "unresolved_rule": "If proof is missing, name the exact subject, missing effect/relationship, inspected evidence IDs and one next query; unresolved is not a complete contract."})
    return {"version": VERSION, "slots": slots, "issued_evidence_inventory": inventory,
        "decision_rule": "Read the supplied subject body and reuse inventory first. Check the same object, field and all required control-flow paths. Candidate effects are hints, not necessity proofs. Query only to close a named missing proof, within the existing budgets."}
