"""Read-only repair feedback over the existing semantic proof frontier.

This projection is neither evidence nor a closure certificate. It names old
claims and issued choices so an agent can correct them through the ordinary
typed submission and source proof checks. It never selects a replacement.
"""
from copy import deepcopy

from ..semantic_discovery.models import canonical, digest
from .repairs import COLLECTIONS, subject_key

VERSION = "context-closure-feedback-v4"
_CASCADE_CODES = {"canonical_construction_unresolved", "core_fuzz_input_path_unresolved",
                  "mandatory_requirement_unresolved"}
_CASCADE_HOLES = {"creator_argument_missing", "construction_dependency_unresolved"}
_FIELDS = {
    "argument_construction": ("construction", "api", "resource_id", "constant"),
    "ownership": ("ownership", "lifetime", "release_api", "resource_id"),
    "lifecycle": ("creation", "initialization", "cleanup", "reuse", "resource_id"),
    "state": ("kind", "api", "resource_id"),
    "callback": ("signature", "userdata", "setup_api", "lifetime", "null_allowed"),
    "input_binding": ("source", "via_function_id", "size_parameter", "size_relation"),
    "buffer_length": ("length_parameter", "relation", "requires_nul_termination", "binary_zero_allowed"),
}
_DIAGNOSTIC_FIELDS = {
    "ownership_escape_lifetime_conflict": ("lifetime",),
    "state_precondition_unresolved": ("kind", "api"),
    "input_length_binding_conflict": ("size_parameter", "size_relation"),
    "mandatory_cleanup_unresolved": ("cleanup.api", "cleanup.mandatory"),
    "resource_identity_multiple_origins": ("resource_id",),
}
_ACTIONS = {
    "argument_construction": {"creation", "callback"},
    "ownership": {"cleanup"}, "lifecycle": {"creation", "initialization", "cleanup"},
    "state": {"initialization", "other"}, "callback": {"callback"},
    "input_binding": {"creation", "other"}, "buffer_length": set(),
}
_IDENTITY_CODES = {"resource_identity_multiple_origins", "multiple_runtime_origins",
    "creator_invocation_multiplicity", "invocation_identity_ambiguous", "invocation_scope_ambiguous"}


def _unique(rows):
    return sorted({canonical(r): deepcopy(r) for r in rows}.values(), key=canonical)


def _evidence_records(evidence):
    if not evidence:
        return {}
    if isinstance(evidence, dict) and "records" in evidence:
        evidence = evidence["records"]
    if isinstance(evidence, list):
        return {r["evidence_id"]: r for r in evidence}
    return evidence


def _subject_matches(kind, row, parameter, field, *, returned=None, subject_kind=None, resource_id=None):
    names = (row.get("buffer_parameter"), row.get("length_parameter")) if kind == "buffer_length" else (
        row.get("parameter", row.get("subject_parameter")),)
    return ((parameter is None or parameter in names) and (field is None or row.get("field") == field)
        and (returned is None or bool(row.get("return_value")) == returned)
        and (subject_kind is None or row.get("subject_kind") == subject_kind)
        and (resource_id is None or row.get("resource_id") in {None, resource_id}))


def _target(fact, row, index, fields, goal):
    kind = fact["predicate"]
    collection = COLLECTIONS.get(kind)
    base = "value." + collection + "[" + str(index) + "]" if collection else "value"
    return {"requirement_id": fact["requirement_id"], "subject_function_id": fact["function_id"],
        "kind": kind, "fact_id": fact["fact_id"], "subject_key": list(subject_key(kind, row)),
        "subject_parameter": row.get("parameter", row.get("subject_parameter", row.get("buffer_parameter"))),
        "subject_return_value": row.get("return_value", False), "subject_field": row.get("field"),
        "subject_kind": row.get("subject_kind"), "resource_id": row.get("resource_id"),
        "field_paths": [base + "." + key for key in fields],
        "observed_values": {key: _field_value(row, key) for key in fields}, "goal": goal}


def _field_value(row, path):
    value = row
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return deepcopy(value)


def _different_fields(rows, prefix=""):
    """Name concrete conflicts too, including flags omitted by generic goals."""
    if len(rows) < 2 or all(canonical(row) == canonical(rows[0]) for row in rows):
        return []
    if all(isinstance(row, dict) for row in rows):
        result = []
        for key in sorted(set().union(*(set(row) for row in rows))):
            name = prefix + "." + key if prefix else key
            result += _different_fields([row.get(key) for row in rows], name)
        return result
    return [prefix] if prefix else []


def _binding_matches(binding, subject):
    if binding.get("parameter") != subject["parameter"]:
        return False
    if subject["return_value"] and binding.get("subject_kind") != "PointerReturn":
        return False
    if subject["subject_kind"] is not None and binding.get("subject_kind") != subject["subject_kind"]:
        return False
    if subject["field"] is not None and binding.get("field") != subject["field"]:
        # Effect fields are writes/reads of the owner, not a declaration that
        # cleanup consumes an independently owned pointer field.
        return False
    return True


def _actions(kind, diagnostics):
    codes = {d.get("code") for d in diagnostics}
    if kind == "lifecycle":
        if codes & {"mandatory_cleanup_unresolved", "owned_return_lifecycle_unresolved"}:
            return {"cleanup"}
        if "required_context_initialization_unresolved" in codes:
            return {"initialization"}
        if codes & {"resource_creation_unresolved", "creator_api_unresolved"}:
            return {"creation"}
        if codes & _IDENTITY_CODES:
            return set()
    return _ACTIONS.get(kind, set())


def _callback_binding_matches(row, parameters):
    names = {row.get("parameter"), row.get("callback_parameter"), row.get("callee_expression")}
    owner = row.get("owner_origin")
    if isinstance(owner, str) and owner.startswith("parameter:"):
        owner = owner[len("parameter:"):]
        names.add(owner)
        if row.get("field"):
            names.add(owner + "." + row["field"])
            names.add(owner + "->" + row["field"])
    return bool(parameters.intersection(names))


def _options(signed, fid, kind, subjects, actions):
    signed = signed or {}
    subject = signed.get("subject_function_id")
    parameters = {row["parameter"] for row in subjects if row["parameter"] is not None}
    candidates = []
    for row in signed.get("support_candidates", []):
        parents = row.get("required_by", [])
        if (fid != parents and not (isinstance(parents, list) and fid in parents)) or row.get("reason") not in actions:
            continue
        bindings = [deepcopy(binding) for binding in row.get("subject_bindings", [])
            if any(_binding_matches(binding, exact) for exact in subjects)]
        if bindings:
            candidates.append({**deepcopy(row), "subject_bindings": bindings})
    return {"input_length_choices": [deepcopy(r) for r in signed.get("input_length_choices", [])
                if r.get("function_id", subject) == fid and kind in {"argument_construction", "input_binding", "buffer_length"}
                and parameters.intersection({r.get("buffer_parameter"), r.get("length_parameter")})],
        "ownership_subjects": [deepcopy(r) for r in signed.get("ownership_subjects", [])
                if r.get("function_id", subject) == fid and kind in {"ownership", "lifecycle"} and any(
                    r.get("parameter") == s["parameter"] and bool(r.get("return_value")) == s["return_value"]
                    and r.get("field") == s["field"] and (s["subject_kind"] is None or r.get("subject_kind") == s["subject_kind"])
                    for s in subjects)],
        "support_candidates": candidates,
        "source_callback_bindings": [deepcopy(r) for r in signed.get("source_callback_bindings", [])
                if r.get("root_function_id", subject) == fid and kind in {"callback", "argument_construction"}
                and _callback_binding_matches(r, parameters)],
        "action_filter": sorted(actions), "subject_filter": _unique(subjects),
        "rule": "Issued options are legal choices and source hints for these exact subjects/actions, not proof of a replacement value, aliasing or necessity."}


def _diagnostic_subjects(node):
    """Collection roots may carry several exact subjects in their diagnostics."""
    parameter, field = node.get("subject_parameter"), node.get("subject_field")
    diagnostics = node.get("diagnostics", [])
    subjects = {(d.get("subject_parameter", d.get("parameter")), d.get("subject_field")) for d in diagnostics
        if d.get("subject_parameter", d.get("parameter")) is not None}
    if parameter is not None or not subjects:
        return [(parameter, field, diagnostics)]
    return [(p, f, [d for d in diagnostics if d.get("subject_parameter", d.get("parameter")) in {None, p}
        and d.get("subject_field") in {None, f}]) for p, f in sorted(subjects, key=canonical)]


def _local_dependencies(node, nodes, parameter_nodes):
    """Only explicit dependency-only failures can be deferred to their cause."""
    diagnoses = node.get("diagnostics", [])
    if not diagnoses or any(d.get("code") not in _CASCADE_CODES for d in diagnoses):
        return set()
    holes = [h for d in diagnoses for h in d.get("graph_holes", [])]
    if not holes or any(h.get("code") not in _CASCADE_HOLES or not h.get("missing_dependencies") for h in holes):
        return set()
    deps = {d["obligation_id"] for d in node.get("dependencies", [])
            if d["obligation_id"] in nodes and nodes[d["obligation_id"]].get("proof_status") != "proved"}
    for hole in holes:
        for pid in hole["missing_dependencies"]:
            if pid not in parameter_nodes:
                return set()
            deps.add(parameter_nodes[pid])
    return deps - {node["obligation_id"]}


def _evidence_state(fid, evidence, signed, targets=(), options=None, body_inventory=None):
    exact = [r for r in evidence.values() if r.get("function_id") == fid]
    complete = {r["evidence_id"] for r in exact if r.get("tool") == "get_function"
        and not r.get("truncated") and r.get("defined") is not False and r.get("content")}
    # The existing registry issues subject_evidence_ids only after a complete
    # source read; this projection merely remembers that existing inventory.
    if (signed or {}).get("subject_function_id") == fid:
        complete |= set(signed.get("subject_evidence_ids", []))
    complete |= set((body_inventory or {}).get(fid, []))
    complete_functions = {r.get("function_id") for r in evidence.values() if r.get("tool") == "get_function"
        and not r.get("truncated") and r.get("defined") is not False and r.get("content")}
    complete_functions.update((signed or {}).get("issued_function_ids", []))
    complete_functions.update(body_inventory or {})
    complete_functions.update(row["function_id"] for row in (signed or {}).get("support_candidates", [])
        if row.get("source_status") == "issued_complete_body")
    if complete:
        complete_functions.add(fid)
    required_functions = {value for target in targets for key, value in target["observed_values"].items()
        if (key == "api" or key.endswith(".api") or key in {"release_api", "setup_api", "via_function_id"}) and value}
    # The subject's complete body never authenticates its proposed helper API.
    # Missing API choices indicate more investigation, not a guessed cleanup.
    roles = set((options or {}).get("action_filter", []))
    missing_roles = ["cleanup"] if "cleanup" in roles and not (options or {}).get("support_candidates") and not required_functions else []
    return {"complete_body_evidence_ids": sorted(complete),
        "truncated_evidence_ids": sorted(r["evidence_id"] for r in exact if r.get("truncated")),
        "required_function_ids": sorted(required_functions),
        "missing_complete_body_function_ids": sorted(required_functions - complete_functions),
        "missing_source_roles": missing_roles,
        "rule": "A complete subject body does not establish the missing contract or helper bodies; reuse exact issued evidence and acquire missing dependencies."}


def _diagnostic_codes(diagnostics):
    codes = set()
    for diagnostic in diagnostics:
        codes.add(diagnostic.get("code", ""))
        codes.update(hole.get("code", "") for hole in diagnostic.get("graph_holes", []))
        detail = diagnostic.get("detail") or {}
        codes.update(detail[key] for key in ("reason", "code", "unsupported_feature") if isinstance(detail.get(key), str))
    return codes


def _category(diagnostics, blockers, evidence_state):
    codes = _diagnostic_codes(diagnostics)
    if blockers or codes & {"upstream_excluded", "upstream_scope_blocked", "required_api_upstream_excluded"}:
        return "upstream_blocker"
    if any(isinstance(code, str) and "unsupported" in code for code in codes) or any(
            (d.get("detail") or {}).get("unsupported_feature") for d in diagnostics):
        return "unsupported"
    if codes & {"source_body_missing", "source_definition_missing", "required_source_body_unavailable",
                "helper_body_missing", "callee_body_missing", "missing_source_evidence"}:
        return "missing_evidence"
    if evidence_state["missing_complete_body_function_ids"] or evidence_state["missing_source_roles"]:
        return "missing_evidence"
    if evidence_state["complete_body_evidence_ids"]:
        return "contract_correction"
    return "missing_evidence"


def _blocker_action(category, evidence_state, *, blocker_kind=None):
    actions = {
        "upstream_blocker": "Report the frozen scope blocker unresolved; do not activate excluded APIs or alter Slice/FT.",
        "unsupported": "Report the exact unsupported source/proof feature unresolved; more model confidence cannot supply a framework certificate.",
        "missing_evidence": "Acquire the exact missing helper body or scoped action call-site evidence, then submit source-supported typed candidates; the subject body alone is insufficient.",
        "contract_correction": "Correct the named typed fields with issued evidence; only revalidated source proofs may replace active facts.",
    }
    action = actions[category]
    if blocker_kind == "resource_identity_ambiguity" and category == "contract_correction":
        action = "Keep distinct caller/call-offset/resource origins. Request an exact invocation-identity proof; do not select or merge origins by matching producer/type. Ambiguity does not by itself establish unsupported analysis."
    return {"category": category, "blocker_kind": blocker_kind, "next_action": action,
        "missing_complete_body_function_ids": evidence_state["missing_complete_body_function_ids"],
        "missing_source_roles": evidence_state["missing_source_roles"],
        "body_inventory_is_proof": False}


def _same_cleanup_subject(resource, owner):
    """Link declared slots, never certify two runtime resources as aliases."""
    if resource.get("subject_parameter") != owner.get("parameter") or bool(resource.get("return_value")) != bool(owner.get("return_value")):
        return False
    resource_id, owner_id = resource.get("resource_id"), owner.get("resource_id")
    if resource_id is not None and owner_id is not None and resource_id != owner_id:
        return False
    if owner.get("field") is not None:
        # Lifecycle has no field in its native schema. Only an already shared
        # exact RID can connect its row to a separately declared field owner.
        if resource.get("field") != owner["field"] and not (resource_id is not None and resource_id == owner_id):
            return False
    if owner.get("subject_kind") == "OutParameterPointee" and not (resource_id is not None and resource_id == owner_id):
        return False
    return True


def _cleanup_targets(node, facts):
    if node["kind"] not in {"lifecycle", "ownership"}:
        return []
    fid, parameter, field = node["subject_function_id"], node.get("subject_parameter"), node.get("subject_field")
    resource_id = node.get("resource_id")
    resources, owners = [], []
    for fact in facts:
        kind = fact["predicate"]
        if fact["function_id"] != fid or kind not in {"lifecycle", "ownership"}:
            continue
        for index, row in enumerate(fact["value"].get(COLLECTIONS[kind], [])):
            if parameter is not None and row.get("parameter", row.get("subject_parameter")) != parameter:
                continue
            if resource_id is not None and row.get("resource_id") not in {None, resource_id}:
                continue
            if field is not None and kind == "ownership" and row.get("field") != field:
                continue
            if node.get("subject_return_value") is not None and bool(row.get("return_value")) != node["subject_return_value"]:
                continue
            if kind == "ownership" and node.get("subject_kind") is not None and row.get("subject_kind") != node["subject_kind"]:
                continue
            (resources if kind == "lifecycle" else owners).append((fact, row, index))
    targets = []
    codes = _diagnostic_codes(node.get("diagnostics", []))
    for resource_fact, resource, resource_index in resources:
        for owner_fact, owner, owner_index in owners:
            if not _same_cleanup_subject(resource, owner):
                continue
            if owner.get("resource_id") is None and len({r.get("resource_id") for _, r, _ in resources
                    if _same_cleanup_subject(r, owner)}) > 1:
                # A declaration alone does not identify which runtime result a
                # null-RID ownership claim describes.
                continue
            cleanup_api, release_api = (resource.get("cleanup") or {}).get("api"), owner.get("release_api")
            exact_mandatory_gap = ("mandatory_cleanup_unresolved" in codes
                and (parameter is not None or resource_id is not None
                    or node.get('subject_return_value') is True))
            if not (owner.get("ownership") == "owned"
                    and (cleanup_api is None or release_api is None or cleanup_api != release_api)
                    or exact_mandatory_gap):
                continue
            goal = ("Recheck lifecycle.cleanup.api and ownership.release_api for this exact declared object/resource together. "
                "Explicitly submit both typed slots when they need correction; preserve independently proved ownership/lifetime, other subjects and "
                "all old evidence. An issued cleanup candidate is not a proof that it consumes this object. Only the existing "
                "source evaluator may retire an old claim; distinct invocation origins must remain distinct.")
            targets.append(_target(resource_fact, resource, resource_index, ("cleanup.api",), goal))
            targets.append(_target(owner_fact, owner, owner_index, ("release_api",), goal))
    return _unique(targets)


def _cleanup_row_affected(row, facts, fid):
    cleanup = row.get("cleanup") or {}
    if cleanup.get("mandatory") and cleanup.get("api") is None:
        return True
    return any(_same_cleanup_subject(row, owner) and owner.get("ownership") == "owned"
        and (owner.get("release_api") is None or cleanup.get("api") is None
            or owner.get("release_api") != cleanup.get("api"))
        for fact in facts if fact["function_id"] == fid and fact["predicate"] == "ownership"
        for owner in fact["value"].get("entries", []))


def _leaf_fields(value, prefix=""):
    if isinstance(value, dict):
        return [(name, child) for key, entry in value.items() for name, child in
            _leaf_fields(entry, prefix + "." + key if prefix else key)]
    return [(prefix, value)]


def _identity_frontier(item, resource_identity):
    """Remember the framework's exact unresolved origins without aliasing."""
    if not (_diagnostic_codes(item["diagnostics"]) & _IDENTITY_CODES):
        return {"unresolved": [], "observations": [], "rule": "No invocation-identity conclusion is made by feedback."}
    unresolved = [deepcopy(row) for row in (resource_identity or {}).get("unresolved", [])
        if row.get("function_id") == item["subject_function_id"] and (item["subject_parameter"] is None
            or row.get("parameter") == item["subject_parameter"])]
    origin_ids = {rid for row in unresolved for rid in row.get("origins", [])}
    observations = [deepcopy(row) for row in (resource_identity or {}).get("value_flow", {}).get("observations", [])
        if row.get("resource_id") in origin_ids]
    return {"unresolved": _unique(unresolved), "observations": _unique(observations),
        "rule": "These issued runtime observations stay distinct. Caller, call offset, RID and evidence are hints to the missing invocation proof, not a certificate of aliasing or unsupported analysis."}


def _length_targets(node, facts, options):
    """Link a failed derived argument to missing, separately typed extents."""
    if node["kind"] not in {"argument_construction", "input_binding", "buffer_length"}:
        return []
    fid, parameter = node["subject_function_id"], node.get("subject_parameter")
    choices = [p for p in options["input_length_choices"] if parameter in (
        p.get("buffer_parameter"), p.get("length_parameter"))]
    result = []
    for pair in choices:
        buffer, length = pair["buffer_parameter"], pair["length_parameter"]
        for fact in facts:
            if fact["function_id"] != fid or fact["predicate"] not in {"input_binding", "buffer_length"}:
                continue
            kind = fact["predicate"]
            for i, row in enumerate(fact["value"].get(COLLECTIONS[kind], [])):
                name = row.get("parameter") if kind == "input_binding" else row.get("buffer_parameter")
                if name != buffer:
                    continue
                field = "size_parameter" if kind == "input_binding" else "length_parameter"
                if row.get(field) == length:
                    continue
                result.append(_target(fact, row, i, (field,),
                    "Verify the issued buffer/extent choices against the complete body; explicitly submit a source-proved "
                    "extent and keep input_binding.size_parameter and buffer_length.length_parameter consistent. "
                    "A derived scalar label alone does not bind an extent. Do not select a pair from its name/type alone."))
    return _unique(result)


def _input_construction_targets(node, facts, options):
    """Keep a disputed input origin and its construction in the same repair.

    Naming a construction ``input`` does not correct a previously submitted
    derived/context binding. These are separately typed slots. Only existing
    claims are linked here; no input origin or replacement value is selected.
    Output storage without an input-binding claim is outside this projection.
    """
    if node["kind"] not in {"argument_construction", "input_binding"}:
        return []
    fid, parameter = node["subject_function_id"], node.get("subject_parameter")
    names = {parameter} if parameter is not None else set()
    for pair in options["input_length_choices"]:
        if parameter in (pair.get("buffer_parameter"), pair.get("length_parameter")):
            names.add(pair.get("buffer_parameter"))
    bindings, arguments = {}, {}
    for fact in facts:
        if fact["function_id"] != fid or fact["predicate"] not in {"input_binding", "argument_construction"}:
            continue
        for index, row in enumerate(fact["value"].get(COLLECTIONS[fact["predicate"]], [])):
            name = row.get("parameter")
            if names and name not in names:
                continue
            destination = bindings if fact["predicate"] == "input_binding" else arguments
            destination.setdefault(name, []).append((fact, row, index))
    targets = []
    for name, input_rows in bindings.items():
        argument_rows = arguments.get(name, [])
        source_shapes = {canonical({key: row.get(key) for key in ("source", "via_function_id", "transform")})
            for _, row, _ in input_rows}
        construction_shapes = {canonical({key: row.get(key) for key in ("construction", "api", "resource_id", "constant")})
            for _, row, _ in argument_rows}
        unbound = any(row.get("source") in {"derived", "context"} and row.get("via_function_id") is None
            for _, row, _ in input_rows)
        disagrees = any((argument.get("construction") == "input" and binding.get("source") != "fuzz_data")
            or (binding.get("source") == "fuzz_data" and argument.get("construction") not in {"input", "unknown"})
            or (argument.get("api") is not None and binding.get("via_function_id") is not None
                and argument["api"] != binding["via_function_id"])
            for _, argument, _ in argument_rows for _, binding, _ in input_rows)
        if not (unbound or disagrees or len(source_shapes) > 1 or len(construction_shapes) > 1):
            continue
        goal = ("Recheck this input origin and its argument construction together using the exact issued body and "
            "canonical path. An argument label does not replace input_binding.source/via_function_id/transform. "
            "A derived/context claim with no established upstream path remains unresolved; direct fuzz_data needs "
            "its own source-supported canonical recipe. Explicitly submit consistent typed slots, preserve unrelated "
            "subjects and resource identities, and never choose an origin from names or types alone.")
        for fact, row, index in input_rows:
            targets.append(_target(fact, row, index, ("source", "via_function_id", "transform"), goal))
        for fact, row, index in argument_rows:
            targets.append(_target(fact, row, index, _FIELDS["argument_construction"], goal))
    return _unique(targets)


def build_closure_feedback(report, requirements, facts, *, signed=None, evidence=None,
                           canonical_construction=None, scope_blockers=(), resource_identity=None):
    """Name the earliest actionable subjects without changing facts or scope.

    ``report`` is a freshly recomputed completeness report (or the graph itself).
    A missing graph yields no authoritative frontier. Downstream dependency-only
    gaps remain in the result as deferred gaps and must be revalidated after a
    correction. Unrelated local failures always retain their own repair item.
    """
    graph = report.get("semantic_obligation_graph", report)
    nodes = {n["obligation_id"]: n for n in graph.get("nodes", [])}
    frontier = set(graph.get("frontier", []))
    evidence = _evidence_records(evidence)
    # The current framework graph can authenticate complete range reads even
    # when a function was not fetched through get_function. This is strictly a
    # body-availability inventory, never a proof of ownership or cleanup.
    body_inventory = {node["subject_function_id"]: node.get("evidence_ids", []) for node in nodes.values()
        if node.get("predicate") == "api_source_available" and node.get("local_proof", {}).get("status") == "proved"
        and node.get("evidence_ids") and all(eid in evidence for eid in node["evidence_ids"])
        and any(source.get("kind") == "source_definition" and source.get("active")
            for source in node.get("local_proof", {}).get("sources", []))}
    reqs = {r["requirement_id"]: r for r in requirements}
    parameter_nodes = {s["parameter_id"]: n["obligation_id"] for n in nodes.values()
        for s in n.get("local_proof", {}).get("sources", []) if s.get("kind") == "canonical_construction"}
    for row in (canonical_construction or {}).get("parameters", []):
        match = next((n for n in nodes.values() if n.get("predicate") == "parameter_recipe"
            and n["subject_function_id"] == row["function_id"] and n.get("subject_parameter") == row["parameter"]), None)
        if match:
            parameter_nodes[row["parameter_id"]] = match["obligation_id"]
    upstream = {nid: _local_dependencies(nodes[nid], nodes, parameter_nodes) for nid in frontier if nid in nodes}

    def causes(nid, path=()):
        if nid in path or not upstream.get(nid):
            return {nid}
        return set().union(*(causes(dep, (*path, nid)) for dep in upstream[nid]))

    grouped = {}
    for nid in sorted(frontier):
        for cause in sorted(causes(nid)):
            node = nodes.get(cause)
            if not node or node.get("kind") == "integrity":
                continue
            for parameter, field, diagnostics in _diagnostic_subjects(node):
                key = (node.get("requirement_id"), node["subject_function_id"], node["kind"], parameter, field)
                item = grouped.setdefault(key, {"requirement_id": key[0], "subject_function_id": key[1],
                    "kind": key[2], "subject_parameter": key[3], "subject_field": key[4],
                    "frontier_obligation_ids": [], "dependent_gaps": [], "affected_roots": [], "diagnostics": []})
                item["frontier_obligation_ids"].append(cause)
                item["diagnostics"] += diagnostics
                if nid != cause and nid in nodes:
                    dependent = nodes[nid]
                    item["dependent_gaps"].append({"obligation_id": nid, "requirement_id": dependent.get("requirement_id"),
                        "subject_function_id": dependent["subject_function_id"], "diagnostics": dependent.get("diagnostics", []),
                        "next_action": "Recompute this gap after repairing the prerequisite; it is still unresolved."})
                item["affected_roots"] += [rid for rid in graph.get("open_roots", []) if
                    cause == rid or cause in nodes.get(rid, {}).get("blocking_obligations", []) or
                    nid == rid or nid in nodes.get(rid, {}).get("blocking_obligations", [])]
    items = []
    for item in grouped.values():
        fid, rid, kind = item["subject_function_id"], item["requirement_id"], item["kind"]
        item["diagnostics"] = _unique(item["diagnostics"])
        item["dependent_gaps"] = _unique(item["dependent_gaps"])
        for key in ("frontier_obligation_ids", "affected_roots"):
            item[key] = sorted(set(item[key]))
        relevant_nodes = [nodes[nid] for nid in item["frontier_obligation_ids"]]
        declared_kinds = {source.get("subject_kind") for node in relevant_nodes
            for source in node.get("local_proof", {}).get("sources", [])
            if source.get("kind") == "declared_ownership_subject" and source.get("subject_kind")}
        declared_kind = next(iter(declared_kinds)) if len(declared_kinds) == 1 else None
        item["subject_return_value"] = True if declared_kind == "PointerReturn" else None
        item["subject_kind"] = declared_kind
        resource_ids = {node.get("resource_id") for node in relevant_nodes if node.get("resource_id")}
        item["resource_id"] = next(iter(resource_ids)) if len(resource_ids) == 1 else None
        blockers = [deepcopy(b) for b in scope_blockers if b.get("requirement_id") == rid or
            b.get("subject_function_id", b.get("function_id")) == fid]
        item["upstream_scope_blockers"] = blockers
        current = [deepcopy(f) for f in facts if f.get("requirement_id") == rid]
        item["current_facts"] = current
        targets = []
        fields = sorted({field for d in item["diagnostics"] for field in (d.get("detail") or {}).get("unknown_fields", [])})
        if not fields:
            fields = sorted({field for d in item["diagnostics"] for field in _DIAGNOSTIC_FIELDS.get(d.get("code"), ())})
        for fact in current:
            collection = COLLECTIONS.get(kind)
            rows = fact["value"].get(collection, []) if collection else [fact["value"]]
            for i, row in enumerate(rows):
                if _subject_matches(kind, row, item["subject_parameter"], item["subject_field"],
                        returned=item["subject_return_value"], subject_kind=declared_kind if kind == "ownership" else None,
                        resource_id=item["resource_id"]):
                    if (kind == "lifecycle" and "mandatory_cleanup_unresolved" in _diagnostic_codes(item["diagnostics"])
                            and item["subject_parameter"] is None and item["resource_id"] is None
                            and not _cleanup_row_affected(row, facts, fid)):
                        continue
                    alternatives = [other for f in current for other in f["value"].get(collection, [])
                        if subject_key(kind, other) == subject_key(kind, row)] if collection else []
                    conflict_fields = _different_fields(alternatives)
                    targets.append(_target(fact, row, i, sorted(set(fields) | set(conflict_fields))
                        if fields or conflict_fields else _FIELDS.get(kind, tuple(row)),
                        "Correct only this exact subject using issued source and typed fields; unsupported or missing proof stays unresolved."))
        # Missing extent links live in other requirement slots, even when the
        # frontier belongs to the argument-construction slot.
        target_node = {**nodes[item["frontier_obligation_ids"][0]], "subject_parameter": item["subject_parameter"],
            "subject_field": item["subject_field"], "resource_id": item["resource_id"], "diagnostics": item["diagnostics"],
            "subject_return_value": item["subject_return_value"], "subject_kind": declared_kind}
        targets += _cleanup_targets(target_node, facts)
        subjects = []
        for target in targets:
            if target["subject_function_id"] != fid:
                continue
            if target["kind"] == "lifecycle" and any(owned["kind"] == "ownership"
                    and owned["subject_parameter"] == target["subject_parameter"]
                    and owned["subject_return_value"] == target["subject_return_value"]
                    and (owned["resource_id"] == target["resource_id"] or owned["resource_id"] is None)
                    for owned in targets):
                # Prefer the linked declaration subject, including pointer-cell
                # versus pointee and separately owned fields, to a coarse
                # lifecycle row that has no native subject_kind/field.
                continue
            subjects.append({"parameter": target["subject_parameter"], "return_value": target["subject_return_value"],
                "field": target["subject_field"], "subject_kind": target["subject_kind"], "resource_id": target["resource_id"]})
        if not subjects and item["subject_parameter"] is not None:
            subjects.append({"parameter": item["subject_parameter"], "return_value": False,
                "field": item["subject_field"], "subject_kind": declared_kind, "resource_id": item["resource_id"]})
        # Lifecycle return rows need their declaration kind even when a linked
        # ownership row is missing. Null parameter is not a wildcard subject.
        for subject in subjects:
            if subject["return_value"] and subject["subject_kind"] is None:
                subject["subject_kind"] = "PointerReturn"
        item["issued_options"] = _options(signed, fid, kind, _unique(subjects), _actions(kind, item["diagnostics"]))
        targets += _length_targets(target_node, facts, item["issued_options"])
        targets += _input_construction_targets(target_node, facts, item["issued_options"])
        item["correction_targets"] = _unique(targets)
        item["evidence_state"] = _evidence_state(fid, evidence, signed, item["correction_targets"],
            item["issued_options"], body_inventory)
        item["category"] = _category(item["diagnostics"], blockers, item["evidence_state"])
        item["blocker_kind"] = ("resource_identity_ambiguity" if _diagnostic_codes(item["diagnostics"]) & _IDENTITY_CODES else item["category"])
        item["actionable_blocker"] = _blocker_action(item["category"], item["evidence_state"], blocker_kind=item["blocker_kind"])
        item["identity_frontier"] = _identity_frontier(item, resource_identity)
        item["active_fact_ids"] = sorted(f["fact_id"] for f in facts)
        item["retirement_rule"] = "All active facts remain effective until the existing source proof evaluator certifies a replacement and its transaction commits. Feedback never retires facts."
        item["repair_requirement_ids"] = sorted({r for r in [rid, *(t["requirement_id"] for t in targets)] if r in reqs})
        targeted = {t["fact_id"] for t in targets}
        item["preserve_fact_ids"] = sorted(f["fact_id"] for f in facts if f["fact_id"] not in targeted)
        item["preserve_rows"] = []
        item["preserve_fields"] = []
        for fact in facts:
            if fact["fact_id"] not in targeted:
                continue
            collection = COLLECTIONS.get(fact["predicate"])
            for i, row in enumerate(fact["value"].get(collection, []) if collection else []):
                base = "value." + collection + "[" + str(i) + "]"
                row_targets = [target for target in targets if target["fact_id"] == fact["fact_id"]
                    and any(path == base or path.startswith(base + ".") for path in target["field_paths"])]
                if not row_targets:
                    item["preserve_rows"].append({"fact_id": fact["fact_id"], "field_path": "value." + collection + "[" + str(i) + "]",
                        "value": deepcopy(row), "evidence_ids": deepcopy(fact["evidence_ids"])})
                else:
                    paths = {path for target in row_targets for path in target["field_paths"]}
                    for path, value in _leaf_fields(row):
                        full = base + "." + path
                        if not any(full == target or full.startswith(target + ".") for target in paths):
                            item["preserve_fields"].append({"fact_id": fact["fact_id"], "field_path": full,
                                "value": deepcopy(value), "evidence_ids": deepcopy(fact["evidence_ids"])})
        item["question"] = ("Repair the exact named contract fields with existing issued evidence; preserve independent subjects, "
            "resource identities and evidence. Submit explicit typed corrections, then let the framework recompute affected roots. "
            "For missing evidence, identify one available scoped query; for an upstream blocker, unsupported proof or invocation identity ambiguity, report the exact blocker unresolved.")
        item["feedback_id"] = "closure_feedback_" + digest(item)[:24]
        items.append(item)
    # Preservation is group-wide: one item's independent list must never
    # instruct the agent to preserve a subject targeted by another repair item.
    all_targets = [target for item in items for target in item["correction_targets"]]
    targeted_facts = {target["fact_id"] for target in all_targets}
    for item in items:
        item["preserve_fact_ids"] = [fid for fid in item["preserve_fact_ids"] if fid not in targeted_facts]
        item["preserve_rows"] = [entry for entry in item["preserve_rows"] if not any(
            target["fact_id"] == entry["fact_id"] and any(path == entry["field_path"]
                or path.startswith(entry["field_path"] + ".") for path in target["field_paths"])
            for target in all_targets)]
        item["preserve_fields"] = [entry for entry in item["preserve_fields"] if not any(
            target["fact_id"] == entry["fact_id"] and any(entry["field_path"] == path
                or entry["field_path"].startswith(path + ".") for path in target["field_paths"])
            for target in all_targets)]
        item["feedback_id"] = "closure_feedback_" + digest({k: v for k, v in item.items() if k != "feedback_id"})[:24]
    groups = []
    for fid in sorted({item["subject_function_id"] for item in items}):
        components = []
        for item in [item for item in items if item["subject_function_id"] == fid]:
            ids = set(item["repair_requirement_ids"])
            linked = [component for component in components if ids.intersection(component)]
            for component in linked:
                ids.update(component)
                components.remove(component)
            components.append(ids)
        for ids in components:
            group = {"subject_function_id": fid, "requirement_ids": sorted(ids),
                "correction_targets": _unique([target for target in all_targets if target["requirement_id"] in ids]),
                "rule": "Investigate these linked slots together. Explicit submissions are candidates; only the framework's source checks can commit them."}
            group["group_id"] = "context_revision_group_" + digest(group)[:24]
            groups.append(group)
    result = {"version": VERSION, "artifact_kind": "context_closure_feedback", "graph_digest": graph.get("graph_digest"),
        "items": sorted(items, key=canonical), "transaction_groups": sorted(groups, key=canonical),
        "rule": "Feedback does not issue evidence, select facts, expand the frozen FT/scope, increase budgets or allow harness generation."}
    result["frontier_digest"] = digest(result)
    return result


def attach_closure_feedback(tasks, feedback):
    """Attach relevant read-only feedback without changing task identities."""
    result = deepcopy(tasks)
    for task in result:
        relevant = [deepcopy(item) for item in feedback["items"] if task.get("requirement_id") in item["repair_requirement_ids"]]
        if relevant:
            prior = task.get("closure_feedback", {}).get("items", [])
            for item in relevant:
                rejected = [r for old in prior for r in old.get("rejected_candidates", [])
                    if set(r["submitted_requirement_ids"]).intersection(item["repair_requirement_ids"])]
                if rejected:
                    item["rejected_candidates"] = _unique(rejected)
            task["closure_feedback"] = {"version": VERSION, "frontier_digest": feedback["frontier_digest"], "items": relevant}
    return result


def attach_rejected_candidates(feedback, rejections):
    """Keep failed proposals visible while active facts remain rolled back."""
    result = deepcopy(feedback)
    for item in result["items"]:
        candidates = [deepcopy(rejection) for rejection in rejections
            if set(rejection["submitted_requirement_ids"]).intersection(item["repair_requirement_ids"])]
        if candidates:
            item["rejected_candidates"] = _unique(candidates)
    result["frontier_digest"] = digest({k: v for k, v in result.items() if k != "frontier_digest"})
    return result
