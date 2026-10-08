"""Source contradictions to unrelated EXCLUDE, never automatic role decisions.

A support effect/type match alone proves no necessity. This narrow certificate
requires an observed fresh origin, a CORE field read and an exact release of
that same object in an ordered caller sequence. Empty semantic contracts keep
the source graph independent of model ownership/lifecycle/resource labels.
"""
from copy import deepcopy

from ..semantic_discovery.models import canonical, digest, DecisionSchemaError
from .core_proofs import inclusion_proofs
from .support_effects import bindings

VERSION = "source-exclusion-contradiction-v3"


class ExclusionEvidenceError(DecisionSchemaError):
    # The legacy remaining ordinary round can ask the agent for an explicit
    # corrected role. A source contradiction never creates an extra operation.
    terminal_extra_repair_allowed = False

    def __init__(self, errors):
        self.errors = errors
        first = errors[0]
        super().__init__(first["field"], first.get("received", first.get("reason_codes")),
            ["issued SUPPORT with established necessity", "explicit UNRESOLVED with missing-proof question"])

    def to_dict(self):
        return {**super().to_dict(), "error": "source_related_function_excluded", "errors": deepcopy(self.errors),
            "repair_instruction": "Select an issued SUPPORT alternative only if its necessity is established, "
                "or explicitly UNRESOLVED with the missing-proof question. No role is selected automatically."}


def exclusion_blockers(tools):
    """Recompute on evidence changes; no source read, tool charge or fact write."""
    identity = digest([tools.index.catalog.source_fingerprint, sorted(tools.authorized_ids), tools.evidence])
    cached = getattr(tools, "_source_exclusion_cache", None)
    if cached and cached[0] == identity:
        return deepcopy(cached[1])
    result = _blockers(tools)
    tools._source_exclusion_cache = (identity, deepcopy(result))
    return result


def _exact_local_chain(function, calls, nodes, parent_choice, cleanup_choice, creator_offset):
    """Only one locally held object with creator -> CORE -> cleanup uses.

    The graph does not propagate every defined callee's escape/may-release.
    Reject additional caller calls and object references rather than infer
    that an unexamined helper, assignment or alias preserves the object.
    """
    from ..semantic_discovery.tools import _walk, _text
    from ..harness_context.value_flow import body_tree

    source, body = body_tree(function)
    if body is None or body.has_error or parent_choice['source_node'] != cleanup_choice['source_node']:
        return False
    local = nodes.get(parent_choice['source_node'], {})
    if local.get('node_type') != 'LocalValue' or local.get('function_id') != function['id']:
        return False
    offsets = [creator_offset, parent_choice['call_offset'], cleanup_choice['call_offset']]
    ast_calls = sorted((n for n in _walk(body) if n.type == 'call_expression'), key=lambda n: n.start_byte)
    graph_calls = sorted((c for c in calls if c['caller_id'] == function['id']), key=lambda c: c['call_offset'])
    if ([n.start_byte for n in ast_calls] != offsets or
            [c['call_offset'] for c in graph_calls] != offsets):
        return False
    references = sorted((n for n in _walk(body) if n.type == 'identifier' and
                         _text(n, source) == local.get('name')), key=lambda n: n.start_byte)
    if (len(references) != 3 or not references[0].start_byte < creator_offset or
            not ast_calls[1].start_byte < references[1].start_byte < ast_calls[1].end_byte or
            not ast_calls[2].start_byte < references[2].start_byte < ast_calls[2].end_byte):
        return False
    # An overwritten pointer parameter/global is not a fresh local storage.
    declaration = references[0].parent
    while declaration is not None and declaration.type not in {'init_declarator', 'compound_statement'}:
        declaration = declaration.parent
    value = declaration.child_by_field_name('value') if declaration is not None and declaration.type == 'init_declarator' else None
    return value is not None and value.type == 'call_expression' and value.start_byte == creator_offset


def _blockers(tools):
    from ..minimal_ft.models import ProjectSnapshot
    from ..harness_context.argument_graph import GraphBuilder
    from ..harness_context.resource_identity import (
        exclusive_parameter_use_proof, exclusive_return_export_proof, parameter_release_proof)

    anchor = tools.frontier.candidate.function_id
    snapshot = ProjectSnapshot.from_artifacts(tools.index.artifacts)
    functions = snapshot.functions
    # This source-only view asserts no semantic input, ownership, lifecycle,
    # support necessity or resource identity. GraphBuilder authenticates EIDs.
    context = {"facts": [], "core_apis": [anchor], "input_contract": {"bindings": []},
        "buffer_length_contract": {"links": []}, "argument_contract": {"arguments": []},
        "lifecycle_contract": {"resources": []}, "ownership_contract": {"entries": []},
        "state_contract": {"preconditions": []}}
    ft = {"ft_id": "slice_source_" + digest([snapshot.source_fingerprint, anchor])[:24],
        "core_functions": [{"function_id": anchor}], "support_candidates": [], "excluded_functions": []}
    builder = GraphBuilder(context, ft, [], snapshot, tools.evidence)
    bodies, records = builder.bodies, builder.records
    if anchor not in bodies:
        return {}
    parents = {fid for fid in tools.authorized_ids & bodies.keys()
               if fid == anchor or inclusion_proofs(anchor, fid, functions, records)}
    context["core_apis"] = sorted(parents)
    ft["core_functions"] = [{"function_id": fid} for fid in sorted(parents)]
    effects = [(parent, api, effect)
        for parent in sorted(parents) for api in sorted(tools.authorized_ids & bodies.keys()) if api != parent
        for effect in bindings(functions[parent], functions[api], functions, set(bodies)).get("cleanup", [])
        if effect["subject_kind"] == "PointerParameter"]
    if not effects:
        return {}
    graph = builder.build()
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    parameters = {(n["function_id"], n["name"]): n["node_id"] for n in nodes.values() if n["node_type"] == "Parameter"}
    resolved = {c["target_parameter"]: c for c in graph["dependency_graph"]["resolved_parameters"]}
    origins = {n["resource_id"]: n["origin"] for n in graph["resource_origins"]}
    summaries, releases, allocations, result = {}, {}, {}, {}
    for parent, api, effect in effects:
        subject, released_parameter = effect["parameter"], effect["api_parameter"]
        subject_key = (parent, subject)
        if subject_key not in summaries:
            summaries[subject_key] = exclusive_parameter_use_proof(functions[parent], subject, snapshot, bodies)
        summary = summaries[subject_key]
        if not summary:
            continue
        fields = sorted({field for parameter, field in summary["reads"] if parameter == subject})
        subject_origin = 'parameter:' + subject
        if (not fields or not summary["paths"] or any(p["uncertain"] or
                subject_origin in p["escapes"] or subject_origin in p['released'] or
                p['release_counts'].get(subject_origin, (0, 0)) != (0, 0) for p in summary["paths"])):
            continue
        release_key = (api, released_parameter)
        if release_key not in releases:
            releases[release_key] = parameter_release_proof(functions[api], released_parameter, snapshot, bodies)
        release = releases[release_key]
        if not release:
            continue
        parent_id, cleanup_id = parameters.get((parent, subject)), parameters.get((api, released_parameter))
        parent_choice, cleanup_choice = resolved.get(parent_id), resolved.get(cleanup_id)
        if not parent_choice or not cleanup_choice or not cleanup_choice.get("resource_id"):
            continue
        dispatch = None
        via = parent
        if parent_choice.get("basis") == "callback_parameter_forwarding":
            dispatches = [d for d in graph["callback_dispatches"] if d["proof_status"] == "proven"
                and d["function_id"] == parent and any(m["parameter"] == subject
                    and parameters.get((d["via_function_id"], m["via_parameter"])) == parent_choice["source_node"]
                    for m in d["parameter_forwarding"])]
            if len(dispatches) != 1:
                continue
            dispatch = dispatches[0]
            via = dispatch["via_function_id"]
            parent_choice = resolved.get(parent_choice["source_node"])
        if (not parent_choice or parent_choice.get("basis") != "call_site_value_flow"
                or cleanup_choice.get("basis") != "call_site_value_flow"
                or parent_choice.get("resource_id") != cleanup_choice["resource_id"]
                or parent_choice.get("caller_id") != cleanup_choice.get("caller_id")):
            continue
        rid = cleanup_choice["resource_id"]
        origin = origins.get(rid, {})
        creator, caller = origin.get("function_id"), origin.get("caller_id")
        if (origin.get("kind") != "return" or creator not in bodies or caller not in bodies
                or caller != parent_choice["caller_id"] or not origin.get("call_offset", -1)
                    < parent_choice.get("call_offset", -1) < cleanup_choice.get("call_offset", -1)):
            continue
        if creator not in allocations:
            allocations[creator] = exclusive_return_export_proof(functions[creator], snapshot, bodies)
        allocation = allocations[creator]
        if not allocation:
            continue
        if not _exact_local_chain(functions[caller], builder.calls, nodes, parent_choice, cleanup_choice, origin['call_offset']):
            continue
        source_ids = set(summary["source_function_ids"]) | set(release["source_function_ids"]) \
            | set(allocation["source_function_ids"]) | {anchor, parent, via, api, creator, caller}
        if not source_ids <= bodies.keys():
            continue
        eids = sorted(set().union(*(bodies[fid] for fid in source_ids))
            | set(parent_choice["evidence_ids"]) | set(cleanup_choice["evidence_ids"])
            | set(dispatch["evidence_ids"] if dispatch else []))
        certificate = {"version": VERSION, "kind": "source_bound_cleanup_relation",
            "source_fingerprint": snapshot.source_fingerprint,
            "anchor_function_id": anchor, "parent_function_id": parent, "subject_parameter": subject,
            "required_fields": fields, "function_id": api, "cleanup_parameter": released_parameter,
            "creator_function_id": creator, "resource_id": rid, "caller_function_id": caller,
            "creator_call_offset": origin["call_offset"], "core_call_offset": parent_choice["call_offset"],
            "cleanup_call_offset": cleanup_choice["call_offset"], "via_function_id": via,
            "caller_chain": "single local creator -> CORE -> cleanup; no additional calls or object uses",
            "callback_forwarding": deepcopy(dispatch["parameter_forwarding"] if dispatch else []),
            "source_function_ids": sorted(source_ids), "evidence_ids": eids, "proof_status": "proven",
            "scope": "contradicts_unrelated_exclusion_only; no automatic role or ownership/lifecycle fact"}
        certificate["proof_id"] = "exclusion_proof_" + digest(certificate)[:24]
        result.setdefault(api, []).append(certificate)
    return {fid: sorted({canonical(c): c for c in certificates}.values(), key=canonical)
            for fid, certificates in sorted(result.items())}


def validate_exclusions(rows, tools):
    excluded = [(index, row) for index, row in enumerate(rows) if row["role"] == "exclude"]
    if not excluded:
        return
    blockers = exclusion_blockers(tools)
    errors = [{"error": "source_related_function_excluded", "field": f"classification[{index}]",
        "function_id": row["function_id"], "reason_codes": row["reason_codes"],
        "contradictions": blockers[row["function_id"]]}
        for index, row in excluded if row["function_id"] in blockers]
    if errors:
        raise ExclusionEvidenceError(errors)
    from .effect_questions import validate_effect_exclusions
    validate_effect_exclusions(rows, tools)
