"""Signed declaration subjects and source-issued support choices.

Candidate roles are exploration choices, never proof of necessity/ownership.
Only the existing repository tools can enlarge the source-issued registry.
"""
from ..semantic_discovery.models import digest, canonical
from ..semantic_discovery.tools import _walk, _text
from .value_flow import complete_bodies

VERSION = "subject-effect-semantic-proposals-v4"
OWNERSHIP_KINDS = ("PointerParameter", "PointerReturn", "OutParameterPointee", "ResourceObject")


def pointer_fields(declaration):
    from tree_sitter import Language, Parser
    import tree_sitter_c
    source = declaration.encode()
    root = Parser(Language(tree_sitter_c.language())).parse(source).root_node
    result = set()
    for node in _walk(root):
        if node.type != "field_declaration":
            continue
        for declarator in node.named_children:
            if declarator.type in {"type_identifier", "primitive_type", "type_qualifier"}:
                continue
            if any(n.type == "pointer_declarator" for n in _walk(declarator)):
                result.update(_text(n, source) for n in _walk(declarator) if n.type == "field_identifier")
    return sorted(result)


def ownership_subjects(fid, snapshot):
    function = snapshot.functions[fid]
    rows = []
    def add(kind, parameter=None, returned=False, field=None):
        row = {"function_id": fid, "subject_kind": kind, "parameter": parameter,
            "return_value": returned, "field": field}
        rows.append({**row, "subject_id": "ownership_subject_" + digest([snapshot.functions_fingerprint, row])[:24]})
    for p in function.get("parameters", []):
        if p.get("is_pointer") or p.get("is_opaque_handle"):
            add("PointerParameter", p["name"])
        elif p.get("is_struct_like"):
            add("ResourceObject", p["name"])
        if p.get("pointer_depth", 0) >= 2:
            from .value_flow import body_tree
            source, body = body_tree(function)
            if body is not None and not body.has_error and any(n.type == "assignment_expression"
                    and _text(n.child_by_field_name("left"), source).replace(" ", "") == "*" + p["name"]
                    for n in _walk(body)):
                add("OutParameterPointee", p["name"])
        for struct in snapshot.artifacts.structs:
            if p["base_type"] in {struct["name"], *struct.get("aliases", [])}:
                for field in pointer_fields(struct["declaration"]):
                    add("ResourceObject", p["name"], field=field)
    if function.get("return_pointer_depth", 0):
        add("PointerReturn", returned=True)
    return sorted(rows, key=canonical)


def ownership_subject(entry, fid, snapshot):
    choices = [s for s in ownership_subjects(fid, snapshot)
        if all(s[k] == entry[k] for k in ("parameter", "return_value", "field"))]
    if entry.get("subject_kind"):
        choices = [s for s in choices if s["subject_kind"] == entry["subject_kind"]]
    else:
        choices = [s for s in choices if s["subject_kind"] != "OutParameterPointee"]
    if len(choices) != 1 or entry.get("subject_id", choices[0]["subject_id"] if choices else None) != (choices[0]["subject_id"] if choices else None):
        raise ValueError("ownership_subject_not_signed_by_declaration")
    return choices[0]


def registry(tools, requirements=()):
    snapshot = tools.snapshot
    visible = {eid: r for eid, r in tools.evidence.items() if eid in tools.visible_ids}
    bodies = complete_bodies(snapshot, visible)
    requirements = list(requirements) or [tools.requirement]
    parents = sorted({fid for r in requirements for fid in [r["subject_function_id"], *r["required_by"]]})
    candidates = []
    from .callbacks import callback_declarations
    from .evidence import callback_abis
    for parent in parents:
        function = snapshot.functions[parent]
        callbacks = set().union(*(callback_abis(c["signature"]) for c in callback_declarations(function, snapshot)))
        for fid in sorted(set(bodies) & set(tools.scope_ids) - set(tools.excluded)):
            if fid == parent:
                continue
            api = snapshot.functions[fid]
            from ..semantic_slicing.support_effects import bindings as effect_bindings
            roles = effect_bindings(function, api, snapshot.functions, set(bodies))
            api_callbacks = set().union(*(callback_abis(c['signature']) for c in callback_declarations(api, snapshot)))
            from ..semantic_slicing.core_proofs import processes_parameters
            direct_handler = bool(callbacks & callback_abis(api['signature'])) and processes_parameters(api)
            callback_fields = {c['field'] for c in callback_declarations(function, snapshot) if c['field']}
            registration = bool(callbacks & api_callbacks) and any(
                b['effect'] == 'observed_field_write' and callback_fields & set(b['fields'])
                for rows in roles.values() for b in rows)
            if direct_handler or registration:
                roles["callback"] = [{"parameter": name, "type": "callback", "pointer_depth": 0, 'subject_kind': None,
                    'effect': 'callback_registration' if registration else 'callback_processing', 'api_parameter': None, 'fields': []}
                    for c in callback_declarations(function, snapshot)
                    for name in ([c['parameter'], c['parameter']+'.'+c.get('field_path', c['field']),
                        c['parameter']+'->'+c.get('field_path', c['field'])] if c['field'] else [c['parameter']])]
            for reason, subjects in roles.items():
                key = [snapshot.functions_fingerprint, fid, parent, reason]
                candidates.append({"candidate_id": "support_candidate_" + digest(key)[:24],
                    "function_id": fid, "function": api["name"], "required_by": parent,
                    "reason": reason, "subject_bindings": sorted({canonical(s): s for s in subjects}.values(), key=canonical),
                    "evidence_ids": sorted(bodies[fid]), "source_status": "issued_complete_body",
                    "relation_strength": "source_subject_effect", "necessity_proven": False})
    fid = requirements[0]["subject_function_id"]
    from .value_roles import origin_catalog
    from .input_pairs import buffer_pairs
    return {"version": VERSION, "subject_function_id": fid,
        "ownership_subjects": ownership_subjects(fid, snapshot),
        "origin_catalog": origin_catalog(snapshot, visible, tools.scope_ids),
        "input_length_choices": buffer_pairs(snapshot.functions[fid]) if fid in bodies else [],
        "subject_evidence_ids": sorted(eid for eid in bodies.get(fid, []) if visible[eid]['tool'] in
            {'get_function', 'read_source_range', 'find_function_argument_usages'}),
        "support_candidates": sorted(candidates, key=canonical),
        "issued_function_ids": sorted(set(bodies) & set(tools.scope_ids) - set(tools.excluded)),
        "parameter_names": [p["name"] for p in snapshot.functions[fid]["parameters"]],
        "evidence_ids": sorted(visible)}


def wire_registry(signed):
    """Origins are already in typed schema/issued_origins; do not repeat them."""
    return {k: v for k, v in signed.items() if k != 'origin_catalog'}


def registry_update(tools):
    signed = wire_registry(registry(tools))
    previous = getattr(tools, '_proposal_registry_sent', None)
    tools._proposal_registry_sent = signed
    if previous is None or previous['subject_function_id'] != signed['subject_function_id']:
        return {'signed_proposal_registry': signed}
    # Evidence records already expose their IDs. Send only changed registry
    # rows, preserving a full current registry in persisted run metadata.
    changes = {k: [v for v in signed[k] if v not in previous[k]] for k in
        ('ownership_subjects', 'support_candidates', 'input_length_choices', 'issued_function_ids', 'evidence_ids', 'subject_evidence_ids')}
    changes = {k: v for k, v in changes.items() if v}
    return {'signed_proposal_registry_delta': changes} if changes else {}


def merge_registry(previous, output):
    """Replay deltas for offline fixtures and readers of persisted messages."""
    if 'signed_proposal_registry' in output:
        return output['signed_proposal_registry']
    result = {**previous}
    for k, rows in output.get('signed_proposal_registry_delta', {}).items():
        result[k] = [*previous.get(k, []), *[r for r in rows if r not in previous.get(k, [])]]
    return result


def match_dependency(proposal, requirement, tools):
    if proposal["function_id"] is None:
        if proposal["necessity"] != "unresolved":
            raise ValueError("support_activation_requires_signed_candidate")
        return None
    rows = [c for c in registry(tools, [requirement])["support_candidates"]
        if all(c[k] == proposal[k] for k in ("function_id", "required_by", "reason"))]
    if len(rows) != 1 or proposal.get("candidate_id", rows[0]["candidate_id"] if rows else None) != (rows[0]["candidate_id"] if rows else None):
        raise ValueError("support_activation_candidate_not_signed")
    return rows[0]


def optional_fields(schema, fields):
    """Canonical artifacts retain expanded subjects; old explicit fixtures work."""
    schema["properties"].update(fields)


def expand_ownership(value, signed):
    subjects = {r["subject_id"]: r for r in signed["ownership_subjects"]}
    for entry in value["entries"]:
        row = subjects[entry["subject_id"]]
        entry.update({k: row[k] for k in ("parameter", "return_value", "field", "subject_kind")})
    return value
