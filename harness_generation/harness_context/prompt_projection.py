"""Compact agent views; original certificates/evidence and Gate inputs stay intact."""
from copy import deepcopy

VERSION = "context-prompt-projection-v9"


def proposal_view(facts, graph=None, preview=None):
    """Describe observed claims without promoting a proved sibling to authority.

    Aggregate requirement nodes can contain validated proposals while proving
    only one part of their value. Only exact granular construction/ownership
    certificates with an unchanged projected row cover a complete row here.
    This transport annotation is never an input to the Gate or reconciliation.
    """
    from .evidence import CONTRACT_FIELDS
    nodes = (graph or {}).get('nodes', [])
    preview = preview or {}
    result = []
    for fact in facts:
        kind = fact['predicate']
        matching = [n for n in nodes if n.get('requirement_id') == fact['requirement_id']
                    and n.get('subject_function_id') == fact['function_id']
                    and fact['fact_id'] in n.get('fact_ids', [])]
        section, collection = CONTRACT_FIELDS.get(kind, ('', ''))
        rows = fact['value'].get(collection, []) if collection else []
        claims = []
        for index, row in enumerate(rows):
            parameter = row.get('parameter', row.get('subject_parameter'))
            projected = [p for p in preview.get(section, {}).get(collection, [])
                         if p.get('fact_id') == fact['fact_id']
                         and all(p.get(k) == row.get(k) for k in
                                 ('parameter', 'subject_parameter', 'return_value', 'field', 'subject_id'))]
            unchanged = bool(projected) and all(all(p.get(k) == v for k, v in row.items()) for p in projected)
            exact = []
            for node in matching:
                if node.get('subject_parameter') != parameter or node.get('subject_field') != row.get('field'):
                    continue
                proof = node.get('local_proof', {})
                if node.get('proof_status') != 'proved' or proof.get('status') != 'proved':
                    continue
                sources = proof.get('sources', [])
                construction = kind == 'argument_construction' and node.get('predicate') == 'parameter_recipe' and any(
                    s.get('kind') == 'canonical_construction' and s.get('reason') == 'graph_semantic_agreement'
                    and s.get('proof_digest') for s in sources)
                ownership = kind == 'ownership' and node.get('predicate') == 'ownership_subject' and any(
                    s.get('kind') == 'source_checked_ownership_projection'
                    and fact['fact_id'] in s.get('semantic_fact_ids', []) for s in sources)
                if unchanged and (construction or ownership):
                    exact.append(node)
            claims.append({'field_path': 'value.' + collection + '[' + str(index) + ']',
                           'subject_parameter': parameter, 'subject_field': row.get('field'),
                           'proof_status': 'proved' if exact else 'unverified',
                           'covered_fields': sorted(row) if exact else [],
                           'obligation_ids': sorted(n['obligation_id'] for n in exact),
                           'evidence_ids': sorted({e for n in exact for e in n.get('evidence_ids', [])})})
        covered = [r for r in claims if r['proof_status'] == 'proved']
        status = ('proved' if claims and len(covered) == len(claims) else
                  'partial' if covered else 'unverified')
        # Collection metadata has no granular certificate in this projection.
        if set(fact['value']) - {collection}:
            status = 'partial' if covered else 'unverified'
        result.append({**deepcopy(fact), 'proof_status': status, 'claim_proofs': claims,
                       'graph_obligations': [{'obligation_id': n['obligation_id'],
                                              'predicate': n.get('predicate'),
                                              'proof_status': n.get('proof_status')}
                                             for n in matching],
                       'proof_rule': 'Graph status covers only the exact listed claims. Uncovered fields and observed proposals require ordinary source validation.'})
    return result


def resource_identity_view(function, facts, preview, catalog, graph=None):
    """Select issued defaults or existing exact endpoint certificates only.

    A lifecycle proposal is an observation, not an identity certificate. Source
    origin choices are kept separate from proof that two endpoints share an
    object. Neither proposed creator names nor types authorize aliasing.
    """
    from .models import resource_id
    from .evidence import CONTRACT_FIELDS
    from ..semantic_discovery.models import canonical
    fid = function['id']
    subjects = [(p['name'], False) for p in function.get('parameters', [])] + [(None, True)]
    proposals = {p['fact_id']: p for p in proposal_view(facts, graph, preview)}
    observed = []
    for fact in facts:
        _, collection = CONTRACT_FIELDS.get(fact['predicate'], ('', ''))
        for index, row in enumerate(fact['value'].get(collection, []) if collection else []):
            rid = row.get('resource_id')
            if not rid:
                continue
            parameter = row.get('parameter', row.get('subject_parameter'))
            creator = row.get('creation', {}).get('api') or (row.get('api') if row.get('construction') == 'creator_api' else None)
            if fact['function_id'] != fid and creator != fid:
                continue
            proof = next((p for p in proposals[fact['fact_id']]['claim_proofs']
                          if p['field_path'] == 'value.' + collection + '[' + str(index) + ']'), None)
            observed.append({'fact_id': fact['fact_id'], 'requirement_id': fact['requirement_id'],
                             'kind': fact['predicate'], 'function_id': fact['function_id'],
                             'subject_parameter': parameter, 'subject_field': row.get('field'),
                             'return_value': bool(row.get('return_value')), 'resource_id': rid,
                             'creator_api': creator, 'proof_status': proof['proof_status'] if proof else 'unverified',
                             'source_issued_origin': deepcopy(catalog.get(rid)),
                             'evidence_ids': deepcopy(fact.get('evidence_ids', []))})
    selected, choices = {}, []
    for parameter, returned in subjects:
        key = 'return_value' if returned else parameter
        default = resource_id(fid, parameter)
        origin = catalog.get(default, {}).get('origin', {})
        default = default if (origin.get('function_id') == fid and origin.get('parameter') == parameter
                              and origin.get('kind') == ('return' if returned else 'parameter')) else None
        certificates = []
        for binding in preview.get('resource_identity', {}).get('bindings', []):
            reason = binding.get('reason', '')
            if (binding.get('function_id') == fid and binding.get('parameter') == parameter
                    and binding.get('return_value') == returned and binding.get('resource_id') in catalog
                    and binding.get('evidence_ids') and (reason.startswith('source_') or reason in
                            {'single_harness_owned_return_binding', 'unique_owned_return_release_binding'})):
                certificates.append({'resource_id': binding['resource_id'], 'kind': 'source_endpoint_binding',
                                     'reason': reason, 'evidence_ids': deepcopy(binding['evidence_ids']),
                                     **({'candidate_ids': deepcopy(binding['candidate_ids'])} if binding.get('candidate_ids') else {})})
        for row in preview.get('canonical_construction', {}).get('parameters', []):
            rid = (row.get('recipe') or {}).get('resource_id')
            if (not returned and row.get('function_id') == fid and row.get('parameter') == parameter
                    and row.get('status') == 'resolved' and rid in catalog and row.get('proof_digest')
                    and row.get('evidence_ids')):
                certificates.append({'resource_id': rid, 'kind': 'resolved_canonical_construction',
                                     'reason': row.get('reason'), 'proof_digest': row['proof_digest'],
                                     'evidence_ids': deepcopy(row['evidence_ids'])})
        certificates = sorted({canonical(c): c for c in certificates}.values(), key=canonical)
        proved_ids = {c['resource_id'] for c in certificates}
        local = [o for o in observed if o['function_id'] == fid and o['subject_parameter'] == parameter
                 and o['return_value'] == returned and o['subject_field'] is None]
        proposed_ids = {o['resource_id'] for o in local}
        if len(proved_ids) > 1:
            value, status = None, 'ambiguous_certificates'
        elif proved_ids:
            value, status = next(iter(proved_ids)), 'certified_endpoint'
        elif len(proposed_ids) > 1:
            value, status = None, 'ambiguous_observed_proposals'
        else:
            value, status = default, 'issued_default' if default else 'unresolved'
        selected[key] = value
        ids = proposed_ids | proved_ids | ({default} if default else set())
        choices.append({'function_id': fid, 'subject_parameter': parameter, 'return_value': returned,
                        'selected_resource_id': value, 'selection_status': status,
                        'source_issued_default': default, 'certificates': certificates,
                        'observed_fact_ids': sorted(o['fact_id'] for o in local),
                        'observed_conflict': len(proposed_ids) > 1,
                        'issued_options': [{'resource_id': rid, **deepcopy(catalog[rid])}
                                           for rid in sorted(ids) if rid in catalog]})
    return {'resource_ids': selected, 'subjects': choices,
            'observed_resource_choices': sorted(observed, key=canonical),
            'rule': 'resource_ids are issued defaults or exact existing endpoint certificates. An issued option is not an alias proof, a default is not a runtime binding, and observed resource choices do not select facts. Resolve ambiguity through ordinary typed proposals and source checks; never merge by type, creator, or answer order.'}


def feedback_view(feedback):
    result = deepcopy(feedback)
    for item in result.get('items', []):
        # Linked subjects can lie outside the primary function's proposal view.
        # Keep their exact old value, including fields omitted by a narrow
        # correction target, so conflict feedback survives guarded transport.
        targeted = {t.get('fact_id') for t in item.get('correction_targets', [])}
        if item.get('current_facts'):
            item['current_facts'] = [f for f in item['current_facts'] if f.get('fact_id') in targeted]
        item.pop('preserve_fact_ids', None)
        # The persistence ledger is not investigation context. Repeating every
        # active FT fact ID in each feedback item adds no subject proof.
        item.pop('active_fact_ids', None)
    return result


def diagnostic_view(row):
    """Keep exact subject/error identities, without repeated question/graph dumps."""
    keys = {"code", "kind", "subject_function_id", "subject_parameter", "subject_field",
            "requirement_id", "parameter", "parameter_id", "reason", "resource_id", "detail"}
    result = {k: deepcopy(v) for k, v in row.items() if k in keys}
    if row.get("graph_holes"):
        result["graph_holes"] = [diagnostic_view(h) for h in row["graph_holes"]]
    if row.get('closure_feedback'):
        result['closure_feedback'] = feedback_view(row['closure_feedback'])
    return result


def proof_view(row):
    result = {k: deepcopy(v) for k, v in row.items() if k != "diagnostics"}
    result["diagnostics"] = [diagnostic_view(d) for d in row.get("diagnostics", [])]
    return result


def task_view(row, *, include_proofs=True):
    result = {k: deepcopy(v) for k, v in row.items()
              if k not in {"missing_proofs", "question", "graph_holes"}}
    if include_proofs:
        result["missing_proofs"] = [proof_view(p) for p in row.get("missing_proofs", [])]
    result["validation_diagnostics"] = [diagnostic_view(d) for d in row.get("validation_diagnostics", [])]
    if row.get("graph_holes"):
        result["graph_holes"] = [diagnostic_view(h) for h in row["graph_holes"]]
    if row.get('closure_feedback'):
        result['closure_feedback'] = feedback_view(row['closure_feedback'])
    return result


def obligation_view(view):
    result = deepcopy(view)
    for group in ("proved", "missing_evidence", "blocked"):
        result[group] = [{k: deepcopy(v) for k, v in row.items()
                          if k not in {"question", "diagnostics", "fact_ids"}}
                         for row in view.get(group, [])]
    return result


def agenda_view(agenda):
    result = deepcopy(agenda)
    for slot in result["slots"]:
        slot["missing_proofs"] = [proof_view(p) for p in slot["missing_proofs"]]
        if slot.get('closure_feedback'):
            slot['closure_feedback'] = feedback_view(slot['closure_feedback'])
    return result


COMMON_CONTRACT_GUIDANCE = (
    "Observed proposals are claims; only exact claim_proofs cover their listed subjects/fields. Preserve proved entries; a proved sibling does not prove the whole value.",
    "Issued resource defaults/origins are not alias proofs or runtime bindings. Never merge by type, creator or answer order; conflicting origins need source evidence.",
    "Use signed subject/candidate IDs and subject_evidence_ids. upstream_excluded/scope blockers grant no APIs or evidence; report the exact unavailable effect unresolved without changing frozen scope or identities.",
    "Use the supplied typed schema for each slot. Missing proof uses that slot's unresolved_template, facts=[] and exact open_questions. Correct every reported schema error.",
)

# Explicit predicate ownership avoids dropping a rule because its text lacks an
# incidental keyword. These are terminal reminders, not new semantic authority.
CONTRACT_GUIDANCE_BY_KIND = {
    "input_binding": (
        "Input data/extent match buffer_length exactly; flags are not extents. Context/returned objects carry input through source=context/derived, not fuzz_data.",
        "Prove NUL, units, mutability, alignment and exact pointer lifetime. Retained input uses until_release/until_context_cleanup, not during_call; incomplete access evidence stays unresolved.",
    ),
    "buffer_length": (
        "Bind the actual buffer and declared scalar length_parameter consistently with input_binding.size_parameter; a derived scalar label alone does not connect them.",
        "Output/storage capacity links need full length_parameter, requires_nul_termination and binary_zero_allowed fields; they need no input_binding and never make output storage fuzz_data.",
    ),
    "argument_construction": (
        "Account for all declared parameters with exact canonical recipes/issued origins. FuzzInput, Constant, CallbackObject and PointerStorage use null resource IDs; their address cells are not owned pointees.",
        "A derived extent still needs the source-proved buffer_length.length_parameter link. Internal source-certified invocations use enclosing API execution and source-owned storage, not extra calls.",
    ),
    "ownership": (
        "Select signed ownership subject_id: creator return/out pointee differs from consumer parameter. Deallocator's consumed pointer is transferred; its address cell is not allocated ownership.",
        "Owned until_release returns need exact proved release_api consistent with lifecycle cleanup. Creator ownership or later caller release does not make a consumer owned/transferred; callback userdata requires complete synchronous forwarding and exact handler effects.",
    ),
    "lifecycle": (
        "An API's own allocated return uses creation.kind=creator_api and creation.api=this API. Preserve proved creation/init/reuse/resource fields while correcting cleanup; full rows cannot use null to retain old fields.",
        "Keep identity separate from invocation initialization. Internal creator writes need no additional initialization API; a fresh object created/released per input uses per_input. Missing owned-return release stays unresolved, never optional by default.",
    ),
    "state": (
        "Prove the exact field/precondition on the same object and required paths; another field/object or resource identity does not prove invocation state.",
    ),
    "callback": (
        "Use the exact declared callback owner/field/ABI. callback.userdata is the actual source parameter/member, such as user or ctx.userdata; do not substitute a resource ID.",
        "Invocation-specific target certificates do not prove lifetime or cleanup. A source-certified callback implementation executes as a function value through its enclosing API, not a separate initialization call.",
    ),
    "return_semantics": (
        "Pointer returns need explicit nullable/owned/error_cleanup. Scalar nullable/owned may be null; an ordinary no-failure numeric result uses success=always and error_cleanup=false when source-proved.",
    ),
    "call_order": (
        "before/after use this slot's exact issued_function_ids. Read an absent authorized consumer body before submission; never drop a required consumer edge just to fit enums. Unknown source relations stay unresolved.",
        "must_precede calls before then after; must_follow reverses them. Prove minimal create/init→use→cleanup by exact dependencies, not shared types or caller preference.",
    ),
    "support_decision": (
        "value.decision is required/optional/rejected/unresolved. Select only exact matching subjects/roles supported by THIS item's facts; signatures do not prove necessity and internally executed helpers need no extra harness call.",
    ),
}


def terminal_guidance(requirements, *, terminal_name=None):
    kinds = sorted({row["kind"] for row in requirements})
    unknown = set(kinds) - set(CONTRACT_GUIDANCE_BY_KIND)
    if unknown:
        raise ValueError("missing terminal guidance for requirement kinds: " + ", ".join(sorted(unknown)))
    name = terminal_name or ("submit_requirement_resolution" if len(requirements) == 1
                             else "submit_requirement_resolutions")
    return {"terminal_name": name,
        "slots": {"r" + str(i): r["kind"] for i, r in enumerate(requirements)},
        "format": "One compact native " + name + " call with resolutions={r0: typed_resolution, ...}. Every supplied slot exactly once. No prose or repeated dependencies.",
        "contracts": [*COMMON_CONTRACT_GUIDANCE,
            *(rule for kind in kinds for rule in CONTRACT_GUIDANCE_BY_KIND[kind])]}
