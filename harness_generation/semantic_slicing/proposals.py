"""Source-issued role choices; selecting one never silently repairs a proposal."""
from ..semantic_discovery.models import digest, canonical
from ..semantic_discovery.tools import _schema
from .core_proofs import inclusion_proofs, source_evidence
from .support_effects import bindings

VERSION = 'slice-role-choices-v1'
REASONS = {'creation': 'resource_creation', 'initialization': 'required_initialization',
    'cleanup': 'resource_cleanup', 'configuration': 'minimal_configuration', 'other': 'required_initialization'}


def choices(tools):
    anchor = tools.frontier.candidate.function_id
    functions = tools.index.functions
    bodies = {fid: source_evidence(fid, functions, tools.evidence) for fid in tools.authorized_ids}
    issued = {fid for fid, eids in bodies.items() if eids}
    rows = []
    def add(fid, role, reasons, eids, **detail):
        row = dict(function_id=fid, function=functions[fid]['name'], role=role,
            reason_codes=reasons, evidence_ids=sorted(set(eids)), **detail)
        rows.append({**row, 'choice_id': 'slice_choice_' + digest(row)[:24]})
    for fid in sorted(tools.authorized_ids):
        if fid == anchor:
            eids = [eid for eid, r in tools.evidence.items() if r.get('frontier_kind') == 'accepted_anchor' and r.get('function_id') == fid]
            add(fid, 'core', ['accepted_anchor'], eids)
            continue
        add(fid, 'unresolved', ['insufficient_evidence'], bodies[fid])
        if fid in issued:
            add(fid, 'exclude', ['unrelated_behavior'], bodies[fid], decision_required='affirmative outside-target behavior; source remains caller evidence')
        proofs = inclusion_proofs(anchor, fid, functions, tools.evidence)
        if proofs:
            add(fid, 'core', ['core_data_dependency'], [e for p in proofs for e in p['evidence_ids']], core_inclusion_proof=proofs)
        effects = bindings(functions[anchor], functions[fid], functions, issued)
        for reason, subjects in effects.items():
            add(fid, 'support', [REASONS[reason]], bodies[fid] + bodies[anchor],
                subject_bindings=subjects, necessity_proven=False)
    return sorted(rows, key=canonical)


def terminal_schema(tools):
    options = choices(tools)
    return _schema('submit_semantic_slice',
        'Select framework-issued choice_id per classified API. Anchor is mandatory. Unresolved choices need open_questions. No free roles/reasons.',
        {'classification': {'type': 'array', 'minItems': 1, 'maxItems': 256, 'items': {
            'type': 'object', 'additionalProperties': False, 'required': ['choice_id', 'open_questions'],
            'properties': {'choice_id': {'type': 'string', 'enum': [r['choice_id'] for r in options]},
                'open_questions': {'type': 'array', 'maxItems': 8, 'items': {'type': 'string', 'minLength': 1, 'maxLength': 1024}}}}}},
        ['classification'])


def expand(rows, tools):
    signed = {r['choice_id']: r for r in choices(tools)}
    result = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'choice_id', 'open_questions'} or row['choice_id'] not in signed:
            raise ValueError('slice_role_choice_not_issued')
        selected = signed[row['choice_id']]
        result.append({k: selected[k] for k in ('function_id', 'role', 'reason_codes', 'evidence_ids')} | {'open_questions': row['open_questions']})
    return result
