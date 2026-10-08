"""Source-issued role choices; selecting one never silently repairs a proposal."""
from ..semantic_discovery.models import digest, canonical, DecisionSchemaError, TerminalSelectionError
from ..semantic_discovery.tools import _schema
from .core_proofs import inclusion_proofs, source_evidence
from .support_effects import bindings

VERSION = 'slice-role-choices-v7'


class SliceChoiceSelectionError(TerminalSelectionError):
    terminal_repair_category = 'slice_role_choice_not_issued'

    def __init__(self, index, received):
        super().__init__('slice_role_choice_not_issued')
        self.index, self.received = index, received

    def to_dict(self):
        return {'error': self.terminal_repair_category,
                'field': f'classification[{self.index}].choice_id', 'received': self.received,
                'instruction': 'Select an exact currently issued choice yourself; no ID is repaired or selected for you.'}


REASONS = {'creation': 'resource_creation', 'initialization': 'required_initialization',
    'cleanup': 'resource_cleanup', 'configuration': 'minimal_configuration', 'other': 'required_initialization'}


def _choice_id(tools, fid, role, reasons):
    return 'slice_choice_' + digest([tools.index.catalog.source_fingerprint,
        tools.frontier.candidate.function_id, fid, role, reasons])[:24]


def choices(tools):
    anchor = tools.frontier.candidate.function_id
    functions = tools.index.functions
    bodies = {fid: source_evidence(fid, functions, tools.evidence) for fid in tools.authorized_ids}
    issued = {fid for fid, eids in bodies.items() if eids}
    from .source_exclusions import exclusion_blockers
    blockers = exclusion_blockers(tools)
    from .effect_questions import returned_resource_questions
    effect_questions = returned_resource_questions(tools)
    rows = []
    def add(fid, role, reasons, eids, **detail):
        row = dict(function_id=fid, function=functions[fid]['name'], role=role,
            reason_codes=reasons, evidence_ids=sorted(set(eids)), **detail)
        # A choice names a semantic alternative, not a revision of its proof.
        # Expansion still requires the alternative to exist in the CURRENT
        # registry and supplies its current evidence/proofs. Additional source
        # reads must not invalidate a choice already shown to the model.
        rows.append({**row, 'choice_id': _choice_id(tools, fid, role, reasons)})
    for fid in sorted(tools.authorized_ids):
        if fid == anchor:
            eids = [eid for eid, r in tools.evidence.items() if r.get('frontier_kind') == 'accepted_anchor' and r.get('function_id') == fid]
            add(fid, 'core', ['accepted_anchor'], eids)
            continue
        detail = {'exclusion_blockers': [{'proof_id': p['proof_id'], 'parent_function_id': p['parent_function_id'],
            'subject_parameter': p['subject_parameter'], 'kind': p['kind'], 'evidence_ids': p['evidence_ids']}
            for p in blockers[fid]]} if fid in blockers else {}
        if fid in effect_questions:
            detail['unresolved_effect_questions'] = effect_questions[fid]
        add(fid, 'unresolved', ['insufficient_evidence'], bodies[fid], **detail)
        if fid in issued and fid not in blockers and fid not in effect_questions:
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
    alternatives = []
    for unresolved in (False, True):
        identities = [r['choice_id'] for r in options if (r['role'] == 'unresolved') == unresolved]
        if not identities:
            continue
        alternatives.append({'type': 'object', 'additionalProperties': False,
            'required': ['choice_id', 'open_questions'], 'properties': {
                'choice_id': {'type': 'string', 'enum': identities},
                'open_questions': {'type': 'array', 'minItems': int(unresolved), 'maxItems': 8,
                    'items': {'type': 'string', 'minLength': 1, 'maxLength': 1024}}}})
    return _schema('submit_semantic_slice',
        'Submit once as the sole native call, without prose. Select at most ONE issued choice per function, '
        'including the mandatory anchor CORE choice. Each unresolved choice needs its own concrete missing-proof '
        'question. Omitted frontier functions remain unresolved; no free roles/reasons or competing alternatives.',
        {'classification': {'type': 'array', 'minItems': 1, 'maxItems': min(256, len(tools.authorized_ids)),
                            'uniqueItems': True, 'items': {'anyOf': alternatives}}},
        ['classification'])


def terminal_guidance(tools):
    """Compact task rules; all role/evidence decisions remain model selections."""
    anchor = tools.frontier.candidate.function_id
    anchor_choice = next(r for r in choices(tools) if r['function_id'] == anchor and r['role'] == 'core')
    return {'mandatory_anchor_choice_id': anchor_choice['choice_id'],
        'one_function_one_choice': 'Select one issued alternative per function, never both unresolved and exclude/core/support.',
        'unresolved_questions': 'Every selected unresolved row needs a concrete missing-proof question; correct ALL reported rows.',
        'source_exclusions': 'An issued exact source resource relation blocks unrelated EXCLUDE. Select SUPPORT only with necessity proof, or UNRESOLVED; no role is assigned for you.',
        'uncertain_return_effects': 'Unresolved effects on an exact returned-object consumer cannot establish unrelated EXCLUDE. Investigate its callee/callback source, or select the issued UNRESOLVED choice; no cleanup necessity is inferred.',
        'compact_submission': 'Use only choice_id and open_questions. No prose, role deliberation, or duplicated source.',
        'unclassified_frontier': 'Omit untouched frontier entries; the framework retains them unresolved. Never infer an unproved role.'}


def expand(rows, tools):
    signed = {r['choice_id']: r for r in choices(tools)}
    result = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {'choice_id', 'open_questions'}:
            raise DecisionSchemaError(f'classification[{index}]', sorted(row) if isinstance(row, dict) else type(row).__name__, ['choice_id', 'open_questions'])
        if not isinstance(row['choice_id'], str) or not row['choice_id']:
            raise DecisionSchemaError(f'classification[{index}].choice_id', row['choice_id'], ['issued choice_id string'])
        if row['choice_id'] not in signed:
            from .source_exclusions import exclusion_blockers, ExclusionEvidenceError
            blockers = exclusion_blockers(tools)
            withdrawn = next((fid for fid in blockers if row['choice_id'] ==
                _choice_id(tools, fid, 'exclude', ['unrelated_behavior'])), None)
            if withdrawn:
                raise ExclusionEvidenceError([{'error': 'source_related_function_excluded',
                    'field': f'classification[{index}].choice_id', 'received': row['choice_id'],
                    'function_id': withdrawn, 'contradictions': blockers[withdrawn]}])
            from .effect_questions import returned_resource_questions, SliceExclusionEffectError
            questions = returned_resource_questions(tools)
            withdrawn = next((fid for fid in questions if row['choice_id'] ==
                _choice_id(tools, fid, 'exclude', ['unrelated_behavior'])), None)
            if withdrawn:
                raise SliceExclusionEffectError(index, row['choice_id'], questions[withdrawn])
            raise SliceChoiceSelectionError(index, row['choice_id'])
        selected = signed[row['choice_id']]
        result.append({k: selected[k] for k in ('function_id', 'role', 'reason_codes', 'evidence_ids')} | {'open_questions': row['open_questions']})
    return result
