"""Subtractive evaluation interventions, isolated in a fresh worker process.

Gate/validators/prompts/tool schemas are never patched. The same projection
intervention is active during mining, persistence validation and generation.
A keeps model-grounded resource IDs but removes framework identity projection.
B adds existing generic identity projection; both remove construction proofs.
C is byte-for-byte unpatched production behavior.
"""
from copy import deepcopy

DESCRIPTIONS = {
    'A': 'Agent + unchanged validators; model resource IDs; no construction certificates',
    'B': 'A + generic value-flow/resource identity; no high-level construction/state certificates',
    'C': 'current full implementation (no monkeypatches)',
}


def apply(configuration):
    if configuration not in DESCRIPTIONS:
        raise ValueError('unknown ablation')
    if configuration == 'C':
        return
    from harness_generation.harness_context import construction
    # The evidence-gathering preflight and tool registry are held constant.
    construction.local_chains = lambda snapshot, records, allowed: []
    construction.project_construction = lambda context, snapshot, records, allowed: {
        'version': 'evaluation_disabled_construction_v1', 'sources': [], 'local_chains': []}
    construction.covered_requirements = lambda context, requirements, snapshot: []
    from harness_generation.harness_context import resource_identity
    # Remove the owned-return release shortcut and allocation-based reuse
    # normalization too: B measures flow identity, not these high-level rules.
    resource_identity.allocated_return = lambda function, snapshot: False
    resource_identity.releases_parameter = lambda *args, **kwargs: False
    if configuration == 'A':
        def model_ids(context, snapshot, records):
            bindings = [{'function_id': r['function_id'], 'parameter': r['subject_parameter'],
                'return_value': r['return_value'], 'resource_id': r['resource_id'],
                'reason': 'model_grounded_identity_no_framework_projection',
                'evidence_ids': deepcopy(r['evidence_ids'])} for r in context['lifecycle_contract']['resources']]
            return {'version': 'evaluation_model_identity_v1', 'bindings': bindings,
                    'reuse_projections': [], 'value_flow': {'observations': [], 'unresolved': []}, 'unresolved': []}
        resource_identity.resolve_resources = model_ids
