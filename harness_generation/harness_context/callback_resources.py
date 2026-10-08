"""An erased callback parameter references one explicitly owned creator result."""
from copy import deepcopy

from ..semantic_discovery.models import canonical, digest
from .resource_identity import _cleanup_source_view, exact_cleanup_connection

VERSION = 'source-callback-resource-reference-v1'


def prove_callback_resource_reference(context, binding, snapshot, records):
    """Bridge identity only, without adding lifecycle, ownership or a fuzz root.

    A typed/opaque context still needs its own lifecycle. Only an erased
    callback slot with exact synchronous source forwarding and a selected
    owned return's complete allocation/release chain can use this certificate.
    Existing consumer lifecycle rows are never bypassed, including conflicts.
    """
    if any(not isinstance(row, dict) or row.get('evidence_id') != eid
           for eid, row in records.items()):
        return None
    fid, parameter, producer = binding['function_id'], binding['parameter'], binding.get('via_function_id')
    if (binding.get('source') != 'context' or binding.get('transform') != 'none'
            or binding.get('size_parameter') is not None or binding.get('size_relation') != 'none'
            or producer not in snapshot.functions or fid not in snapshot.functions or fid not in context['core_apis']):
        return None
    declared = [p for p in snapshot.functions[fid]['parameters'] if p['name'] == parameter]
    if (len(declared) != 1 or declared[0].get('base_type') != 'void'
            or declared[0].get('pointer_depth') != 1 or declared[0].get('is_struct_like')
            or declared[0].get('is_opaque_handle')):
        return None
    lifetimes = context['lifecycle_contract']['resources']
    if any(row['function_id'] == fid and row['subject_parameter'] == parameter for row in lifetimes):
        return None
    selected = [row for row in context['canonical_construction']['parameters']
        if row['function_id'] == fid and row['parameter'] == parameter]
    if len(selected) != 1 or selected[0]['status'] != 'resolved':
        return None
    recipe = selected[0].get('recipe') or {}
    if recipe.get('kind') != 'creator_call' or recipe.get('producer_api') != producer or not recipe.get('resource_id'):
        return None
    rid = recipe['resource_id']
    resources = [row for row in lifetimes if row['function_id'] == producer
        and row['return_value'] and row['subject_parameter'] is None]
    if len(resources) != 1:
        return None
    resource = resources[0]
    cleanup = resource['cleanup']['api']
    if (resource['resource_id'] != rid or resource['creation'] != {'kind': 'creator_api', 'api': producer}
            or not resource['cleanup']['mandatory'] or cleanup not in snapshot.functions
            or resource['reuse'] == 'unknown' or resource['type'] != snapshot.functions[producer].get('return_base_type')
            or snapshot.functions[producer].get('return_pointer_depth') != 1):
        return None
    owners = [row for row in context['ownership_contract']['entries'] if row['function_id'] == producer
        and row['return_value'] and row.get('parameter') is None and row.get('field') is None]
    consumers = [row for row in context['ownership_contract']['entries'] if row['function_id'] == fid
        and not row['return_value'] and row.get('parameter') == parameter and row.get('field') is None]
    if (len(owners) != 1 or owners[0].get('subject_kind') != 'PointerReturn'
            or owners[0]['ownership'] != 'owned' or owners[0]['lifetime'] != 'until_release'
            or owners[0]['release_api'] != cleanup or owners[0]['resource_id'] != rid
            or len(consumers) != 1 or consumers[0].get('subject_kind') != 'PointerParameter'
            or consumers[0]['ownership'] != 'borrowed' or consumers[0]['lifetime'] != 'during_call'
            or consumers[0]['release_api'] is not None or consumers[0]['resource_id'] != rid):
        return None
    builder, graph = _cleanup_source_view(context, snapshot, records)
    connection = exact_cleanup_connection(context, snapshot, records, fid, parameter, False, cleanup,
                                         _view=(builder, graph))
    if not connection or connection['creator_api'] != producer or connection['resource_id'] != rid:
        return None
    nodes = {node['node_id']: node for node in graph['nodes']}
    resolved = [row for row in graph['dependency_graph']['resolved_parameters']
        if nodes[row['target_parameter']]['function_id'] == fid
        and nodes[row['target_parameter']].get('name') == parameter
        and row.get('basis') == 'callback_parameter_forwarding']
    if len(resolved) != 1:
        return None
    target, source = nodes[resolved[0]['target_parameter']], nodes[resolved[0]['source_node']]
    # Forwarding rows are parameter edges, not resource origins. Follow their
    # authenticated source slot to one call-site origin; a model RID on either
    # consumer cannot supply the missing source proof. The cleanup connection
    # independently authenticates every forwarding descriptor and effect.
    candidate, seen = resolved[0], set()
    while candidate.get('basis') in {'callback_parameter_forwarding', 'internal_parameter_forwarding'}:
        if candidate['target_parameter'] in seen:
            return None
        seen.add(candidate['target_parameter'])
        incoming = [row for row in graph['dependency_graph']['resolved_parameters']
                    if row['target_parameter'] == candidate['source_node']]
        if len(incoming) != 1:
            return None
        candidate = incoming[0]
    if (candidate.get('basis') != 'call_site_value_flow' or candidate.get('resource_id') != rid
            or candidate.get('caller_id') != connection['caller_id']):
        return None
    origins = [row['origin'] for row in graph['resource_origins'] if row['resource_id'] == rid]
    if (len(origins) != 1 or origins[0].get('kind') != 'return'
            or origins[0].get('function_id') != producer
            or origins[0].get('caller_id') != connection['caller_id']
            or origins[0].get('call_offset') != connection['creator_call_offset']):
        return None
    dispatches = [row for row in graph['callback_dispatches'] if row['proof_status'] == 'proven'
        and row['function_id'] == fid and row['via_function_id'] == source['function_id']
        and row.get('calls_per_invocation') == 1
        and {'parameter': parameter, 'via_parameter': source['name']} in row['parameter_forwarding']]
    if len(dispatches) != 1 or dispatches[0] not in context['argument_graph'].get('callback_dispatches', []):
        return None
    source_selected = [row for row in context['canonical_construction']['parameters']
        if row['function_id'] == source['function_id'] and row['parameter'] == source['name']]
    if (len(source_selected) != 1 or source_selected[0]['status'] != 'resolved'
            or any(source_selected[0]['recipe'].get(key) != recipe.get(key)
                   for key in ('kind', 'producer_api', 'resource_id'))):
        return None
    certificate = {'version': VERSION, 'source_fingerprint': snapshot.source_fingerprint,
        'function_id': fid, 'parameter': parameter, 'producer_api': producer, 'cleanup_api': cleanup,
        'resource_id': rid, 'binding': deepcopy(binding),
        'parameter_id': target['node_id'], 'producer_parameter_id': source['node_id'],
        'callback_dispatch': deepcopy(dispatches[0]), 'source_cleanup_connection': connection,
        'semantic_fact_ids': sorted({row['fact_id'] for row in [owners[0], consumers[0], resource]
                                   if row.get('fact_id')}),
        'evidence_ids': sorted(set(connection['evidence_ids']) | set(dispatches[0]['evidence_ids'])),
        # Plan reauthenticates these complete records against the same snapshot.
        # Retain every issued authenticated record so uniqueness does not drop
        # an additional known origin during independent reconstruction.
        'source_records': [deepcopy(builder.records[eid]) for eid in sorted(builder.records)]}
    certificate['proof_id'] = 'callback_resource_' + digest(certificate)[:24]
    return certificate


def project_callback_resource_references(context, snapshot, records):
    proofs = [prove_callback_resource_reference(context, binding, snapshot, records)
              for binding in context['input_contract']['bindings']]
    context['callback_resource_references'] = sorted([proof for proof in proofs if proof], key=canonical)
