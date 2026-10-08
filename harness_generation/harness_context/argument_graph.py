"""Deterministic argument origins and dependencies over issued source.

This is a bounded, straight-line C value analysis, not SSA. A call return proves
an origin, never ownership. Branches, mutation, indirect calls and unproved
expressions retain holes. IDs are generated here, never submitted by a model.
"""
from collections import defaultdict
from copy import deepcopy
import re

from ..semantic_discovery.models import canonical, digest
from ..semantic_discovery.tools import _walk, _text
from .value_flow import body_tree, complete_bodies, unique_callee
from .resource_identity import releases_parameter

VERSION = "argument-construction-graph-v6"
DEPENDENCY_VERSION = "harness-dependency-graph-v1"
NODE_TYPES = ("Function", "Parameter", "ReturnValue", "OutParameter", "LocalValue",
              "StructField", "Resource", "FuzzInput", "Constant", "CallbackObject", "Allocator")
EDGE_TYPES = ("produces", "assigned_to", "aliases", "passed_as", "stored_into", "loaded_from",
              "derived_from", "consumed_by", "released_by", "initialized_by", "feeds")
SOURCE_KINDS = ("fuzz_bytes", "fuzz_size", "constant", "derived_scalar", "local_stack_object",
    "zero_initialized_object", "creator_return", "out_parameter", "existing_resource",
    "callback_object", "struct_field", "allocator_object", "unknown")
FAILURE_CODES = ("argument_origin_missing", "argument_origin_ambiguous", "creator_argument_missing",
    "out_parameter_origin_unknown", "derived_scalar_unknown", "resource_alias_ambiguous",
    "cleanup_consumer_missing", "state_writer_missing", "state_reader_missing", "dependency_cycle")
NONLINEAR = {"if_statement", "switch_statement", "for_statement", "while_statement", "do_statement",
             "goto_statement", "preproc_if", "preproc_ifdef"}


def parameter_id(fid, index):
    return "parameter_" + digest({"function_id": fid, "parameter_index": index})[:24]


def _id(kind, identity):
    return kind.lower() + "_" + digest(identity)[:24]


def _key(node, source):
    if node is None:
        return None
    if node.type in {"identifier", "field_identifier"}:
        return _text(node, source)
    if node.type == "field_expression":
        base = _key(node.child_by_field_name("argument"), source)
        field = node.child_by_field_name("field")
        return base + "." + _text(field, source) if base and field else None
    return None


def _straight(body):
    return body is not None and not body.has_error and not any(n.type in NONLINEAR for n in _walk(body))


def _nonnull_guard_name(statement, source):
    from .internal_invocations import unwrap
    if statement.type != 'if_statement' or statement.child_by_field_name('alternative') is not None:
        return None
    condition = unwrap(statement.child_by_field_name('condition'))
    if condition is not None and condition.type == 'identifier':
        return _text(condition, source)
    if condition is not None and condition.type == 'binary_expression' and _text(condition.child_by_field_name('operator'), source) == '!=':
        left, right = condition.child_by_field_name('left'), condition.child_by_field_name('right')
        if left.type == 'identifier' and right.type == 'number_literal' and _text(right, source) == '0':
            return _text(left, source)
    return None


def _nullable_call_guards(body, source):
    """Only exact nonnull guards around a straight sequence of direct calls."""
    if body is None or body.has_error:
        return False
    guards = [n for n in _walk(body) if n.type in NONLINEAR]
    if not guards:
        return False
    for guard in guards:
        if guard.parent != body or _nonnull_guard_name(guard, source) is None:
            return False
        consequence = guard.child_by_field_name('consequence')
        statements = consequence.named_children if consequence.type == 'compound_statement' else [consequence]
        statements = [n for n in statements if n.type != 'comment']
        if not statements or any(n.type != 'expression_statement' or len(n.named_children) != 1
                or n.named_children[0].type != 'call_expression'
                or n.named_children[0].child_by_field_name('function').type != 'identifier' for n in statements):
            return False
    return True


class GraphBuilder:
    def __init__(self, context, ft, requirements, snapshot, records):
        self.context, self.ft, self.requirements = context, ft, requirements
        self.snapshot = snapshot
        self.records = {eid: record for eid, record in records.items() if
            eid == 'ev_' + digest({'snapshot': snapshot.source_fingerprint,
                'record': {k:v for k,v in record.items() if k != 'evidence_id'}})[:32]}
        self.bodies = complete_bodies(snapshot, self.records)
        self.release_bodies = {fid: eids for fid, eids in self.bodies.items() if fid not in ft['excluded_functions']}
        self.nodes, self.edges, self.candidates, self.calls = {}, {}, {}, []
        self.diagnostics, self.state_edges, self.wrappers = [], [], []
        self.dispatches = []
        self.internal_invocations = []
        self.params, self.endpoints = {}, defaultdict(list)
        self.functions = {r['function_id'] for r in ft['core_functions'] + ft['support_candidates']}
        self.functions |= set(self.bodies)
        # An excluded callable can still be a complete caller evidence source.
        # Its body is analysed; calls to excluded APIs remain forbidden below.
        self.blocked_parameters = set()

    def node(self, kind, identity, **data):
        nid = _id(kind, identity)
        self.nodes.setdefault(nid, {'node_id': nid, 'node_type': kind, **data})
        return nid

    def edge(self, kind, source, target, eids, **data):
        value = {'kind': kind, 'source': source, 'target': target, 'evidence_ids': sorted(set(eids)),
                 'proof_status': 'proven', **data}
        eid = _id('edge', value)
        self.edges[eid] = {'edge_id': eid, **value}

    def function(self, fid):
        function = self.snapshot.functions[fid]
        fn = self.node('Function', fid, function_id=fid,
            role='active_semantic_core' if fid in self.context['core_apis'] else
                'excluded_source_evidence' if fid in self.ft['excluded_functions'] else 'support_or_evidence')
        for index, parameter in enumerate(function.get('parameters', [])):
            pid = parameter_id(fid, index)
            self.params[fid, parameter['name']] = pid
            self.nodes.setdefault(pid, {'node_id': pid, 'node_type': 'Parameter', 'function_id': fid,
                'parameter_index': index, 'name': parameter['name'],
                'declared_type': parameter.get('declaration', parameter.get('base_type', 'unknown')),
                'base_type': parameter.get('base_type'), 'pointer_depth': parameter.get('pointer_depth', 0),
                'constness': bool(re.search(r'\bconst\b', parameter.get('declaration', ''))),
                'role': 'mandatory_argument' if any(r['subject_function_id'] == fid and r['mandatory']
                    and r['kind'] == 'argument_construction' for r in self.requirements) else 'dependency_argument'})
        return fn

    def candidate(self, target, value, eids, **data):
        if value is None:
            return
        source = value['node']
        entry = {'target_parameter': target, 'source_kind': value['kind'], 'source_node': source,
            'evidence_ids': sorted(set(eids) | set(value.get('evidence_ids', []))),
            'proof_status': value.get('proof_status', 'proven'), 'rejection_reason': value.get('rejection_reason'),
            'dependencies': sorted(set(value.get('dependencies', []))),
            **{k: value[k] for k in ('api', 'resource_id', 'expression', 'constant', 'origin_kind', 'recipe') if k in value}, **data}
        parameter = self.nodes[target]
        if value.get('resource_id'):
            origin = next(n['origin'] for n in self.nodes.values() if n.get('resource_id') == value['resource_id'])
            erased_object_pointer = parameter['base_type']=='void' and parameter['pointer_depth']==origin['pointer_depth']==1
            if not erased_object_pointer and (parameter['base_type'] != origin['type'] or parameter['pointer_depth'] != origin['pointer_depth']):
                entry.update(proof_status='rejected', rejection_reason='value_flow_type_mismatch')
        if ((value['kind']=='fuzz_size' and parameter['pointer_depth']) or
                (value['kind']=='fuzz_bytes' and not parameter['pointer_depth']) or
                (value['kind']=='constant' and parameter['pointer_depth'] and value.get('constant') != 0)):
            entry.update(proof_status='rejected', rejection_reason='value_flow_type_mismatch')
        if value.get('recipe', {}).get('array_elements') and (parameter['pointer_depth'] != 1
                or parameter['base_type'] != value['recipe']['element_type']):
            entry.update(proof_status='rejected', rejection_reason='value_flow_type_mismatch')
        cid = _id('candidate', entry)
        self.candidates[cid] = {'candidate_id': cid, **entry}
        self.edge('passed_as', source, target, entry['evidence_ids'], proof_status=entry['proof_status'])

    def seeded_values(self):
        values = {}
        for binding in self.context['input_contract']['bindings']:
            fid, name = binding['function_id'], binding['parameter']
            if (fid, name) not in self.params or binding['source'] != 'fuzz_data' or binding['transform'] not in {'direct', 'copy', 'nul_terminate'}:
                continue
            if fid not in self.bodies or not set(binding['evidence_ids']) <= self.records.keys():
                continue
            for parameter, kind in ((name, 'fuzz_bytes'), (binding.get('size_parameter'), 'fuzz_size')):
                if (fid, parameter) not in self.params:
                    continue
                if kind=='fuzz_size' and any(link['function_id']==fid and link.get('length_parameter')==parameter
                    and link.get('relation')=='derived' for link in self.context['buffer_length_contract']['links']):
                    continue  # A length of a derived prefix is not the entire fuzz size.
                node = self.node('FuzzInput', [self.ft['ft_id'], kind], source_kind=kind)
                value = {'node': node, 'kind': kind, 'evidence_ids': binding['evidence_ids']}
                if kind == 'fuzz_size':
                    value.update(expression={'op': 'fuzz_size'}, lower=0, upper=None)
                values[fid, parameter] = value
                self.candidate(self.params[fid, parameter], value, binding['evidence_ids'], basis='validated_input_binding')
            # Reproduce a bounded input adapter from an issued caller. This is
            # a harness construction strategy rooted in the target binding,
            # not an assertion that arbitrary caller parameters are fuzz data.
            values.update(self.caller_input_seeds(binding))
        return values

    def caller_input_seeds(self, binding):
        fid = binding['function_id']
        function = self.snapshot.functions[fid]
        names = [p['name'] for p in function['parameters']]
        if binding.get('size_parameter') not in names or binding.get('parameter') not in names:
            return {}
        bi, li = names.index(binding['parameter']), names.index(binding['size_parameter'])
        result = {}
        for caller_id in sorted(self.bodies):
            caller = self.snapshot.functions[caller_id]
            source, body = body_tree(caller)
            if not _straight(body):
                continue
            parameters = {p['name']: p for p in caller['parameters']}
            for call in (n for n in _walk(body) if n.type == 'call_expression'):
                callee = unique_callee(self.snapshot, _text(call.child_by_field_name('function'), source), caller)
                args = call.child_by_field_name('arguments').named_children
                if not callee or callee['id'] != fid or len(args) != len(names):
                    continue
                buffer = _text(args[bi], source)
                p = parameters.get(buffer)
                if args[bi].type != 'identifier' or not p or p.get('pointer_depth') != 1 or p['base_type'] != function['parameters'][bi]['base_type']:
                    continue
                value = args[li]
                seen = set()
                while value.type == 'identifier' and _text(value, source) not in parameters:
                    name = _text(value, source)
                    declarations = [n for n in _walk(body) if n.type == 'init_declarator'
                        and _text(n.child_by_field_name('declarator'), source) == name and n.end_byte < call.start_byte]
                    if name in seen or len(declarations) != 1:
                        break
                    seen.add(name); value = declarations[0].child_by_field_name('value')
                    if value is None:
                        break
                if value is None or value.type != 'conditional_expression':
                    continue
                condition = value.child_by_field_name('condition')
                yes, no = value.child_by_field_name('consequence'), value.child_by_field_name('alternative')
                if condition.type != 'binary_expression':
                    continue
                left, right = condition.child_by_field_name('left'), condition.child_by_field_name('right')
                extent = _text(left, source); q = parameters.get(extent)
                if not q or q.get('is_pointer') or q.get('is_struct_like') or left.type != 'identifier' or right.type != 'number_literal':
                    continue
                if _text(condition.child_by_field_name('operator'), source) not in {'<', '<='} or _text(left, source) != _text(yes, source) or _text(right, source) != _text(no, source):
                    continue
                used = {buffer, extent, *seen}
                if any(n.type in {'assignment_expression', 'update_expression'} and
                       _text(n.child_by_field_name('left') if n.type == 'assignment_expression' else n.named_children[0], source) in used for n in _walk(body)):
                    continue
                eids = sorted(set(binding['evidence_ids']) | set(self.bodies[caller_id]))
                for name, kind in ((buffer, 'fuzz_bytes'), (extent, 'fuzz_size')):
                    node = self.node('FuzzInput', [self.ft['ft_id'], kind], source_kind=kind)
                    entry = dict(node=node, kind=kind, evidence_ids=eids)
                    if kind == 'fuzz_size':
                        entry.update(expression={'op': 'fuzz_size'}, lower=0, upper=None)
                    result[caller_id, name] = entry
        return result

    def callback_value(self, fid, parameter, argument, caller, source):
        """Resolve a passed function value by exact declaration, never by name role."""
        from .callbacks import callback_declarations
        from .evidence import callback_abis
        if fid not in self.bodies or argument.type != 'identifier' or any(p['name'] == _text(argument, source) for p in caller['parameters']):
            return None
        declarations = [d for d in callback_declarations(self.snapshot.functions[fid], self.snapshot)
            if d['parameter'] == parameter['name'] and d['field'] is None]
        target = unique_callee(self.snapshot, _text(argument, source), caller)
        if len(declarations) != 1 or not target or target['id'] not in self.bodies or target['id'] in self.ft['excluded_functions']:
            return None
        if callback_abis(declarations[0]['signature']) != callback_abis(target['signature']):
            return None
        node = self.node('CallbackObject', [fid, parameter['name'], target['id']],
            source_kind='callback_object', function_id=target['id'], callback_id=declarations[0]['callback_id'])
        return dict(node=node, kind='callback_object', api=target['id'],
            evidence_ids=sorted(self.bodies[fid] | self.bodies[target['id']]))

    def callback_dispatch(self, callee, call):
        """Reproduce one synchronous indirect call and its exact parameter forwarding."""
        source, body = body_tree(callee)
        if callee['id'] not in self.bodies or not _straight(body):
            return
        # This schedule certifies a thin synchronous dispatcher. Storage,
        # additional calls and early returns need a richer lifetime schedule.
        if len([n for n in body.named_children if n.type != 'comment']) != 1:
            return
        for name, value in call['arguments'].items():
            if value.get('kind') != 'callback_object' or not value.get('api'):
                continue
            indirect = [n for n in _walk(body) if n.type == 'call_expression'
                and _text(n.child_by_field_name('function'), source) == name]
            if len(indirect) != 1:
                continue
            if indirect[0].parent.type not in {'return_statement', 'expression_statement'}:
                continue
            parameters = {p['name'] for p in callee['parameters']}
            if any(n.type in {'assignment_expression', 'update_expression'} and
                   _text(n.child_by_field_name('left') if n.type == 'assignment_expression' else n.named_children[0], source) in parameters
                   for n in _walk(body)):
                continue
            target = self.snapshot.functions[value['api']]
            self.function(target['id'])
            args = indirect[0].child_by_field_name('arguments').named_children
            if len(args) != len(target['parameters']) or any(a.type != 'identifier'
                    or (callee['id'], _text(a, source)) not in self.params for a in args):
                continue
            eids = sorted(set(call['evidence_ids']) | self.bodies[callee['id']] | self.bodies[target['id']])
            forwarding = []
            for parameter, argument in zip(target['parameters'], args):
                parent_name = _text(argument, source)
                parent = self.params[callee['id'], parent_name]
                self.candidate(self.params[target['id'], parameter['name']],
                    dict(node=parent, kind='existing_resource', dependencies=[parent]), eids,
                    basis='callback_parameter_forwarding', caller_id=callee['id'])
                forwarding.append(dict(parameter=parameter['name'], via_parameter=parent_name))
            self.dispatches.append(dict(function_id=target['id'], via_function_id=callee['id'],
                callback_parameter=name, parameter_forwarding=forwarding, calls_per_invocation=1,
                evidence_ids=eids, proof_status='proven'))

    def semantic_candidates(self):
        # Existing validated propositions remain distinct from mechanical proof.
        # They supply candidate mechanisms but cannot invent graph identities.
        for argument in self.context['argument_contract']['arguments']:
            fid, name = argument['function_id'], argument['parameter']
            if (fid, name) not in self.params:
                continue
            construction, eids = argument['construction'], argument['evidence_ids']
            if fid not in self.bodies or not set(eids) <= self.records.keys():
                continue
            kind = {'stack': 'local_stack_object', 'zero_init': 'zero_initialized_object',
                    'callback': 'callback_object', 'creator_api': 'creator_return', 'constant': 'constant'}.get(construction)
            if not kind:
                continue
            if kind in {'local_stack_object','zero_initialized_object'} and self.snapshot.functions[fid]['file'].endswith(('.cc','.cpp','.cxx','.hpp')):
                continue
            api = argument.get('api')
            if kind == 'creator_return':
                # A semantic API suggestion alone is not a runtime-origin proof.
                continue
            if kind == 'constant' and type(argument.get('constant')) not in {int, bool}:
                continue
            node_kind = 'CallbackObject' if kind == 'callback_object' else 'Constant' if kind == 'constant' else 'LocalValue'
            node = self.node(node_kind, [fid, name, kind, argument.get('constant')], source_kind=kind)
            self.candidate(self.params[fid, name], {'node': node, 'kind': kind,
                'proof_status': 'candidate',
                **({'constant': argument['constant']} if kind == 'constant' else {})}, eids,
                basis='validated_semantic_fact', fact_id=argument['fact_id'])

    def construction_strategies(self):
        """Reproduce a planned creator call when no caller origin was observed.

        This proves a construction mechanism, not an observed runtime alias or
        ownership. Existing resource bindings and cleanup proofs fix the slot;
        every producer argument still has to close recursively.
        """
        from .models import resource_id
        from ..semantic_slicing.support_effects import bindings
        resources = self.context['lifecycle_contract']['resources']
        for argument in self.context['argument_contract']['arguments']:
            fid, name, rid = argument['function_id'], argument['parameter'], argument.get('resource_id')
            if fid not in self.bodies or not rid or (fid, name) not in self.params:
                continue
            source = next((s for s in self.context.get('construction_contract', {}).get('sources', [])
                if s.get('verified') is True and s['function_id'] == fid and s['parameter'] == name
                and s['kind'] == 'cleanup_consumption' and s['resource_id'] == rid), None)
            api = argument.get('api') if argument['construction'] == 'creator_api' else source.get('creator_api') if source else None
            if api not in self.bodies or api in self.ft['excluded_functions']:
                continue
            # A declaration recipe cannot replace or collapse observed instances.
            if not (source and source.get('binding_scope') == 'single_harness_invocation') and any(n['node_type'] == 'Resource' and n['origin']['function_id'] == api
                   and 'caller_id' in n['origin'] for n in self.nodes.values()):
                continue
            parent, producer = self.snapshot.functions[fid], self.snapshot.functions[api]
            effects = bindings(parent, producer, self.snapshot.functions, set(self.bodies)).get('creation', [])
            if not any(e['parameter'] == name and e['effect'] == 'pointer_return' for e in effects):
                continue
            origin = dict(function_id=api, kind='return', parameter=None,
                type=producer.get('return_base_type'), pointer_depth=producer.get('return_pointer_depth'))
            declared = {resource_id(api), 'resource_' + digest(origin)[:24]}
            constructed = any(b['function_id'] == api and b.get('return_value') and b['resource_id'] == rid
                and b['reason'] == 'unique_harness_creator_binding'
                for b in self.context.get('resource_identity', {}).get('bindings', []))
            if rid not in declared and not constructed and not source:
                continue
            # The independently projected cleanup proof carries the same slot.
            if source and source['creator_api'] != api:
                continue
            eids = sorted(self.bodies[fid] | self.bodies[api] | (set(source['evidence_ids']) if source else set()))
            node = self.node('Resource', rid, resource_id=rid, origin=origin,
                ownership='unresolved', proof_basis='planned_creator_strategy', evidence_ids=eids)
            deps = [self.params[api, p['name']] for p in producer['parameters']]
            self.candidate(self.params[fid, name], dict(node=node, kind='creator_return', api=api,
                resource_id=rid, dependencies=deps), eids, basis='source_checked_creator_strategy')
            self.edge('produces', self.function(api), node, eids)

    def flow(self, caller_id, seeds):
        caller = self.snapshot.functions[caller_id]
        source, body = body_tree(caller)
        eids = sorted(self.bodies[caller_id])
        if caller['file'].endswith(('.cc','.cpp','.cxx','.hpp')):
            self.diagnostics.append({'code':'resource_alias_ambiguous', 'function_id':caller_id,
                'reason':'cpp_construction_unmodelled', 'evidence_ids':eids})
            return
        if not _straight(body) and not _nullable_call_guards(body, source):
            self.diagnostics.append({'code': 'resource_alias_ambiguous', 'function_id': caller_id,
                'reason': 'branch_loop_or_unparsed_body', 'evidence_ids': eids})
            return
        env, writes = {}, defaultdict(int)
        for parameter in caller.get('parameters', []):
            pid = self.params[caller_id, parameter['name']]
            env[parameter['name']] = seeds.get((caller_id, parameter['name'])) or {
                'node': pid, 'kind': 'existing_resource', 'dependencies': [pid]}

        def local(name, value, node, declaration=False, object_type=None):
            writes[name] += 1
            if writes[name] > 1:
                env[name] = {'node': self.node('LocalValue', [caller_id, name], function_id=caller_id, name=name),
                    'kind': 'unknown', 'proof_status': 'rejected', 'rejection_reason': 'reassignment'}
                self.diagnostics.append({'code': 'resource_alias_ambiguous', 'function_id': caller_id,
                    'local': name, 'reason': 'reassignment', 'evidence_ids': eids})
                return
            kind = 'StructField' if '.' in name else 'LocalValue'
            nid = self.node(kind, [caller_id, name], function_id=caller_id, name=name)
            if value:
                self.edge('stored_into' if kind == 'StructField' else 'assigned_to', value['node'], nid, eids)
                if value.get('resource_id'):
                    self.edge('aliases', value['node'], nid, eids, resource_id=value['resource_id'])
                if value['kind'] in {'local_stack_object','zero_initialized_object'}:
                    self.edge('initialized_by', value['node'], nid, eids)
                env[name] = {**value, 'node': nid}
            else:
                env[name] = {'node': nid, 'kind': 'unknown', 'proof_status': 'rejected',
                             'rejection_reason': 'unproved_expression'}

        def scalar(node):
            from .internal_invocations import sizeof_array
            arrays = {name: value['recipe'] for name, value in env.items() if value.get('recipe', {}).get('array_elements')}
            array = sizeof_array(node, source, arrays)
            if array:
                number = array['array_elements']
                return {'node': self.node('Constant', [number], value=number), 'kind': 'constant',
                        'constant': number, 'expression': {'op': 'constant', 'value': number}, 'lower': number, 'upper': number}
            if node.type == 'number_literal':
                spelling = _text(node, source)
                try:
                    number = int(re.sub(r'[uUlL]+$', '', spelling), 0 if spelling.startswith(('0x','0X')) else 10)
                except ValueError:
                    return None
                nid = self.node('Constant', [number], value=number)
                return {'node': nid, 'kind': 'constant', 'constant': number, 'expression': {'op': 'constant', 'value': number},
                        'lower': number, 'upper': number}
            if node.type == 'binary_expression':
                left, right = evaluate(node.child_by_field_name('left')), evaluate(node.child_by_field_name('right'))
                op = _text(node.child_by_field_name('operator'), source)
                if not left or not right or op not in {'+', '-'} or right.get('kind') != 'constant' or 'expression' not in left:
                    return None
                delta = right['constant'] * (1 if op == '+' else -1)
                lower = left.get('lower', 0) + delta
                upper = left.get('upper')
                upper = upper + delta if upper is not None else None
                if lower < 0 or upper is None or upper > 32767:
                    return {'node': self.node('LocalValue', [caller_id, node.start_byte], expression_unsupported=True),
                        'kind': 'derived_scalar', 'proof_status': 'rejected', 'rejection_reason': 'arithmetic_bounds_unproved'}
                expression = {'op': 'add' if op == '+' else 'subtract', 'left': left['expression'], 'right': right['expression']}
                nid = self.node('LocalValue', [caller_id, node.start_byte], expression=expression)
                self.edge('derived_from', left['node'], nid, eids)
                return {'node': nid, 'kind': 'derived_scalar', 'expression': expression,
                        'dependencies': left.get('dependencies', []), 'lower': lower, 'upper': upper}
            if node.type == 'conditional_expression':
                condition = node.child_by_field_name('condition')
                yes, no = node.child_by_field_name('consequence'), node.child_by_field_name('alternative')
                if condition is not None and condition.type == 'binary_expression':
                    left, right = condition.child_by_field_name('left'), condition.child_by_field_name('right')
                    if (_text(condition.child_by_field_name('operator'), source) in {'<', '<='}
                            and _text(left, source) == _text(yes, source) and _text(right, source) == _text(no, source)):
                        value, limit = evaluate(left), evaluate(right)
                        if value and value.get('kind') == 'fuzz_size' and limit and limit.get('kind') == 'constant' and limit['constant'] >= 0:
                            expression = {'op': 'min', 'left': value['expression'], 'right': limit['expression']}
                            nid = self.node('LocalValue', [caller_id, node.start_byte], expression=expression)
                            self.edge('derived_from', value['node'], nid, eids)
                            return {'node': nid, 'kind': 'derived_scalar', 'expression': expression,
                                    'lower': 0, 'upper': limit['constant']}
                return None
            return None

        def evaluate(node):
            if node is None:
                return None
            if node.type == 'parenthesized_expression':
                return evaluate(node.named_children[0]) if len(node.named_children) == 1 else None
            name = _key(node, source)
            if name:
                value = env.get(name)
                if value and node.type == 'field_expression':
                    field = self.node('StructField', [caller_id, name], function_id=caller_id, name=name)
                    self.edge('loaded_from', value['node'], field, eids)
                    if value.get('resource_id'):
                        return {**value, 'kind':'struct_field', 'origin_kind':value['kind']}
                return value
            if node.type == 'pointer_expression' and _text(node, source).startswith('&'):
                name = _key(node.named_children[0], source) if node.named_children else None
                value = env.get(name)
                if value and value['kind'] in {'local_stack_object', 'zero_initialized_object'}:
                    return value
                return None
            if node.type != 'call_expression':
                return scalar(node)
            target = node.child_by_field_name('function')
            args = node.child_by_field_name('arguments').named_children
            if target is None or target.type != 'identifier':
                env.clear()
                self.diagnostics.append({'code': 'resource_alias_ambiguous', 'function_id': caller_id,
                    'reason': 'indirect_call_escape', 'evidence_ids': eids})
                return None
            callee = unique_callee(self.snapshot, _text(target, source), caller)
            if not callee or callee['id'] in self.ft['excluded_functions'] or len(args) != len(callee.get('parameters', [])):
                if (any(n.type == 'pointer_expression' for arg in args for n in _walk(arg)) or
                        any((env.get(_key(arg,source)) or {}).get('resource_id') for arg in args)):
                    env.clear()
                    self.diagnostics.append({'code':'resource_alias_ambiguous','function_id':caller_id,
                        'reason':'unknown_call_escape','evidence_ids':eids})
                return None
            fid = callee['id']
            self.function(fid)
            call = {'function_id': fid, 'caller_id': caller_id, 'call_offset': node.start_byte,
                    'evidence_ids': eids, 'arguments': {}}
            for parameter, argument in zip(callee['parameters'], args):
                pid = self.params[fid, parameter['name']]
                value = evaluate(argument)
                if value is None and _text(argument, source) not in env:
                    value = self.callback_value(fid, parameter, argument, caller, source)
                if value is None:
                    value = {'node':self.node('LocalValue',[caller_id,argument.start_byte,'unknown']),
                        'kind':'unknown', 'proof_status':'candidate', 'rejection_reason':'unproved_expression'}
                self.candidate(pid, value, eids, caller_id=caller_id, call_offset=node.start_byte, basis='call_site_value_flow')
                call['arguments'][parameter['name']] = value
                if value and value.get('resource_id'):
                    self.endpoints[pid].append(value['resource_id'])
                    self.edge('consumed_by', value['node'], pid, eids, resource_id=value['resource_id'])
                if argument.type == 'pointer_expression' and _text(argument, source).startswith('&'):
                    local_name = _key(argument.named_children[0], source) if argument.named_children else None
                    if parameter.get('pointer_depth', 0) > 1 and local_name:
                        callee_source, callee_body = body_tree(callee)
                        out = [n for n in _walk(callee_body) if n.type == 'assignment_expression'
                            and _text(n.child_by_field_name('left'), callee_source).replace(' ', '') == '*' + parameter['name']
                            and n.child_by_field_name('right').type == 'call_expression'] if _straight(callee_body) else []
                        if fid in self.bodies and len(out) == 1:
                            result = resource(callee, node, 'out_parameter', parameter)
                            local(local_name, result, argument)
                            output = self.node('OutParameter', [fid, parameter['name']], function_id=fid,
                                               parameter_id=pid)
                            self.edge('produces', output, result['node'], eids + sorted(self.bodies[fid]))
                            # Address storage is constructed locally, independently
                            # from the resource that the output slot will receive.
                            storage = self.node('LocalValue', [caller_id, local_name, 'out_storage'], name=local_name)
                            self.candidate(pid, {'node': storage, 'kind': 'local_stack_object'}, eids,
                                           basis='out_parameter_storage')
                        else:
                            env[local_name] = {'node': self.node('LocalValue', [caller_id, local_name]), 'kind': 'out_parameter',
                                'proof_status': 'candidate', 'rejection_reason': 'out_parameter_origin_unknown', 'dependencies': [pid]}
            self.calls.append(call)
            self.callback_dispatch(callee, call)
            for parameter in callee['parameters']:
                value = call['arguments'][parameter['name']]
                if value and value.get('resource_id') and releases_parameter(callee,parameter['name'],self.snapshot,self.release_bodies):
                    for name, stored in list(env.items()):
                        if stored.get('resource_id') == value['resource_id']:
                            env[name] = {'node':stored['node'], 'kind':'unknown', 'proof_status':'rejected',
                                        'rejection_reason':'released_or_escaped_resource'}
            if callee.get('return_pointer_depth', 0):
                return resource(callee, node)
            return None

        def resource(callee, node, kind='return', parameter=None):
            origin = {'function_id': callee['id'], 'kind': kind, 'parameter': parameter['name'] if parameter else None,
                'type': parameter['base_type'] if parameter else callee.get('return_base_type'),
                'pointer_depth': parameter.get('pointer_depth', 0)-1 if parameter else callee.get('return_pointer_depth', 0),
                'caller_id': caller_id, 'call_offset': node.start_byte}
            rid = 'resource_' + digest(origin)[:24]  # Same call-site identity as resource_flows.
            nid = self.node('Resource', rid, resource_id=rid, origin=origin, ownership='unresolved')
            ret = self.node('ReturnValue', callee['id'], function_id=callee['id']) if parameter is None else self.params[callee['id'], parameter['name']]
            self.edge('produces', ret, nid, eids)
            deps = [self.params[callee['id'], p['name']] for p in callee.get('parameters', [])
                    if parameter is None or p['name'] != parameter['name']]
            mechanism = 'creator_return' if kind=='return' else 'out_parameter'
            allocator_role = any(f['predicate']=='support_decision' and f['function_id']==callee['id']
                and f['value']['reason']=='allocator' and f['value']['decision'] in {'required','optional'}
                for f in self.context['facts'])
            if allocator_role:
                allocation = self.node('Allocator', [rid,'validated_allocator_role'], resource_id=rid, origin=origin)
                self.edge('assigned_to',nid,allocation,eids)
                mechanism='allocator_object'
            return {'node': nid, 'kind': mechanism,
                    'resource_id': rid, 'api': callee['id'], 'dependencies': deps, 'evidence_ids': eids}

        for statement in body.named_children:
            if statement.type == 'declaration':
                from .internal_invocations import byte_array
                array = byte_array(statement, source)
                if array:
                    local(array['name'], {'node': self.node('LocalValue', [caller_id, array['name'], 'array_storage']),
                        'kind': 'local_stack_object', 'recipe': {'array_elements': array['elements'],
                            'element_type': array['element_type'], 'initialization': array['initialization']}}, statement, declaration=True)
                    continue
                for declarator in statement.named_children:
                    target = declarator.child_by_field_name('declarator') if declarator.type == 'init_declarator' else declarator
                    names = [n for n in _walk(target) if n.type == 'identifier']
                    if len(names) != 1 or declarator.type not in {'init_declarator', 'identifier', 'pointer_declarator'}:
                        continue
                    name = _text(names[0], source)
                    value_node = declarator.child_by_field_name('value') if declarator.type == 'init_declarator' else None
                    if target.type == 'identifier' and (value_node is None or value_node.type == 'initializer_list'):
                        zero = value_node is not None and re.fullmatch(r'\{\s*0\s*\}', _text(value_node, source)) is not None
                        value = {'node': self.node('LocalValue', [caller_id, name, 'storage']),
                                 'kind': 'zero_initialized_object' if zero else 'local_stack_object',
                                 'recipe': {'initialization':'all_zero' if zero else 'aggregate_untranslated' if value_node is not None else 'uninitialized_storage'}}
                    else:
                        value = evaluate(value_node)
                    # A declaration without initializer is storage, not a value
                    # assignment; a subsequent out initialization is not reassignment.
                    local(name, value, statement, declaration=True)
                    if value_node is None:
                        writes[name] = 0
            elif statement.type == 'expression_statement' and statement.named_children:
                expression = statement.named_children[0]
                if expression.type == 'assignment_expression':
                    name = _key(expression.child_by_field_name('left'), source)
                    if name:
                        local(name, evaluate(expression.child_by_field_name('right')), expression)
                    else:
                        env.clear()
                else:
                    evaluate(expression)
            elif statement.type == 'return_statement':
                if statement.named_children:
                    evaluate(statement.named_children[0])
                break
            elif statement.type == 'if_statement':
                name = _nonnull_guard_name(statement, source)
                value = env.get(name) or {}
                if not value.get('resource_id') or value.get('proof_status', 'proven') != 'proven':
                    env.clear()
                    break
                consequence = statement.child_by_field_name('consequence')
                children = consequence.named_children if consequence.type == 'compound_statement' else [consequence]
                for child in children:
                    if child.type != 'comment':
                        evaluate(child.named_children[0])
            elif statement.type != 'comment':
                env.clear()
                break

        statements = [n for n in body.named_children if n.type != 'comment']
        if len(statements) == 1 and statements[0].type == 'return_statement':
            expression = statements[0].named_children[0] if statements[0].named_children else None
            if expression is not None and expression.type == 'call_expression':
                args = expression.child_by_field_name('arguments').named_children
                if [_text(arg, source) for arg in args] == [p['name'] for p in caller.get('parameters', [])]:
                    self.wrappers.append({'function_id': caller_id, 'role': 'delegation_wrapper',
                        'changes_core_classification': False, 'evidence_ids': eids})

    def internal_calls(self):
        from .internal_invocations import repeated_invocations
        for fid in sorted(self.context['core_apis']):
            for descriptor in repeated_invocations(self.snapshot.functions[fid], self.snapshot, self.bodies, self.ft['excluded_functions']):
                target = descriptor['function_id']
                self.function(target)
                for row in descriptor['parameter_forwarding']:
                    parent = self.params[fid, row['via_parameter']]
                    self.candidate(self.params[target, row['parameter']],
                        dict(node=parent, kind='existing_resource', dependencies=[parent]), descriptor['evidence_ids'],
                        basis='internal_parameter_forwarding', caller_id=fid, call_offset=descriptor['call_offset'],
                        invocation_proof_id=descriptor['invocation_proof_id'])
                for row in descriptor['local_arguments']:
                    pid = self.params[target, row['parameter']]
                    if row['kind'] == 'array_capacity':
                        number = row['value']
                        value = dict(node=self.node('Constant', [number], value=number), kind='constant', constant=number,
                                     expression={'op':'constant', 'value':number})
                    else:
                        value = dict(node=self.node('LocalValue', [fid, row['name'], 'internal_array']), kind='local_stack_object',
                            recipe={'array_elements':row['elements'], 'element_type':row['element_type'],
                                    'initialization':row['initialization'], 'storage_scope':'internal_invocation', 'via_function_id':fid})
                    self.candidate(pid, value, descriptor['evidence_ids'], basis='source_internal_argument', caller_id=fid,
                        call_offset=descriptor['call_offset'], invocation_proof_id=descriptor['invocation_proof_id'])
                self.internal_invocations.append(descriptor)

    def dependencies(self):
        by_target = defaultdict(list)
        for candidate in self.candidates.values():
            by_target[candidate['target_parameter']].append(candidate)
        resolved, holes, visiting, cycles, stack = {}, {}, set(), set(), []
        def solve(pid):
            if pid in resolved:
                return True
            if pid in holes:
                return False
            if pid in visiting:
                cycles.update(stack[stack.index(pid):])
                return False
            visiting.add(pid)
            stack.append(pid)
            possible = [c for c in by_target[pid] if c['proof_status'] == 'proven']
            # Prefer independently grounded fuzz bindings over usage forwarding
            # into the same API. Distinct runtime origins are never collapsed.
            roots = [c for c in possible if c.get('basis') == 'validated_input_binding']
            possible = roots or possible
            identities = {('resource',c['resource_id']) if c.get('resource_id') else
                (c['source_kind'], canonical(c.get('constant')) if c['source_kind']=='constant' else c['source_node'],
                canonical(c.get('expression'))) for c in possible}
            resources = {c.get('resource_id') for c in possible if c.get('resource_id')}
            if any(c.get('rejection_reason') in {'reassignment','released_or_escaped_resource'} for c in by_target[pid]):
                code = 'resource_alias_ambiguous'
            elif len(resources) > 1 or len(identities) > 1:
                code = 'argument_origin_ambiguous'
            elif not possible:
                rejected = [c.get('rejection_reason') for c in by_target[pid]]
                code = 'out_parameter_origin_unknown' if 'out_parameter_origin_unknown' in rejected else 'derived_scalar_unknown' if any(c['source_kind']=='derived_scalar' for c in by_target[pid]) else 'resource_alias_ambiguous' if 'reassignment' in rejected else 'argument_origin_missing'
            else:
                chosen = sorted(possible, key=canonical)[0]
                missing = [dep for dep in chosen['dependencies'] if not solve(dep)]
                if not missing:
                    resolved[pid] = {**chosen, 'proof_status': 'resolved',
                        'shared_requirement_ids': sorted(r['requirement_id'] for r in self.requirements
                            if r['subject_function_id'] == self.nodes[pid]['function_id'])}
                    visiting.remove(pid)
                    stack.pop()
                    return True
                code = 'creator_argument_missing' if chosen.get('origin_kind',chosen['source_kind']) in {'creator_return','out_parameter'} else 'argument_origin_missing'
            holes[pid] = {'parameter_id': pid, 'function_id': self.nodes[pid]['function_id'],
                'parameter_index': self.nodes[pid]['parameter_index'], 'parameter': self.nodes[pid]['name'],
                'code': code, 'candidate_ids': sorted(c['candidate_id'] for c in by_target[pid]),
                'missing_dependencies': sorted({dep for c in possible for dep in c['dependencies'] if dep not in resolved}),
                'requirement_ids': sorted(r['requirement_id'] for r in self.requirements if r['subject_function_id'] == self.nodes[pid]['function_id']),
                'evidence_ids': sorted({eid for c in by_target[pid] for eid in c['evidence_ids']})}
            visiting.remove(pid)
            stack.pop()
            return False
        for pid in sorted(self.params.values()):
            solve(pid)
        dependency_edges = [{'target': c['target_parameter'], 'requires': dep, 'candidate_id': c['candidate_id'],
            'evidence_ids': c['evidence_ids']} for c in self.candidates.values() for dep in c['dependencies']]
        return {'version': DEPENDENCY_VERSION, 'resolved_parameters': sorted(resolved.values(), key=canonical),
            'unresolved_parameters': sorted(holes.values(), key=canonical),
            'edges': sorted(dependency_edges, key=canonical), 'cycles': sorted(cycles)}

    def resource_diagnostics(self):
        consumers = defaultdict(list)
        for call in self.calls:
            for name, value in call['arguments'].items():
                if value and value.get('resource_id') and value.get('proof_status', 'proven') == 'proven':
                    consumers[value['resource_id']].append((call, name))
        for rid, uses in consumers.items():
            node = next(n for n in self.nodes.values() if n.get('resource_id') == rid)
            origin = node['origin']
            owners = [e for e in self.context['ownership_contract']['entries'] if e['function_id'] == origin['function_id']
                and e['return_value'] and origin['kind']=='return' and e['ownership'] != 'unknown']
            if owners:
                node['ownership_evidence'] = owners
                statuses = {e['ownership'] for e in owners}
                if len(statuses)==1:
                    node['ownership'] = next(iter(statuses))
            cleanup = []
            for call, name in uses:
                fid = call['function_id']
                source, body = body_tree(self.snapshot.functions[fid])
                if _straight(body) and releases_parameter(self.snapshot.functions[fid], name, self.snapshot, self.release_bodies):
                    cleanup.append(call)
                    self.edge('released_by', node['node_id'], self.params[fid,name],
                        call['evidence_ids'] + sorted(self.bodies[fid]), resource_id=rid)
                # Ownership is only taken from an independently validated entry.
                owners = [e for e in self.context['ownership_contract']['entries'] if e['function_id'] == fid
                    and e['parameter'] == name and e['ownership'] != 'unknown']
                if owners:
                    node.setdefault('consumer_ownership_evidence', []).extend(owners)
                self.edge('produces', self.function(origin['function_id']), node['node_id'],
                    call['evidence_ids'], resource_id=rid)
            for call, name in uses:
                if call in cleanup:
                    continue
                self.state_edges.append({'before': origin['function_id'], 'after': call['function_id'],
                    'resource_id': rid, 'reason': 'graph_proven_runtime_origin', 'evidence_ids': call['evidence_ids']})
                for release in cleanup:
                    self.state_edges.append({'before': call['function_id'], 'after': release['function_id'],
                        'resource_id': rid, 'reason': 'graph_same_origin_release',
                        'evidence_ids': sorted(set(call['evidence_ids']) | set(self.bodies[release['function_id']]))})
                for later, other in uses:
                    if (call['caller_id'] != later['caller_id'] or call['call_offset'] >= later['call_offset']
                            or call['function_id'] not in self.bodies or later['function_id'] not in self.bodies):
                        continue
                    from .ordering import field_accesses
                    a, b = self.snapshot.functions[call['function_id']], self.snapshot.functions[later['function_id']]
                    if not _straight(body_tree(a)[1]) or not _straight(body_tree(b)[1]):
                        continue
                    fields = field_accesses(a, name, True) & field_accesses(b, other, False)
                    if fields:
                        eids = sorted(set(call['evidence_ids']) | self.bodies[a['id']] | self.bodies[b['id']])
                        self.state_edges.append({'before': a['id'], 'after': b['id'], 'resource_id': rid,
                            'reason': 'graph_same_origin_field_write_read', 'fields': sorted(fields), 'evidence_ids': eids})
                        self.edge('feeds', self.function(a['id']), self.function(b['id']), eids, resource_id=rid, fields=sorted(fields))
            if not cleanup and any(e.get('ownership') == 'owned' or e.get('cleanup',{}).get('mandatory')
                    for e in self.context['ownership_contract']['entries'] + self.context['lifecycle_contract']['resources']
                    if e.get('resource_id') == rid):
                self.diagnostics.append({'code': 'cleanup_consumer_missing', 'resource_id': rid,
                    'evidence_ids': sorted({eid for call,_ in uses for eid in call['evidence_ids']})})

    def build(self):
        for fid in sorted(self.functions):
            self.function(fid)
        seeds = self.seeded_values()
        self.semantic_candidates()
        for caller in sorted(self.bodies):
            self.flow(caller, seeds)
        self.construction_strategies()
        self.internal_calls()
        for wrapper in self.wrappers:
            fn = self.nodes[self.function(wrapper['function_id'])]
            fn['slice_role'] = fn['role']
            fn['role'] = 'delegation_wrapper_diagnostic_only'
        dependencies = self.dependencies()
        self.resource_diagnostics()
        for cycle in dependencies['cycles']:
            self.diagnostics.append({'code': 'dependency_cycle', 'parameter_id': cycle, 'evidence_ids': []})
        for precondition in self.context['state_contract']['preconditions']:
            if precondition['kind'] in {'input_fed', 'initialized', 'reset'}:
                if not precondition.get('api'):
                    self.diagnostics.append({'code': 'state_writer_missing', 'function_id': precondition['function_id'],
                        'evidence_ids': precondition['evidence_ids']})
                elif not any(e['before']==precondition['api'] and e['after']==precondition['function_id'] for e in self.state_edges):
                    self.diagnostics.append({'code': 'state_reader_missing', 'function_id': precondition['function_id'],
                        'reason': 'no_shared_origin_field_dependency', 'evidence_ids': precondition['evidence_ids']})
        return {'schema_version': 1, 'artifact_kind': 'argument_construction_graph', 'version': VERSION,
            'ft_id': self.ft['ft_id'], 'input_digest': digest([self.ft, self.context['facts'],
                {eid: record for eid, record in sorted(self.records.items())}]),
            'nodes': sorted(self.nodes.values(), key=canonical), 'edges': sorted(self.edges.values(), key=canonical),
            'construction_candidates': sorted(self.candidates.values(), key=canonical),
            'dependency_graph': dependencies, 'resource_origins': sorted(
                [n for n in self.nodes.values() if n['node_type']=='Resource'], key=canonical),
            'resource_consumers': sorted([e for e in self.edges.values() if e['kind']=='consumed_by'], key=canonical),
            'unresolved_ownership': sorted(n['node_id'] for n in self.nodes.values() if n['node_type']=='Resource' and n['ownership']=='unresolved'),
            'state_dependencies': sorted({canonical(e):e for e in self.state_edges if e['before']!=e['after']}.values(), key=canonical),
            'wrapper_diagnostics': sorted(self.wrappers, key=canonical),
            'callback_dispatches': sorted({canonical(d): d for d in self.dispatches}.values(), key=canonical),
            'internal_invocations': sorted(self.internal_invocations, key=canonical),
            'diagnostics': sorted(self.diagnostics, key=canonical)}


def build_argument_graph(context, ft, requirements, snapshot, records):
    return GraphBuilder(context, ft, requirements, snapshot, records).build()


def issued_resource_ids(snapshot, records, allowed_ids):
    """Framework-only identity catalog; labels cannot manufacture resources."""
    from .value_roles import origin_catalog
    return set(origin_catalog(snapshot, records, allowed_ids))


def project_graph_arguments(context, graph, requirements, snapshot):
    """Project representable constructions, never ownership/lifecycle guesses."""
    projected = []
    arguments = context['argument_contract']['arguments']
    by_parameter = {(a['function_id'], a['parameter']): a for a in arguments}
    nodes = {node['node_id']: node for node in graph['nodes']}
    for proof in graph['dependency_graph']['resolved_parameters']:
        parameter = nodes[proof['target_parameter']]
        key = parameter['function_id'], parameter['name']
        if key in by_parameter and by_parameter[key]['construction'] != 'unknown':
            continue
        kind = proof['source_kind']
        construction = {'fuzz_bytes':'input', 'fuzz_size':'input', 'constant':'constant',
                        'creator_return':'creator_api',
                        'zero_initialized_object':'zero_init', 'callback_object':'callback'}.get(kind)
        if not construction or not proof['evidence_ids']:
            # Out origins, field recipes and scalar IR stay diagnostic until the
            # unchanged HarnessPlan can represent their exact storage/expression.
            continue
        argument = {'function_id': key[0], 'parameter': key[1], 'construction': construction,
            'api': proof.get('api'), 'resource_id': proof.get('resource_id'),
            'constant': proof.get('constant'), 'evidence_ids': proof['evidence_ids'],
            'fact_id': 'graph_proof_' + digest(proof)[:24], 'derived_by': VERSION}
        if key in by_parameter:
            arguments.remove(by_parameter[key])
        arguments.append(argument)
        by_parameter[key] = argument
        projected.append(proof)
    context['argument_contract']['arguments'] = sorted(arguments, key=canonical)
    satisfied = []
    for req in requirements:
        if req['kind'] != 'argument_construction':
            continue
        fid = req['subject_function_id']
        params = snapshot.functions[fid].get('parameters', [])
        proofs = [proof for proof in projected if nodes[proof['target_parameter']]['function_id']==fid]
        if params and len(proofs) == len(params):
            satisfied.append({'requirement_id':req['requirement_id'], 'proof_kind':VERSION,
                'evidence_ids':sorted({eid for proof in proofs for eid in proof['evidence_ids']}),
                'proof_digest':digest(proofs)})
    return satisfied


def investigation_view(graph, fid):
    nodes = {node['node_id']:node for node in graph['nodes']}
    targets = {nid for nid,node in nodes.items() if node['node_type']=='Parameter' and node['function_id']==fid}
    holes = [row for row in graph['dependency_graph']['unresolved_parameters'] if row['parameter_id'] in targets]
    dependencies = {dep for row in holes for dep in row['missing_dependencies']}
    targets |= dependencies
    return {'version':VERSION, 'targets':sorted([nodes[nid] for nid in targets],key=canonical),
        'known_constructions':[row for row in graph['dependency_graph']['resolved_parameters'] if row['target_parameter'] in targets],
        'holes':holes + [row for row in graph['dependency_graph']['unresolved_parameters'] if row['parameter_id'] in dependencies],
        'origin_candidates':[row for row in graph['construction_candidates'] if row['target_parameter'] in targets],
        'state_dependencies':[row for row in graph['state_dependencies'] if fid in {row['before'],row['after']}],
        'wrapper_diagnostics':[row for row in graph['wrapper_diagnostics'] if row['function_id']==fid]}
