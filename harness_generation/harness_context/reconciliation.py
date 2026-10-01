"""One recomputable construction truth, with separate semantic proposals.

Recipe equivalence never erases runtime origin identity. Source rejection is
not repaired by confidence, and ownership is deliberately absent from recipes.
"""
from collections import defaultdict
from copy import deepcopy

from ..semantic_discovery.models import canonical, digest
from .argument_graph import parameter_id

VERSION = 'graph-contract-reconciliation-v3'
RECIPE_VERSION = 'canonical-construction-recipe-v1'


def scalar_bounds(expression):
    if not isinstance(expression, dict):
        return None
    op = expression.get('op')
    if op == 'fuzz_size' and set(expression) == {'op'}:
        return (0, None)
    if op == 'constant' and set(expression) == {'op', 'value'} and type(expression['value']) is int:
        return (expression['value'], expression['value'])
    if op not in {'min', 'add', 'subtract'} or set(expression) != {'op', 'left', 'right'}:
        return None
    left, right = scalar_bounds(expression['left']), scalar_bounds(expression['right'])
    if left is None or right is None or right[0] != right[1] or right[0] < 0:
        return None
    if op == 'min':
        return (min(left[0], right[0]), min(left[1], right[1]) if left[1] is not None else right[1])
    if left[1] is None:
        return None
    low, high = (left[0]+right[0], left[1]+right[1]) if op == 'add' else (left[0]-right[1], left[1]-right[0])
    return (low, high) if 0 <= low <= high <= 32767 else None


def scalar_limit(parameter):
    # Portable lower bounds; no host ABI or arbitrary typedef guessing.
    base = parameter.get('base_type', '').strip()
    if base in {'char', 'signed char', 'int8_t'}:
        return 127
    if base in {'unsigned char', 'uint8_t'}:
        return 255
    if base in {'short', 'short int', 'signed short', 'signed short int', 'int16_t'}:
        return 32767
    if base in {'unsigned short', 'unsigned short int', 'uint16_t'}:
        return 65535
    if base in {'int', 'unsigned', 'unsigned int', 'long', 'long int', 'unsigned long', 'unsigned long int',
                'long long', 'unsigned long long', 'size_t', 'int32_t', 'uint32_t', 'int64_t', 'uint64_t'}:
        return 32767
    return None


class GraphContractReconciler:
    def reconcile(self, context, graph, requirements, snapshot):
        nodes = {n['node_id']: n for n in graph['nodes']}
        parameters = {pid:n for pid,n in nodes.items() if n['node_type']=='Parameter'}
        origins = {r['resource_id']:r['origin'] for r in graph['resource_origins']}
        candidates, proposals = defaultdict(list), defaultdict(list)
        for candidate in graph['construction_candidates']:
            candidates[candidate['target_parameter']].append(candidate)
        for argument in context['argument_contract']['arguments']:
            function = snapshot.functions[argument['function_id']]
            for index, parameter in enumerate(function.get('parameters', [])):
                if parameter['name']==argument['parameter']:
                    proposals[parameter_id(function['id'], index)].append(argument)
        resolved, visiting, diagnostics, classes = {}, [], [], []
        relations = {r['parameter_id']: r for r in context.get('parameter_semantic_contract',{}).get('parameters',[])}

        def satisfies_relation(recipe, pid):
            upper = relations.get(pid,{}).get('mandatory_upper_bound')
            if upper is None or recipe['kind']=='length_relation':
                return True
            bounds = (scalar_bounds(recipe.get('expression')) if recipe['kind']=='derived_scalar' else
                (recipe['value'],recipe['value']) if recipe['kind']=='constant' else
                (0,None) if recipe['kind']=='fuzz_size' else None)
            return bounds is not None and bounds[1] is not None and 0 <= bounds[0] <= bounds[1] <= upper

        def source_recipe(candidate, parameter):
            kind, rid = candidate['source_kind'], candidate.get('resource_id')
            if rid:
                origin = origins.get(rid)
                if not origin:
                    return None
                recipe = {'kind':'out_parameter_call' if origin['kind']=='out_parameter' else 'creator_call',
                    'resource_id':rid, 'producer_api':origin['function_id'],
                    'dependencies':candidate['dependencies']}
                if origin['kind']=='out_parameter':
                    recipe['out_parameter']=origin['parameter']
                return recipe
            if candidate.get('basis')=='out_parameter_storage':
                matches=[(rid,origin) for rid,origin in origins.items() if origin['kind']=='out_parameter'
                    and origin['function_id']==parameter['function_id'] and origin['parameter']==parameter['name']]
                if len(matches)!=1:
                    return None
                return {'kind':'out_parameter_storage','resource_id':matches[0][0], 'initialization':'null', 'dependencies':[]}
            if kind in {'fuzz_bytes','fuzz_size','constant','callback_object'}:
                return {'kind':kind, 'dependencies':candidate['dependencies'],
                    **({'value':candidate.get('constant')} if kind=='constant' else {})}
            if kind=='zero_initialized_object':
                return {'kind':'stack_zero_init', 'dependencies':[]}
            if kind=='local_stack_object':
                recipe=candidate.get('recipe',{})
                if recipe.get('initialization')=='aggregate_untranslated' or not parameter['pointer_depth']:
                    return None
                return {'kind':'stack_storage','dependencies':[]}
            if kind=='derived_scalar':
                expression=candidate.get('expression'); bounds=scalar_bounds(expression)
                limit=scalar_limit(parameter)
                if bounds is None or bounds[1] is None or limit is None or not 0<=bounds[0]<=bounds[1]<=limit:
                    return None
                return {'kind':'derived_scalar','expression':expression, 'bounds':list(bounds), 'dependencies':candidate['dependencies']}
            if kind=='existing_resource' and candidate['dependencies']:
                return {'kind':'parameter_reference','dependencies':candidate['dependencies']}
            return None

        def semantic_recipe(argument, parameter):
            kind=argument['construction']; fid=parameter['function_id']; name=parameter['name']
            if kind=='unknown':
                return None
            if kind=='input':
                bindings=context['input_contract']['bindings']
                if any(b['function_id']==fid and b['parameter']==name and b['source']=='fuzz_data' for b in bindings):
                    return {'kind':'fuzz_bytes','dependencies':[]}
                if any(b['function_id']==fid and b.get('size_parameter')==name for b in bindings):
                    derived=any(link['function_id']==fid and link.get('length_parameter')==name and link.get('relation')=='derived'
                        for link in context['buffer_length_contract']['links'])
                    return {'kind':'length_relation' if derived else 'fuzz_size','dependencies':[]}
                return None
            if kind=='constant' and type(argument.get('constant')) in {int,bool}:
                return {'kind':'constant','value':int(argument['constant']),'dependencies':[]}
            if kind in {'zero_init','stack'}:
                if not parameter['pointer_depth']:
                    return None
                if kind=='zero_init' and parameter['base_type']=='void':
                    return {'kind':'null_pointer_initializer','dependencies':[]}
                recipe={'kind':'stack_zero_init' if kind=='zero_init' else 'stack_storage','dependencies':[]}
                source=next((s for s in context.get('construction_contract',{}).get('sources',[])
                    if s['construction_id']==argument.get('construction_source')),None)
                if source and source.get('assignments'):
                    recipe.update(certified_fields=deepcopy(source['assignments']),source_certificate=source['construction_id'])
                return recipe
            if kind=='callback':
                return {'kind':'callback_object','dependencies':[], **({'producer_api':argument['api']} if argument['api'] else {})}
            if kind in {'creator_api','derived'} and argument.get('resource_id'):
                rid=argument['resource_id']; origin=origins.get(rid)
                if origin:
                    producer=snapshot.functions[origin['function_id']]
                    dependencies=[parameter_id(producer['id'],i) for i,p in enumerate(producer['parameters'])
                        if origin['kind']!='out_parameter' or p['name']!=origin['parameter']]
                    return {'kind':'out_parameter_call' if origin['kind']=='out_parameter' else 'creator_call',
                        'resource_id':rid,'producer_api':origin['function_id'],'dependencies':dependencies,
                        **({'out_parameter':origin['parameter']} if origin['kind']=='out_parameter' else {})}
                if kind=='derived':
                    return {'kind':'resource_reference','resource_id':rid,'producer_api':argument.get('api'),'dependencies':[]}
            if kind=='creator_api' and argument.get('api'):
                producer=snapshot.functions[argument['api']]
                if producer.get('return_pointer_depth') != parameter['pointer_depth'] or producer.get('return_base_type') != parameter['base_type']:
                    return None
                return {'kind':'creator_call','resource_id':argument.get('resource_id'),'producer_api':producer['id'],
                    'dependencies':[parameter_id(producer['id'],i) for i in range(len(producer['parameters']))]}
            if kind=='derived':
                for binding in context['input_contract']['bindings']:
                    if binding['function_id']==fid and binding.get('size_parameter')==name:
                        return {'kind':'length_relation','dependencies':[]}
                if any(link['function_id']==fid and link.get('length_parameter')==name
                    for link in context['buffer_length_contract']['links']):
                    return {'kind':'length_relation','dependencies':[]}
            return None

        def agrees(source, semantic):
            semantic={k:v for k,v in semantic.items() if k not in {'certified_fields','source_certificate'}}
            if source==semantic:
                return True
            if source['kind']=='stack_zero_init' and semantic['kind']=='stack_storage':
                return True
            if semantic['kind']=='length_relation' and source['kind'] in {'fuzz_size','derived_scalar'}:
                return True
            if semantic['kind']=='null_pointer_initializer' and source['kind']=='constant' and source['value']==0:
                return True
            if source['kind']=='out_parameter_storage' and semantic['kind'] in {'stack_zero_init','stack_storage','resource_reference','out_parameter_call'}:
                return semantic.get('resource_id') in {None,source['resource_id']}
            if source['kind'] in {'creator_call','out_parameter_call'} and semantic['kind']=='resource_reference':
                return source['resource_id']==semantic['resource_id'] and semantic.get('producer_api') in {None,source['producer_api']}
            if source['kind']=='creator_call' and semantic['kind']=='creator_call':
                return source['producer_api']==semantic['producer_api'] and semantic.get('resource_id') in {None,source['resource_id']}
            return False

        def solve(pid):
            if pid in resolved:
                return resolved[pid]['status']=='resolved'
            parameter=parameters.get(pid)
            if parameter is None:
                return False
            if pid in visiting:
                return False
            visiting.append(pid)
            mechanical=[];semantic=[]; grouped=defaultdict(list)
            for candidate in candidates[pid]:
                if candidate['proof_status']=='proven' and candidate.get('basis')!='validated_semantic_fact':
                    recipe=source_recipe(candidate,parameter)
                    if recipe and recipe['kind']=='parameter_reference':
                        dependencies=recipe['dependencies']
                        if len(dependencies)==1 and dependencies[0]!=pid and solve(dependencies[0]):
                            recipe={k:v for k,v in resolved[dependencies[0]]['recipe'].items() if k not in {'recipe_id','version'}}
                        else:
                            recipe=None  # Forwarding an unbound caller parameter is not another proved origin.
                    if recipe and not satisfies_relation(recipe,pid):
                        diagnostics.append({'code':'construction_candidate_semantic_relation_mismatch',
                            'parameter_id':pid,'candidate_id':candidate['candidate_id'],
                            'mandatory_upper_bound':relations[pid]['mandatory_upper_bound']})
                        recipe=None
                    if recipe:
                        mechanical.append((recipe,candidate))
                        grouped[canonical(recipe)].append(candidate)
            for argument in proposals[pid]:
                recipe=semantic_recipe(argument,parameter)
                if recipe:
                    semantic.append((recipe,argument))
            for key,members in sorted(grouped.items()):
                classes.append({'parameter_id':pid,'equivalence_id':'equivalence_'+digest([pid,key])[:24],
                    'recipe':mechanical[next(i for i,(r,_) in enumerate(mechanical) if canonical(r)==key)][0],
                    'candidate_ids':sorted(c['candidate_id'] for c in members)})
            source_options={canonical(r):r for r,_ in mechanical}
            semantic_options={canonical(r):r for r,_ in semantic}
            row={'parameter_id':pid,'function_id':parameter['function_id'],'parameter':parameter['name'],
                'parameter_index':parameter['parameter_index'],'declared_type':parameter['declared_type'],
                'status':'unknown','recipe':None,'reason':'construction_source_missing','evidence_ids':[],
                'candidate_ids':sorted(c['candidate_id'] for c in candidates[pid]),
                'semantic_fact_ids':sorted({a['fact_id'] for a in proposals[pid]}), 'dependencies':[]}
            chosen=None
            killed=any(c.get('rejection_reason') in {'reassignment','released_or_escaped_resource'} for c in candidates[pid])
            if any(not satisfies_relation(r,pid) for r,_ in semantic):
                row.update(status='conflict',reason='semantic_relation_contradiction')
            elif any(a['construction']=='input' and a.get('resource_id') is not None for a in proposals[pid]):
                row.update(status='conflict',reason='phantom_input_resource')
            elif killed:
                row.update(status='conflict' if semantic else 'unknown',reason='source_value_invalidated')
            elif len(semantic_options)>1:
                row.update(status='conflict',reason='semantic_recipe_conflict')
            elif source_options and semantic_options:
                accepted=[r for r in source_options.values() if any(agrees(r,s) for s in semantic_options.values())]
                if len(accepted)==1 and len(source_options)==1:
                    chosen=accepted[0];row['reason']='graph_semantic_agreement'
                elif not accepted:
                    row.update(status='conflict',reason='graph_semantic_contradiction')
                else:
                    # An explicit exact runtime identity can select a member;
                    # an API/type label cannot collapse separate call instances.
                    s=next(iter(semantic_options.values()))
                    selected=[r for r in accepted if s.get('resource_id') and r.get('resource_id')==s['resource_id']]
                    if len(selected)==1:
                        chosen=selected[0];row['reason']='semantic_selects_proven_origin'
                    else:
                        row.update(status='conflict',reason='runtime_origin_ambiguous')
            elif len(source_options)==1:
                chosen=next(iter(source_options.values()));row['reason']='graph_proof'
                if proposals[pid] and not semantic:
                    diagnostics.append({'code':'semantic_recipe_not_reproduced','parameter_id':pid,
                        'semantic_fact_ids':row['semantic_fact_ids'],'reason':'proposal_has_no_verified_recipe'})
                    if any(a['construction'] in {'input','constant','creator_api'} for a in proposals[pid]):
                        chosen=None;row.update(status='conflict',reason='semantic_recipe_unverifiable')
            elif len(source_options)>1:
                row['reason']='runtime_origin_ambiguous'
            elif len(semantic_options)==1:
                chosen=next(iter(semantic_options.values()));row['reason']='semantic_only_not_reproduced'
                if chosen['kind'] in {'length_relation','null_pointer_initializer'}:
                    chosen=None
                diagnostics.append({'code':'semantic_recipe_not_reproduced','parameter_id':pid,
                    'semantic_fact_ids':row['semantic_fact_ids'],'reason':'no_mechanical_origin_proof'})
            if chosen:
                compatible=[s for s,_ in semantic if agrees(chosen,s) and s.get('certified_fields')]
                if compatible:
                    chosen={**chosen,'certified_fields':compatible[0]['certified_fields'],
                            'source_certificate':compatible[0]['source_certificate']}
                deps=chosen['dependencies']; missing=[dep for dep in deps if dep==pid or not solve(dep)]
                row['dependencies']=deps
                if missing:
                    row.update(reason='dependency_cycle' if any(dep in visiting for dep in missing) else 'creator_argument_missing',
                        missing_dependencies=sorted(missing))
                else:
                    row.update(status='resolved',recipe={**deepcopy(chosen),
                        'recipe_id':'recipe_'+digest([pid,chosen])[:24], 'version':RECIPE_VERSION})
            eids={eid for _,c in mechanical for eid in c['evidence_ids']} | {eid for _,a in semantic for eid in a['evidence_ids']}
            row['evidence_ids']=sorted(eids)
            row['proof_digest']=digest(row)
            resolved[pid]=row
            visiting.pop()
            return row['status']=='resolved'
        for pid in sorted(parameters):
            solve(pid)
        return {'version':VERSION,'recipe_version':RECIPE_VERSION,
            'input_digest':digest([graph,context['argument_contract'],context['input_contract'],context.get('parameter_semantic_contract')]),
            'input_contract_digest':digest(context['input_contract']),
            'parameters':sorted(resolved.values(),key=canonical),'equivalence_classes':sorted(classes,key=canonical),
            'diagnostics':sorted(diagnostics,key=canonical)}


def project_canonical_construction(context, contract, requirements, snapshot):
    """Legacy argument rows are a view of the canonical selection, not a source."""
    old={(a['function_id'],a['parameter']):a for a in context['argument_contract']['arguments']}
    arguments=[]; selected={}; mapped=defaultdict(set)
    for row in contract['parameters']:
        key=row['function_id'],row['parameter']; previous=old.get(key)
        if row['status']!='resolved':
            if previous:
                arguments.append({**previous,'canonical_status':row['status'],'canonical_parameter_id':row['parameter_id']})
            continue
        recipe=row['recipe']; kind=recipe['kind']
        construction={'fuzz_bytes':'input','fuzz_size':'input','constant':'constant','stack_zero_init':'zero_init',
            'stack_storage':'stack','creator_call':'creator_api','out_parameter_call':'creator_api',
            'out_parameter_storage':'derived','derived_scalar':'derived','resource_reference':'derived',
            'parameter_reference':'derived','callback_object':'callback'}[kind]
        argument={'function_id':key[0],'parameter':key[1],'construction':construction,
            'api':recipe.get('producer_api'),'resource_id':recipe.get('resource_id'),
            'constant':recipe.get('value'),'evidence_ids':row['evidence_ids'],
            'fact_id':'canonical_'+row['proof_digest'][:24],'canonical_parameter_id':row['parameter_id'],
            'recipe_id':recipe['recipe_id'],'derived_by':VERSION}
        if kind == 'out_parameter_storage':
            # The recipe names the future pointee for Plan lowering. The
            # argument is its address cell, which has no object lifecycle.
            argument['resource_id'] = None
            argument['pointee_resource_id'] = recipe['resource_id']
        if previous and previous.get('construction_source'):
            argument['construction_source']=previous['construction_source']
        if previous and previous['construction']=='derived' and kind in {'creator_call','out_parameter_call'}:
            argument.update(construction='derived',api=None)
        if previous and kind in {'stack_zero_init','stack_storage','callback_object'}:
            argument['resource_id']=previous.get('resource_id')
        if kind=='resource_reference' and previous:
            argument['api']=previous.get('api')
        arguments.append(argument); selected[key]=row
    # Rebind only proved value-flow endpoints; no type-wide identity merge.
    for resource in context['lifecycle_contract']['resources']:
        row=selected.get((resource['function_id'],resource['subject_parameter']))
        if row and row['recipe'].get('resource_id'):
            rid=row['recipe']['resource_id'];mapped[resource['resource_id']].add(rid)
            resource['resource_id']=rid
    for section,field in [('ownership_contract','entries'),('ordering_contract','constraints')]:
        for entry in context[section][field]:
            if section == 'ownership_contract' and entry.get('subject_kind') == 'PointerParameter' and any(
                    p['name'] == entry['parameter'] and p.get('pointer_depth', 0) >= 2
                    for p in snapshot.functions[entry['function_id']]['parameters']):
                continue
            row=selected.get((entry['function_id'],entry.get('parameter')))
            if row and row['recipe'].get('resource_id') and entry.get('field') is None:
                entry['resource_id']=row['recipe']['resource_id']
            elif entry.get('resource_id') in mapped and len(mapped[entry['resource_id']])==1:
                entry['resource_id']=next(iter(mapped[entry['resource_id']]))
    context['argument_contract']['arguments']=sorted(arguments,key=canonical)
    satisfied=[]
    for req in requirements:
        if req['kind']!='argument_construction':
            continue
        function=snapshot.functions[req['subject_function_id']]
        proofs=[selected.get((function['id'],p['name'])) for p in function['parameters']]
        if proofs and all(proofs):
            satisfied.append({'requirement_id':req['requirement_id'],'predicate':'argument_construction','proof_kind':VERSION,
                'evidence_ids':sorted({e for p in proofs for e in p['evidence_ids']}),'proof_digest':digest(proofs)})
    return satisfied
