"""Post-run contract adjudication. This is the ONLY consumer of ground truth.

Correctness is three-valued. Missing output is unverified, not a success. An
operational compile/code failure does not alone prove an unsound semantic Gate.
"""
from collections import Counter
import json
from pathlib import Path
import re

SEMANTIC_DIMENSIONS = ('resource_identity','lifecycle','ownership','callback','ordering','input_binding','multiplicity')
TAXONOMY = ('candidate_false_negative','candidate_invalid_output','candidate_unresolved','candidate_rejected',
    'slice_missing_core','slice_overexpanded_core','slice_missing_support','slice_invalid',
    'resource_identity_unresolved','resource_identity_conflict','argument_construction_unknown','input_binding_unknown',
    'lifecycle_unknown','ownership_unknown','callback_unknown','state_unknown','ordering_cycle','api_closure_unknown',
    'return_semantics_unknown','plan_blocked','plan_invalid','code_generation_invalid','compile_failed',
    'runtime_failed','sanitizer_failed','semantic_contract_mismatch','static_analysis_failed','provider_error','pipeline_exception')


def load(path, default=None):
    return json.loads(path.read_text()) if path and path.is_file() else default


def one(root, pattern):
    paths = sorted(root.glob(pattern))
    return paths[0] if len(paths)==1 else None


def validate_truth(truth):
    from .schema import validate_annotation
    validate_annotation(truth)
    required={'schema_version','annotation_kind','id','core_apis','required_support','resources','input_binding',
              'ownership','callback','ordering','invocation_counts','mandatory_constraints','adjudication'}
    if set(truth)!=required or truth['schema_version']!=1 or truth['annotation_kind']!='independent_manual_contract':
        raise ValueError('invalid ground truth schema')
    for key in ('core_apis','required_support'):
        if not isinstance(truth[key],list) or len(set(truth[key]))!=len(truth[key]):raise ValueError('invalid API set')
    for r in truth['resources']:
        if set(r)!={'id','origin','consumers','cleanup','ownership','scope'} or r['origin']['kind'] not in {'return','out_parameter'}:
            raise ValueError('invalid resource annotation')
    return truth


def precision_recall(actual,expected):
    actual,expected=set(actual),set(expected);intersection=actual&expected
    return {'tp':len(intersection),'fp':len(actual-expected),'fn':len(expected-actual),
            'precision':len(intersection)/len(actual) if actual else None,
            'recall':len(intersection)/len(expected) if expected else None,
            'expected':sorted(expected),'observed':sorted(actual)}


def semantic_checks(context,closure,plan,names,truth):
    if context is None:return {d:{'status':'unverified','checks':[]} for d in SEMANTIC_DIMENSIONS}
    buckets={d:[] for d in SEMANTIC_DIMENSIONS}
    def check(dim,label,value,detail=None):buckets[dim].append({'contract':label,'correct':value,'detail':detail})
    nm=lambda fid:names.get(fid,fid)
    active={nm(fid) for fid in context['core_apis']}|{nm(r['function_id']) for r in closure.get('required_support_apis',[])}
    lives=context['lifecycle_contract']['resources'];owners=context['ownership_contract']['entries'];args=context['argument_contract']['arguments']
    bindings=context['input_contract']['bindings'];callbacks=context['callback_contract']['callbacks']
    expected_bindings={}
    for resource in truth['resources']:
        origin=resource['origin'];producer=origin['api'];producers={producer,*origin.get('alternatives',[])}
        produced=[r for r in lives if nm(r['function_id']) in producers and r['return_value']==(origin['kind']=='return')
                  and r['subject_parameter']==origin['parameter']]
        ids={r['resource_id'] for r in produced}
        # Out-value metadata is distinct from ownership of pointer storage.
        check('lifecycle',resource['id']+':origin',bool(produced),origin)
        check('lifecycle',resource['id']+':release_api',resource['cleanup'] in active)
        check('lifecycle',resource['id']+':mandatory_release',bool(produced) and all(
            r['cleanup']['mandatory'] and nm(r['cleanup']['api'])==resource['cleanup'] for r in produced))
        expected_bindings[resource['id']]=set(ids)
        for consumer in resource['consumers']:
            matches=[r for r in lives if nm(r['function_id'])==consumer['api'] and r['subject_parameter']==consumer['parameter'] and not r['return_value']]
            # Construction arguments can carry an explicit lifecycle identity.
            matches+= [r for r in args if nm(r['function_id'])==consumer['api'] and r['parameter']==consumer['parameter'] and r['resource_id']]
            used={r['resource_id'] for r in matches}
            check('resource_identity',resource['id']+':'+consumer['api']+'.'+consumer['parameter'],bool(ids) and bool(used) and bool(ids&used))
            expected_bindings[resource['id']] &= used
    for left,right in truth['mandatory_constraints'].get('distinct_resources',[]):
        a,b=expected_bindings.get(left,set()),expected_bindings.get(right,set())
        check('resource_identity',left+' != '+right,bool(a) and bool(b) and not a&b)
    for expectation in truth['ownership']:
        matches=[o for o in owners if nm(o['function_id']) in {expectation['api'],*expectation.get('api_alternatives',[])} and o['parameter']==expectation['parameter']
                 and o['return_value']==expectation['return_value'] and o['field'] is None]
        correct=any(o['ownership']==expectation['ownership'] and nm(o['release_api'])==expectation['release_api'] for o in matches)
        # Source-proved no-escape refinements may shorten a borrowed lifetime.
        check('ownership',expectation['api']+'.'+str(expectation['parameter']),correct)
    for expectation in truth['input_binding']:
        matches=[b for b in bindings if nm(b['function_id'])==expectation['api'] and b['parameter']==expectation['parameter']]
        if expectation['source']=='callback':
            # Current zero-return stub policy cannot on its own prove a reader.
            check('input_binding',expectation['api']+':pull_transport',None,'needs a bounds-checked fuzz-backed reader; metadata alone is insufficient')
        else:
            source=expectation['source']
            correct=any(b['source']==source and b['size_parameter']==expectation['size_parameter'] and (
                expectation['via_api'] is None or nm(b['via_function_id'])==expectation['via_api']) for b in matches)
            check('input_binding',expectation['api']+'.'+expectation['parameter'],correct)
            if truth['mandatory_constraints'].get('nul_terminated_input'):
                check('input_binding',expectation['api']+':NUL representation',any(
                    b.get('input_kind')=='nul_terminated_string' and b.get('nul_terminated')
                    and b.get('transform')=='nul_terminate' for b in matches))
    for expectation in truth['callback']:
        matches=[c for c in callbacks if nm(c['function_id'])==expectation['api'] and (
            c['parameter'].replace('->','.')==expectation['parameter'] or
            (c.get('declaration_identity') or {}).get('field_path')==expectation['parameter'].split('.',1)[-1] or
            c['parameter']+'.'+(c.get('declaration_identity') or {}).get('field','')==expectation['parameter'])]
        present=any(c.get('declaration_identity') and c.get('signature') for c in matches)
        check('callback',expectation['api']+'.'+expectation['parameter']+':ABI',present)
        setup=expectation.get('registration_api')
        if setup:check('callback',expectation['api']+':registration',any(nm(c['setup_api'])==setup for c in matches))
        if expectation.get('fuzz_input_required'):
            check('callback',expectation['api']+':reader_behavior',None,'ABI success is not fuzz-backed reader construction')
        if expectation.get('kind')=='allocator':
            check('callback',expectation['api']+':allocator_behavior',None,'zero stub is not an allocator; behavior requires code audit')
        elif expectation.get('return_policy') not in {None,'void'}:
            check('callback',expectation['api']+':return_policy',None,'callback return behavior needs independent generated-code audit')
    reach={(nm(e['before']),nm(e['after'])) for e in context['ordering_graph']['edges'] if e['strength']=='hard'}
    while True:
        expanded=reach|{(a,c) for a,b in reach for b2,c in reach if b==b2}
        if expanded==reach:break
        reach=expanded
    aliases={r['origin']['api']:{r['origin']['api'],*r['origin'].get('alternatives',[])} for r in truth['resources']}
    for e in truth['ordering']:check('ordering',e['before']+'→'+e['after'],any((a,e['after']) in reach for a in aliases.get(e['before'],{e['before']})))
    initialization=truth['mandatory_constraints'].get('initializer_alternatives')
    if initialization:
        check('lifecycle','valid initialization API',bool(active&set(initialization['apis'])))
        check('ordering','initialization before consumer',any((a,initialization['consumer']) in reach for a in initialization['apis']))
    if truth['mandatory_constraints'].get('input_transport_needs_audit'):
        check('input_binding','fuzz-backed indirect input transport',None,'initializer binding needs independent generated-code audit')
    sequence=(plan or {}).get('call_sequence',[])+(plan or {}).get('cleanup_sequence',[])
    counts=Counter(nm(r['function_id']) for r in sequence)
    for api,count in truth['invocation_counts'].items():
        check('multiplicity',api+':calls_per_input',counts[api]==count if plan else None,{'expected':count,'observed':counts.get(api) if plan else None})
    for item in truth['mandatory_constraints'].get('non_null_arguments',[]):
        matches=[a for a in args if nm(a['function_id'])==item['api'] and a['parameter']==item['parameter']]
        check('lifecycle',item['api']+'.'+item['parameter']+':valid_storage',any(a['construction'] in {'stack','zero_init','creator_api','derived'} for a in matches))
    for item in truth['mandatory_constraints'].get('same_argument_storage',[]):
        def value(endpoint):return {a['resource_id'] for a in args if nm(a['function_id'])==endpoint[0] and a['parameter']==endpoint[1] and a['resource_id']}
        a,b=value(item['left']),value(item['right']);check('resource_identity','allocator identity',bool(a) and a==b)
    result={}
    for d,checks in buckets.items():
        status='not_applicable' if not checks else 'incorrect' if any(c['correct'] is False for c in checks) else 'unverified' if any(c['correct'] is None for c in checks) else 'correct'
        result[d]={'status':status,'checks':checks}
    return result


def rule_activity(context,report,configuration,functions,truth):
    rules=('resource_identity','creator_return','cleanup_consumption','public_callback_object','nul_contract','local_state_transition','ordering_projection')
    if context is None:return {r:{'status':'did_not_fire','applied':False,'reason':'upstream_no_context'} for r in rules}
    sources=context['construction_contract']['sources'];identity=context['resource_identity'];activities={}
    for rule in rules:
        disabled=rule in {'creator_return','cleanup_consumption','public_callback_object','local_state_transition'} and configuration!='C' or rule=='resource_identity' and configuration=='A'
        count=0;unresolved=False
        if rule=='resource_identity':
            count=sum(b['reason'] not in {'distinct_subject','model_grounded_identity_no_framework_projection'} for b in identity['bindings']);unresolved=bool(identity['unresolved'])
        elif rule in {'creator_return','cleanup_consumption','public_callback_object'}:count=sum(s['kind']==rule for s in sources)
        elif rule=='nul_contract':count=sum(b.get('input_kind')=='nul_terminated_string' for b in context['input_contract']['bindings'])
        elif rule=='local_state_transition':count=sum(len(c['state_transitions']) for c in context['construction_contract']['local_chains'])
        else:count=sum(e['strength']=='hard' for e in context['ordering_graph']['edges']);unresolved=bool(context['ordering_graph']['hard_cycles'])
        status='fired' if count else 'produced_unresolved' if unresolved else 'did_not_fire'
        if count and report and any('resource_identity' in e['code'] for e in report['validation_errors']) and rule=='resource_identity':status='blocked'
        reason='disabled_by_preregistered_ablation' if disabled else 'published_source_projection' if count else 'recognized_proof_subset_not_matched'
        if not disabled and not count and rule=='creator_return':
            creators={r['origin']['api'] for r in truth['resources']}
            selected=[f for f in functions if f['name'] in creators]
            if selected and all(f['parameters'] for f in selected):reason='creator_has_arguments (evaluation-side diagnosis)'
            elif any(r['origin']['kind']=='out_parameter' for r in truth['resources']):reason='origin_is_out_parameter (evaluation-side diagnosis)'
        activities[rule]={'status':status,'applied':bool(count),'count':count,'reason':reason,'disabled':disabled}
    return activities


def evaluate_trial(root,truth_path,case,configuration,trial,exit_code):
    truth=validate_truth(load(truth_path));root=Path(root);art=root/'artifacts'
    pipeline=load(root/'pipeline.json',{'status':'worker_failed','elapsed_seconds':None})
    functions=load(art/'functions.json',{}).get('functions',[]);names={f['id']:f['name'] for f in functions}
    candidate=load(one(art,'candidate_discovery/agent_runs/*/result.json'),{});slice_doc=load(one(art,'semantic_slices/*/slice.json'),{})
    ft=load(one(art,'minimal_fts/ft_*/minimal_ft.json'),{})
    # ArtifactStore's current directory name is authoritative; tolerate older spelling only in evaluation.
    if not ft:ft=load(one(art,'minimal_ft/ft_*/minimal_ft.json'),{})
    context=load(one(art,'harness_contexts/*/harness_context.json'));report=load(one(art,'harness_contexts/*/completeness.json'),{})
    closure=load(one(art,'harness_contexts/*/api_closure.json'),{})
    plan_path=one(art,'context_generations/*/*/harness_plan.json');plan=load(plan_path)
    generation=load(one(art,'context_generations/*/*/*/metadata.json'),{})
    build=load(one(art,'context_generations/*/*/*/build/build.json'),{});runtime=load(one(art,'context_generations/*/*/*/build/runtime.json'),{})
    validation=load(one(art,'context_generations/*/*/*/code_validation.json'),{})
    semantic=semantic_checks(context,closure,plan,names,truth)
    complete=report.get('generation_allowed') is True
    wrong=[d for d,s in semantic.items() if s['status']=='incorrect'];unverified=[d for d,s in semantic.items() if s['status']=='unverified']
    runtime_valid=runtime.get('status')=='passed';false_complete=complete and bool(wrong)
    # Runtime passing does not turn missing/unknown independent adjudication into correctness.
    outcome='complete_but_invalid' if complete and (wrong or not runtime_valid) else 'complete_and_runtime_valid' if complete and runtime_valid else 'blocked_conservatively'
    failure=set();core_actual=[names.get(fid,fid) for fid in slice_doc.get('core_functions',[])];support_actual=[names.get(r['function_id'],r['function_id']) for r in closure.get('required_support_apis',[])]
    core_score=precision_recall(core_actual,truth['core_apis']) if slice_doc else None
    aliases={a:r['origin']['api'] for r in truth['resources'] for a in r['origin'].get('alternatives',[])}
    support_score=precision_recall([aliases.get(a,a) for a in support_actual],truth['required_support']) if context else None
    verdict=candidate.get('verdict',candidate.get('decision',{}).get('verdict','not_run'))
    if verdict in {'unresolved','rejected'}:failure.add('candidate_'+verdict)
    if verdict=='rejected':failure.add('candidate_false_negative')
    if candidate and candidate.get('run_status')=='invalid':failure.add('candidate_invalid_output')
    if slice_doc and slice_doc.get('run_status') not in {'completed','completed_with_unresolved'}:failure.add('slice_invalid')
    if core_score and core_score['fn']:failure.add('slice_missing_core')
    if core_score and core_score['fp']:failure.add('slice_overexpanded_core')
    if support_score and support_score['fn']:failure.add('slice_missing_support')
    gaps=report.get('hard_missing',[])
    for gap in gaps:
        code=gap['code'];kind=gap['kind']
        mapping={'argument_construction':'argument_construction_unknown','input_binding':'input_binding_unknown','buffer_length':'input_binding_unknown',
                 'lifecycle':'lifecycle_unknown','ownership':'ownership_unknown','callback':'callback_unknown','state':'state_unknown','call_order':'state_unknown','return_semantics':'return_semantics_unknown'}
        if kind in mapping:failure.add(mapping[kind])
        if 'resource_identity' in code:failure.add('resource_identity_unresolved')
        if 'required_api' in code:failure.add('api_closure_unknown')
    for error in report.get('validation_errors',[]):
        if 'resource_identity' in error['code']:failure.add('resource_identity_conflict')
        if 'cycle' in error['code']:failure.add('ordering_cycle')
    if complete and plan is None:failure.add('plan_blocked')
    if generation.get('status')=='invalid_code':failure.add('code_generation_invalid')
    if build and not build.get('success'):failure.add('compile_failed')
    if runtime.get('status')=='failed':failure.add('runtime_failed')
    sanitizer=any(re.search(r'AddressSanitizer|LeakSanitizer|runtime error:',str(c.get('stderr',''))) for c in runtime.get('cases',[]))
    if sanitizer:failure.add('sanitizer_failed')
    if wrong:failure.add('semantic_contract_mismatch')
    if pipeline.get('status')=='static_anchor_unavailable':failure.add('static_analysis_failed')
    if pipeline.get('status') in {'pipeline_exception','worker_failed'}:failure.add('pipeline_exception')
    response_events={};model_errors=0;tool_calls=0;source_chars=0;stage_counts={}
    patterns=('candidate_discovery/agent_runs/*/trace.json','semantic_slices/*/trace.json','harness_contexts/*/agent_runs/*/attempt_*/trace.json')
    for pattern in patterns:
        stage='context' if pattern.startswith('harness_contexts') else 'slice' if pattern.startswith('semantic_slices') else 'candidate'
        counts=stage_counts.setdefault(stage,{'model_calls':0,'tool_calls':0})
        for path in art.glob(pattern):
            events=load(path,{}) .get('events',[])
            for event in events:
                if event['kind']=='model_response':
                    meta=event.get('metadata',{});response_events[meta.get('response_id',str(path)+':'+str(event.get('model_call')))]=meta
                    counts['model_calls']+=1
                elif event['kind']=='model_error':model_errors+=1;counts['model_calls']+=1;failure.add('provider_error')
                elif event['kind']=='tool_call' and not event.get('evidence_reuse'):tool_calls+=1;counts['tool_calls']+=1
    source_chars+=candidate.get('budget',{}).get('source_chars',0)+slice_doc.get('budget',{}).get('source_chars',0)
    ctx_meta=load(one(art,'harness_contexts/*/metadata.json'),{});source_chars+=ctx_meta.get('metrics',{}).get('source_chars',0)
    if ctx_meta:
        # Grouped requests are persisted under multiple requirement IDs; their
        # shared trace must not multiply model/tool costs.
        stage_counts['context']={k:ctx_meta['metrics'].get(k,0) for k in ('model_calls','tool_calls')}
    response=load(one(art,'context_generations/*/*/*/response.json'),{})
    tokens={k:sum(m.get('usage',{}).get(k,0) for m in response_events.values())+response.get('usage',{}).get(k,0) for k in ('prompt_tokens','completion_tokens','total_tokens')}
    row={'case':case['id'],'set':case['set'],'configuration':configuration,'trial':trial,'exit':exit_code,
         'artifact_root':str(root),'pipeline_status':pipeline['status'],'candidate_status':verdict,
         'slice_status':slice_doc.get('run_status','not_run'),'slice_success':slice_doc.get('run_status') in {'completed','completed_with_unresolved'},
         'slice_core_size':len(core_actual) if slice_doc else None,'slice_support_size':len(slice_doc.get('support_functions',[])) if slice_doc else None,
         'slice_unresolved_size':len(slice_doc.get('unresolved_frontier',[])) if slice_doc else None,
         'minimal_ft_core_size':len(ft.get('core_functions',[])) if ft else None,'minimal_ft_support_size':len(ft.get('support_candidates',[])) if ft else None,
         'context_status':report.get('status','not_run'),'context_complete':complete,'hard_gaps':len(gaps) if report else None,
         'soft_unknowns':len(report.get('soft_unknown',report.get('soft_unknowns',[]))) if report else None,
         'api_closure_size':len(context['core_apis'])+len(closure.get('required_support_apis',[])) if context else None,
         'core_precision_recall':core_score,'support_precision_recall':support_score,'semantic_correctness':semantic,
         'semantic_verified':bool(context) and not wrong and not unverified,'false_complete':false_complete,
         'false_complete_reasons':wrong if complete else [],'unverified_dimensions':unverified,'outcome':outcome,
         'plan_success':plan is not None,'code_success':validation.get('status')=='valid',
         'compile_success':build.get('success',False),'runtime_success':runtime_valid,'sanitizer_failed':sanitizer,
         'sanitizer_status':'failed' if sanitizer else 'passed' if runtime_valid else 'not_run_or_unverified',
         'failure_reasons':sorted(failure),'hard_gap_codes':sorted({g['code'] for g in gaps}),'validation_errors':report.get('validation_errors',[]),
         'certificates':rule_activity(context,report,configuration,functions,truth),'model_calls':sum(s['model_calls'] for s in stage_counts.values())+generation.get('model_calls',0),
         'tool_calls':sum(s['tool_calls'] for s in stage_counts.values()),'stages':stage_counts,'tokens':tokens,'source_chars':source_chars,'elapsed_seconds':pipeline.get('elapsed_seconds'),
         'served_models':sorted({m.get('served_model','unknown') for m in response_events.values()}),
         'ground_truth_digest':__import__('hashlib').sha256(Path(truth_path).read_bytes()).hexdigest(),
         'adjudication':'independent necessary-contract comparison; passing runtime never substitutes for semantic verification'}
    return row
