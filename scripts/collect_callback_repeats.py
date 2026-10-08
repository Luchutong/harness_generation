#!/usr/bin/env python3
"""Read-only summaries of registered paired fresh trials; no replay/model calls."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics

from collect_argument_graph_smoke import collect


def audit_registration(cohort):
    registration=cohort['registration']
    expected={(pair['pair_id'],arm):pair for pair in registration['schedule'] for arm in pair['arm_order']}
    observed={(row['pair_id'],row['arm']) for row in cohort['trials']}
    if len(observed)!=len(cohort['trials']) or observed!=set(expected):
        raise ValueError('trial identities do not match the registered schedule')
    fingerprints={}
    for arm,root_string in registration['source_snapshots'].items():
        root=Path(root_string)
        files={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
            for directory in ['harness_generation','sfg_builder','scripts']
            for p in sorted((root/directory).rglob('*.py'))}
        if files!=registration['file_sha256'][arm]:
            raise ValueError(f'{arm} snapshot changed')
        production=sorted([*(root/'harness_generation').rglob('*.py'),*(root/'sfg_builder').rglob('*.py')])
        fingerprints[arm]=hashlib.sha256(b''.join(str(p.relative_to(root)).encode()+p.read_bytes() for p in production)).hexdigest()
    configurations=set()
    for row in cohort['trials']:
        pair=expected[row['pair_id'],row['arm']]
        if row['case']!=pair['case'] or row['repetition']!=pair['repetition']:
            raise ValueError('case/repetition mismatch')
        child=row['child_registration']
        if child['production_fingerprint']!=fingerprints[row['arm']] or child['resume'] or child['failed_retry']:
            raise ValueError('native trial version/freshness mismatch')
        configurations.add(json.dumps({k:child[k] for k in ['provider','validation_budget','context_budget','code_max_tokens']},sort_keys=True))
        trial=row['trial']
        source=(Path(row['child_directory'])/(row['case']+'_project')/'api.c' if row.get('external_interruption')
                else Path(trial['project'])/'api.c')
        if hashlib.sha256(source.read_bytes()).hexdigest()!=registration['case_source_sha256'][row['case']]:
            raise ValueError('trial source differs from the registered fixture')
        if not row.get('external_interruption'):
            native=json.loads(Path(row['summary_path']).read_text())
            if native['trials']!=[trial] or native['registration']!=child:
                raise ValueError('supervisor/native summary disagreement')
    if len(configurations)!=1:
        raise ValueError('provider/budget mismatch')
    upstream_prefixes=('harness_generation/semantic_discovery/','harness_generation/semantic_slicing/','harness_generation/minimal_ft/')
    upstream={arm:{k:v for k,v in registration['file_sha256'][arm].items() if k.startswith(upstream_prefixes)}
              for arm in fingerprints}
    return {'registered_trials':len(observed),'snapshot_hashes_verified':True,'fixture_hashes_verified':True,
        'native_summaries_verified':True,'matching_provider_budget_configurations':len(configurations),
        'candidate_slice_minimal_ft_implementation_identical':upstream['baseline']==upstream['revision'],
        'production_fingerprints':fingerprints}


def upstream_calls(artifacts):
    stages = {}
    for stage, pattern in [('candidate', 'candidate_discovery/agent_runs/*/trace.json'),
                           ('slice', 'semantic_slices/*/trace.json')]:
        events = [e for p in artifacts.glob(pattern)
                  for e in json.loads(p.read_text()).get('events', [])]
        stages[stage] = {
            'model_calls': sum(e['kind'] == 'model_response' or
                               (e['kind'] == 'model_error' and e.get('error_category') != 'budget_exhausted')
                               for e in events),
            'tool_calls': sum(e['kind'] == 'tool_call' for e in events)}
    return stages


def callback_observations(artifacts, row):
    path=next(artifacts.glob('harness_contexts/*/harness_context.json'),None)
    if row['case']!='callback_context' or path is None:
        return None
    context=json.loads(path.read_text())
    dispatches=context['argument_graph'].get('callback_dispatches',[])
    handlers={d['function_id'] for d in dispatches}
    active=row['canonical_active_parameters']
    return {'source_proven_dispatches':len(dispatches),
        'all_active_recipes_resolved':bool(active) and all(p['status']=='resolved' for p in active),
        'forwarded_input_bindings':sum(b['function_id'] in handlers and b['source']=='derived'
                                       for b in context['input_contract']['bindings'])}


def collect_partial(raw):
    """Read persisted observations; do not fabricate a completed native run."""
    root=Path(raw['child_directory'])
    artifacts=root/(raw['case']+'_phase1')
    responses={};errors=[];protocol=[];metadata=[]
    for trace in artifacts.rglob('trace.json'):
        if 'harness_contexts' in trace.parts and not trace.parent.name.startswith('attempt_'):
            continue
        meta=trace.with_name('metadata.json')
        meta=json.loads(meta.read_text()) if meta.exists() else {}
        if meta.get('group_cost_owner') is False:
            continue
        context_trace='harness_contexts' in trace.parts
        if context_trace:metadata.append(meta)
        for event in json.loads(trace.read_text()).get('events',[]):
            if event['kind']=='model_response':responses[event['metadata']['response_id']]=(event['metadata'],context_trace)
            elif event['kind']=='model_error' and event.get('error_category')!='budget_exhausted':errors.append(event)
            elif event.get('error_category'):protocol.append(event)
    read=lambda pattern:next((json.loads(p.read_text()) for p in artifacts.glob(pattern)),{})
    sliced=read('semantic_slices/*/slice.json');ft=read('minimal_fts/*/minimal_ft.json')
    tokens={key:sum(meta.get('usage',{}).get(key,0) for meta,_ in responses.values()) for key in ['prompt_tokens','completion_tokens','total_tokens']}
    return {'case':raw['case'],'status':'external_interruption','slice_status':sliced.get('run_status','not_observed'),
        'ft_status':ft.get('build_status','not_observed'),'context_complete':False,
        'context_status':'not_observed','hard_gap_count':None,'hard_gap_codes':{},
        'compile_success':False,'runtime_success':False,'generation_allowed':False,
        'context_metrics':{'model_calls':sum(m.get('model_calls',0) for m in metadata),
            'tool_calls':None,'recorded_group_tool_calls':sum(m.get('tool_calls',0) for m in metadata)},
        'pipeline_tokens':tokens,'actual_provider_responses':len(responses),'failed_requests':errors,
        'protocol_events':protocol,'normalized_history_successful_requests':[meta['request_diagnostics'] for meta,_ in responses.values()
            if meta.get('request_diagnostics',{}).get('normalized_tool_history_count',0)],
        'canonical_active_parameters':[],'served_models':sorted({meta['served_model'] for meta,_ in responses.values()}),
        'observations_are_partial':True,'cost_is_lower_bound':True,
        'note':'Context/global tool calls and any in-flight provider work were not persisted; no Context failure is inferred.'}


def wilson(success,n):
    z=1.959963984540054
    center=(success/n+z*z/(2*n))/(1+z*z/n)
    delta=z*math.sqrt((success/n)*(1-success/n)/n+z*z/(4*n*n))/(1+z*z/n)
    return [round(100*(center-delta),2),round(100*(center+delta),2)]


def stats(rows):
    n=len(rows)
    count=lambda k:sum(bool(r.get(k)) for r in rows)
    values=lambda key:[r['context_metrics'][key] for r in rows if not r.get('external_interruption')]
    metric=lambda key:dict(total=sum(values(key)),median=statistics.median(values(key)),
        range=[min(values(key)),max(values(key))],complete_observations=len(values(key)))
    gaps=[r['hard_gap_count'] for r in rows if r.get('hard_gap_count') is not None]
    sizes=[r['minimal_ft_size'] for r in rows if r.get('minimal_ft_size') is not None]
    native=[r for r in rows if not r.get('external_interruption')]
    return {'trials':n,'slice_success':sum(r.get('slice_status') in {'completed','completed_with_unresolved'} for r in rows),
        'context_complete':count('context_complete'),'compile_success':count('compile_success'),
        'runtime_success':count('runtime_success'),
        'runtime_wilson_95_percent':wilson(count('runtime_success'),n),
        'completed_native_trials':sum(not r.get('external_interruption') for r in rows),
        'external_interrupted_trials':sum(bool(r.get('external_interruption')) for r in rows),
        'hard_gap_observation_missing':sum(r.get('hard_gap_count') is None for r in rows),
        'hard_gaps_total':sum(r.get('hard_gap_count') or 0 for r in rows),
        'hard_gaps_observed_distribution':{'n':len(gaps),'median':statistics.median(gaps) if gaps else None,
            'range':[min(gaps),max(gaps)] if gaps else None},
        'minimal_ft_size_observed_distribution':{'n':len(sizes),'median':statistics.median(sizes) if sizes else None,
            'range':[min(sizes),max(sizes)] if sizes else None},
        'hard_gap_codes':dict(sum((Counter(r.get('hard_gap_codes',{})) for r in rows),Counter())),
        'status_counts':dict(Counter(r['status'] for r in rows)),
        'context_status_counts':dict(Counter(r['context_status'] for r in rows)),
        'context_model_calls':metric('model_calls'),
        'context_tool_calls':metric('tool_calls'),
        'completed_pipeline_model_calls':sum(r['pipeline_model_calls'] for r in native),
        'completed_pipeline_tool_calls':sum(r['pipeline_tool_calls'] for r in native),
        'recorded_interrupted_context_model_calls':sum(r['context_metrics']['model_calls'] for r in rows if r.get('external_interruption')),
        'pipeline_response_tokens':sum(r['pipeline_tokens']['total_tokens'] for r in rows),
        'pipeline_recorded_successful_responses':sum(r['actual_provider_responses'] for r in rows),
        'failed_request_counts':dict(Counter(e['error_category'] for r in rows for e in r['failed_requests'])),
        'request_attempts':sum(r['actual_provider_responses']+len(r['failed_requests'])+r['unrecorded_codegen_calls'] for r in rows),
        'unrecorded_codegen_calls':sum(r['unrecorded_codegen_calls'] for r in rows),
        'codegen_request_failures':sum(r['codegen_request_failure'] for r in rows),
        'normalized_history_successful_requests':sum(len(r['normalized_history_successful_requests']) for r in rows),
        'terminal_schema_failures':sum(e.get('error_category')=='terminal_schema_error' for r in rows for e in r['protocol_events']),
        'canonical_active_parameter_statuses':dict(Counter(p['status'] for r in rows for p in r['canonical_active_parameters'])),
        'canonical_unresolved_active_reasons':dict(Counter(p['reason'] for r in rows for p in r['canonical_active_parameters'] if p['status']!='resolved')),
        'callback_contexts_observed':sum(r['callback_observations'] is not None for r in rows),
        'callback_dispatch_proven_trials':sum(bool(r['callback_observations'] and r['callback_observations']['source_proven_dispatches']) for r in rows),
        'callback_all_active_recipes_resolved_trials':sum(bool(r['callback_observations'] and r['callback_observations']['all_active_recipes_resolved']) for r in rows),
        'callback_derived_input_trials':sum(bool(r['callback_observations'] and r['callback_observations']['forwarded_input_bindings']) for r in rows),
        'complete_with_semantic_only_active_trials':sum(r['context_complete'] and any(p['status']=='resolved' and p['reason']=='semantic_only_not_reproduced' for p in r['canonical_active_parameters']) for r in rows),
        'resolved_semantic_only_active_parameters':sum(p['status']=='resolved' and p['reason']=='semantic_only_not_reproduced' for r in rows for p in r['canonical_active_parameters'])}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    original=args.experiment/'summary.json';cohort=json.loads(original.read_text())
    if not cohort['completed'] or not cohort['implementation_unchanged'] or len(cohort['trials'])!=60:
        raise ValueError('require all 60 trials and unchanged snapshots')
    audit=audit_registration(cohort)
    rows=[]
    for raw in cohort['trials']:
        if raw.get('external_interruption'):
            row=collect_partial(raw);summary_hash=None
        else:
            batch=collect(Path(raw['summary_path']).parent)
            row=batch['trials'][0];summary_hash=batch['native_summary_sha256']
        trial=raw['trial'];generation=trial.get('generation',{})
        unrecorded=generation.get('model_calls',0) if not trial.get('code_generation_response') else 0
        artifacts=(Path(raw['child_directory'])/(raw['case']+'_phase1') if raw.get('external_interruption')
                   else Path(trial['artifacts']))
        stages=upstream_calls(artifacts)
        stages['context']={k:row['context_metrics'][k] for k in ['model_calls','tool_calls']}
        stages['code']={'model_calls':generation.get('model_calls',0),'tool_calls':0}
        model_calls=sum(s['model_calls'] for s in stages.values())
        tool_calls=(None if raw.get('external_interruption') else sum(s['tool_calls'] for s in stages.values()))
        if not raw.get('external_interruption'):
            observed=row['actual_provider_responses']+len(row['failed_requests'])+unrecorded
            if model_calls!=observed:
                raise ValueError(f"model-call observations disagree in pair {raw['pair_id']} {raw['arm']}")
        rows.append({**row,'arm':raw['arm'],'pair_id':raw['pair_id'],'repetition':raw['repetition'],
            'elapsed_seconds':raw['elapsed_seconds'],'case':raw['case'],'native_summary_sha256':summary_hash,
            'external_interruption':bool(raw.get('external_interruption')),
            'stages':stages,'pipeline_model_calls':model_calls,'pipeline_tool_calls':tool_calls,
            'callback_observations':callback_observations(artifacts,row),
            'generation_error':generation.get('error'),'unrecorded_codegen_calls':unrecorded,
            'codegen_request_failure':bool(unrecorded and 'request failed' in (generation.get('error') or ''))})
    totals={arm:stats([r for r in rows if r['arm']==arm]) for arm in ['baseline','revision']}
    completed_native_totals={arm:stats([r for r in rows if r['arm']==arm and not r['external_interruption']]) for arm in totals}
    cases=cohort['registration']['case_source_sha256']
    per_case={case:{arm:stats([r for r in rows if r['arm']==arm and r['case']==case]) for arm in totals} for case in cases}
    pairs={pair:{r['arm']:r for r in rows if r['pair_id']==pair} for pair in range(1,31)}
    outcomes=Counter((p['baseline']['runtime_success'],p['revision']['runtime_success']) for p in pairs.values())
    improved=outcomes[False,True];regressed=outcomes[True,False];discordant=improved+regressed
    pvalue=min(1,2*sum(math.comb(discordant,k) for k in range(min(improved,regressed)+1))/(2**discordant)) if discordant else 1
    comparison={'both_success':outcomes[True,True],'both_failure':outcomes[False,False],
        'baseline_failure_revision_success':improved,'baseline_success_revision_failure':regressed,
        'descriptive_exact_mcnemar_two_sided_p':pvalue,
        'interpretation':'bundle comparison on reused development fixtures; not individual-layer causal ablation or blind generalization'}
    native_ft_pairs=[p for p in pairs.values() if all(not r['external_interruption'] and
        r['ft_status'] in {'completed','completed_with_unresolved'} for r in p.values())]
    same_core_pairs=[p for p in native_ft_pairs if sorted(p['baseline']['core'])==sorted(p['revision']['core'])]
    def subset_counts(subset):
        counts=Counter((p['baseline']['runtime_success'],p['revision']['runtime_success']) for p in subset)
        return {'pairs':len(subset),'both_success':counts[True,True],'both_failure':counts[False,False],
            'baseline_failure_revision_success':counts[False,True],'baseline_success_revision_failure':counts[True,False],
            'interpretation':'exploratory conditioning on observed upstream outcomes; not the preregistered primary endpoint'}
    result={'category':'paired_fresh_development_regression','source_summary_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),
        'audit':audit,
        'cost_notes':{'successful_response_tokens':'deduplicated native response IDs, including code generation; failed/in-flight work without usage is unknown',
            'pipeline_model_calls':'candidate/slice trace attempts plus Context global calls and code generation metadata; reconciled against observed responses/errors',
            'pipeline_tool_calls':'candidate/slice trace calls plus Context global tool calls; excludes interrupted observations',
            'interrupted_costs':'recorded responses only; unpersisted in-flight work and final Context tool totals are unknown'},
        'analysis_script_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in
            [Path(__file__),Path(__file__).with_name('collect_argument_graph_smoke.py')]},
        'preregistration_sha256':hashlib.sha256((args.experiment/'registration.json').read_bytes()).hexdigest(),
        'production_fingerprints':{arm:next(r['child_registration']['production_fingerprint'] for r in cohort['trials'] if r['arm']==arm) for arm in totals},
        'totals':totals,'completed_native_totals':completed_native_totals,'per_case':per_case,'paired_comparison':comparison,
        'exploratory_both_native_ft_pairs':subset_counts(native_ft_pairs),
        'exploratory_same_core_native_ft_pairs':subset_counts(same_core_pairs),'trials':rows}
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    report=['# Callback boundary matched fresh repetitions','',
        'Development/regression evidence. Same sources, provider settings, budgets and six runtime inputs; all failures included.','',
        '| API model | Baseline Slice / Context / Compile / Runtime | Revision Slice / Context / Compile / Runtime |',
        '| --- | --- | --- |']
    for case,data in per_case.items():
        text=lambda a:' / '.join(f"{data[a][k]}/5" for k in ['slice_success','context_complete','compile_success','runtime_success'])
        report.append(f"| {case} | {text('baseline')} | {text('revision')} |")
    report+=['','```json',json.dumps({'totals':totals,'paired_comparison':comparison},ensure_ascii=False,indent=2),'```','']
    (args.output/'report.md').write_text('\n'.join(report))
    print(json.dumps({'totals':totals,'paired_comparison':comparison},ensure_ascii=False))


if __name__=='__main__':main()
