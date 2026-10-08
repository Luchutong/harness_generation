#!/usr/bin/env python3
"""Collect frozen development results; verify artifacts without rerunning models."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


def write(path,value):
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def policy(root):
    code="""import sys,json
sys.path.insert(0,sys.argv[1])
from harness_generation.harness_context.models import ContextBudget,PROMPT_VERSION,POLICY_VERSION
from harness_generation.harness_context.tools import EXTRA_SCHEMAS
from harness_generation.semantic_discovery.tools import TOOL_SCHEMAS
from harness_generation.semantic_discovery.models import digest
print(json.dumps(dict(budget=ContextBudget().to_dict(),tool_registry_digest=digest([TOOL_SCHEMAS,EXTRA_SCHEMAS]),
    tool_names=sorted(t['function']['name'] for t in [*TOOL_SCHEMAS,*EXTRA_SCHEMAS]),prompt=PROMPT_VERSION,policy=POLICY_VERSION)))
"""
    return json.loads(subprocess.check_output([sys.executable,'-c',code,str(root)],text=True))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    args=parser.parse_args();root=args.root.resolve()
    audit=read(root/'audit.json') if (root/'audit.json').exists() else {}
    audit.update(blind_experiment=False,snapshots={})
    for arm,name in [('baseline','baseline'),('revision','revision_final')]:
        manifest=read(root/(name+'_manifest.json'))['file_sha256'];snapshot=root/name
        mismatch=[p for p,v in manifest.items() if sha(snapshot/p)!=v]
        production={p:v for p,v in manifest.items() if p.startswith(('harness_generation/','sfg_builder/'))}
        audit['snapshots'][arm]=dict(files=len(manifest),mismatches=mismatch,production_fingerprint=digest(production),
            policy=policy(snapshot))
        assert not mismatch,'frozen source changed'
    left,right=[audit['snapshots'][a]['policy'] for a in ('baseline','revision')]
    audit['same_budget']=left['budget']==right['budget']
    audit['same_tool_registry']=left['tool_registry_digest']==right['tool_registry_digest']
    assert audit['same_budget'] and audit['same_tool_registry']
    offline=read(root/'offline_verified/summary.json');assert offline['completed']
    pairs=defaultdict(list)
    for row in offline['trials']:pairs[row['case']].append(row)
    audit['fixed_evidence_pairs']={c:len(rows)==2 and len({r['input_digest'] for r in rows})==1
        and len({r['input_file_sha256'] for r in rows})==1 for c,rows in pairs.items()}
    assert all(audit['fixed_evidence_pairs'].values())
    result={'offline':{'trials':offline['trials'],'aggregate':{}},'native':{'trials':[],'aggregate':{},'by_class':{}}}
    for arm in ('baseline','revision'):
        rows=[r for r in offline['trials'] if r['arm']==arm]
        result['offline']['aggregate'][arm]=dict(trials=len(rows),negative_cases=sum(not r['expected_allowed'] for r in rows),
            false_allow=sum(r['false_allow'] for r in rows),false_block=sum(r['false_block'] for r in rows),
            followup_tasks=sum(r['followup_tasks'] for r in rows))
    native=read(root/'native/summary.json');assert native['completed'],'native schedule incomplete'
    registration=read(root/'native/registration.json')
    audit['runner_frozen_matches_registration']=sha(root/'native/runner_frozen.py')==registration['runner_sha256']
    assert audit['runner_frozen_matches_registration']
    for row in native['trials']:
        row=dict(row)
        target=next(p for p in (root/'native').glob('*_'+row['case']+'_'+row['arm']+'_'+str(row['repeat'])) if p.is_dir())
        # The first runner wrote build_success correctly but left its separately
        # initialized compile_success false. Use the actual compiler artifact;
        # retain every original trial/summary byte, and publish the correction.
        markers=list((target/'fixture/phase1/context_generations').glob('*/*/*/metadata.json'))
        row['compile_success']=False;row['runtime_success']=False;row['code_generation_calls']=0
        for marker in markers:
            row['code_generation_calls']+=read(marker).get('model_calls',0)
            for kind in ('build','runtime'):
                path=marker.parent/'build'/(kind+'.json')
                if path.exists():row['compile_success' if kind=='build' else 'runtime_success']=read(path)['status']=='passed'
        traces=[read(p) for p in (target/'fixture/phase1/harness_contexts').glob('*/agent_runs/*/attempt_*/trace.json')
            if read(p.with_name('metadata.json')).get('group_cost_owner',True)]
        row['served_models']=sorted({e['metadata']['served_model'] for trace in traces for e in trace['events']
            if e['kind']=='model_response' and e.get('metadata',{}).get('served_model')})
        row['execution_failures']=row.get('execution_failures',row.get('provider_errors',[]))
        row['provider_errors']=[e for trace in traces for e in trace['events'] if e['kind']=='model_error']
        row['terminal_execution_errors']=[e for trace in traces for e in trace['events'] if e['kind']=='execution_error']
        reports=list((target/'fixture/phase1/harness_contexts').glob('*/completeness.json'))
        if reports:
            report=read(reports[0]);row['hard_codes']=sorted({r['code'] for r in report['hard_missing']})
            row['validation_errors']=report['validation_errors']
        row['artifact_directory']=str(target.relative_to(root))
        result['native']['trials'].append(row)
    rows=result['native']['trials']
    audit['fixed_ft_per_class']={c:len({r['minimal_ft_digest'] for r in rows if r['case']==c})==1
        for c in {r['case'] for r in rows}}
    audit['fixed_model_and_budget']=len({digest([r['model'],r['budget']]) for r in rows})==1
    assert all(audit['fixed_ft_per_class'].values()) and audit['fixed_model_and_budget']
    def aggregate(group):
        return dict(trials=len(group),context_complete=sum(r['context_complete'] for r in group),
            compile_success=sum(r['compile_success'] for r in group),runtime_success=sum(r['runtime_success'] for r in group),
            hard_gap_rows=sum(r['hard_gaps'] for r in group),model_calls=sum(r['model_calls'] for r in group),
            native_responses=sum(r['native_responses'] for r in group),tool_calls=sum(r['tool_calls'] for r in group),
            model_queries=sum(r['model_query_count'] for r in group),repeated_model_queries=sum(r['repeated_model_queries'] for r in group),
            context_tokens=sum(r['tokens']['total_tokens'] for r in group),
            generation_tokens=sum(r.get('generation_response_usage',{}).get('total_tokens',0) for r in group),
            code_generation_calls=sum(r['code_generation_calls'] for r in group),
            bootstrap_reads=sum(r['metrics'].get('bootstrap_source_reads',0) for r in group),
            bootstrap_reuses=sum(r['metrics'].get('bootstrap_evidence_reuses',0) for r in group),
            proved_requirement_skips=sum(r['metrics'].get('proved_investigation_skips',0) for r in group),
            provider_failures=sum(len(r.get('provider_errors',[])) for r in group),
            terminal_execution_errors=sum(len(r['terminal_execution_errors']) for r in group),
            execution_failed_requirements=sum(len(r['execution_failures']) for r in group))
    for arm in ('baseline','revision'):
        result['native']['aggregate'][arm]=aggregate([r for r in rows if r['arm']==arm])
        result['native']['by_class'][arm]={c:aggregate([r for r in rows if r['arm']==arm and r['case']==c])
            for c in sorted({r['case'] for r in rows})}
    audit['compile_collection_correction']='compile_success recomputed from actual build/build.json; original raw artifacts unchanged'
    audit['execution_error_collection_correction']='provider_errors classified from model_error traces; terminal schema errors reported separately'
    write(root/'audit.json',audit);write(root/'collected_results.json',result)
    print(json.dumps({'offline':result['offline']['aggregate'],'native':result['native']['aggregate']},indent=2))


if __name__=='__main__':main()
