#!/usr/bin/env python3
"""Matched fresh regression trials against two immutable local source snapshots."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import time


def hashes(root):
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
            for directory in ('harness_generation','sfg_builder','scripts')
            for p in sorted((root/directory).rglob('*.py'))}


def atomic(path, data):
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    temporary.replace(path)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--revision',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--env-file',type=Path,required=True)
    parser.add_argument('--repetitions',type=int,default=5)
    parser.add_argument('--seed',type=int,default=20261001)
    args=parser.parse_args()
    if args.repetitions!=5:
        raise ValueError('registered protocol requires five repetitions')
    roots={'baseline':args.baseline.resolve(),'revision':args.revision.resolve()}
    # Load the protocol from the revision, without importing either production
    # version into this supervisor. Child processes have isolated module roots.
    cases=['bounded_scalar','creator_with_args','out_parameter','shared_context','owned_return','callback_context']
    frozen={arm:hashes(root) for arm,root in roots.items()}
    case_hashes={}
    for arm,root in roots.items():
        code="import sys,json,hashlib;sys.path[:0]=['.', 'scripts'];from smoke_argument_graph import CASES;print(json.dumps({k:hashlib.sha256(v.encode()).hexdigest() for k,v in CASES.items()}))"
        case_hashes[arm]=json.loads(subprocess.check_output([sys.executable,'-c',code],cwd=root,text=True))
    if case_hashes['baseline']!=case_hashes['revision']:
        raise ValueError('case source mismatch')
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    rng=random.Random(args.seed)
    pairs=[dict(case=case,repetition=r) for r in range(1,args.repetitions+1) for case in cases]
    rng.shuffle(pairs)
    for i,pair in enumerate(pairs):
        order=list(roots);rng.shuffle(order);pair.update(pair_id=i+1,arm_order=order)
    registration={'schema_version':1,'category':'matched_fresh_development_regression',
        'blind_generalization_evidence':False,'causal_layer_ablation':False,
        'baseline_commit':'59b6afb55e382eec3c62427e3273502455315285',
        'repetitions':args.repetitions,'planned_trials':len(pairs)*2,'workers':2,
        'randomization_seed':args.seed,'schedule':pairs,'case_source_sha256':case_hashes['revision'],
        'source_snapshots':{k:str(v) for k,v in roots.items()},'file_sha256':frozen,
        'coordinator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'stopping_rules':['no retries or dropped failures','stop on source/runner mutation','preserve all provider failures'],
        'budget_matching':'same six source fixtures and default ValidationBudget/ContextBudget in both snapshots; verified from child registrations',
        'primary_endpoint':'all-stage runtime_success over every planned trial',
        'secondary_endpoints':['slice success','context completion','hard gaps','model/tool calls','tokens','compile success'],
        'started_at':datetime.now(timezone.utc).isoformat()}
    atomic(output/'registration.json',registration)
    rows=[]
    def unchanged():
        return all(hashes(root)==frozen[arm] for arm,root in roots.items())
    def save(complete=False):
        atomic(output/'summary.json',{'registration':registration,'completed':complete,
            'implementation_unchanged':unchanged(),'completed_trials':len(rows),
            'trials':sorted(rows,key=lambda r:(r['pair_id'],r['arm']))})
    def trial(pair,arm):
        started=time.monotonic()
        name=f"{pair['pair_id']:02d}_{pair['case']}_r{pair['repetition']:02d}_{arm}"
        target=output/name
        cmd=[sys.executable,str(roots[arm]/'scripts/smoke_argument_graph.py'),
             '--case',pair['case'],'--repetitions','1','--workers','1',
             '--env-file',str(args.env_file.resolve()),'--output',str(target)]
        with (output/(name+'.log')).open('w') as log:
            result=subprocess.run(cmd,cwd=roots[arm],stdout=log,stderr=subprocess.STDOUT)
        summary=target/'summary.json'
        row={'pair_id':pair['pair_id'],'case':pair['case'],'repetition':pair['repetition'],
            'arm':arm,'child_exit_code':result.returncode,'summary_path':str(summary),
            'elapsed_seconds':round(time.monotonic()-started,3)}
        if summary.exists():
            data=json.loads(summary.read_text())
            row['child_registration']=data['registration']
            if not data['completed'] or not data['implementation_unchanged']:
                raise RuntimeError('child did not complete under one frozen implementation')
            if len(data['trials'])!=1:
                raise RuntimeError('child trial cardinality changed')
            row['trial']=data['trials'][0]
        else:
            row['trial']={'status':'supervisor_missing_summary','slice_status':'not_run',
                          'compile_success':False,'runtime_success':False}
        return row
    save()
    with ThreadPoolExecutor(max_workers=2) as pool:
        for pair in pairs:
            if not unchanged():raise RuntimeError('source changed during registered experiment')
            jobs={pool.submit(trial,pair,arm):arm for arm in pair['arm_order']}
            for future in as_completed(jobs):
                row=future.result();rows.append(row);save()
                print('[PAIRED]',row['pair_id'],row['case'],row['arm'],row['trial'].get('status'),f"{len(rows)}/60",flush=True)
            if not unchanged():raise RuntimeError('source changed during registered experiment')
    comparable={json.dumps({k:r['child_registration'][k] for k in ['validation_budget','context_budget','provider','code_max_tokens']},sort_keys=True)
                for r in rows if 'child_registration' in r}
    if len(comparable)!=1:raise RuntimeError('provider configuration or budget mismatch across trials')
    registration['completed_at']=datetime.now(timezone.utc).isoformat()
    # The original registration remains immutable; completion metadata is only
    # in summary. A hash links every analysis to that pre-call registration.
    registration['preregistration_sha256']=hashlib.sha256((output/'registration.json').read_bytes()).hexdigest()
    save(complete=True)


if __name__=='__main__':main()
