"""Preregistered fresh native A/B/C trials. Failed trials remain in the denominator."""
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime,timezone
import json
from pathlib import Path
import random
import subprocess
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from blind_eval.ablation import DESCRIPTIONS
from blind_eval.identity import assert_frozen,file_digest
from blind_eval.evaluate import evaluate_trial,validate_truth
from harness_generation.records import write_json


def run(args):
    args.output=args.output.resolve();freeze=args.output/'freeze/manifest.json';assert_frozen(freeze)
    if (args.output/'preregistration.json').exists():raise ValueError('new output directory required; no failed-trial retry/resume')
    benchmark=args.benchmark_dir.resolve()
    cases=[]
    for file in ('synthetic_manifest.json','real_manifest.json'):
        cases.extend(json.loads((benchmark/file).read_text())['cases'])
    for case in cases:
        truth=benchmark/Path(case['source_dir']).parent/'ground_truth.json'
        validate_truth(json.loads(truth.read_text()))
        # Validate the exact persisted build schema before making any model call.
        from harness_generation.target_build import TargetBuildConfig
        TargetBuildConfig.from_dict({'schema_version':1,'project_root':str(benchmark/case['source_dir']),
            'source_files':case['sources'],'header_files':case['headers'],'include_paths':case['include_paths'],
            'compiler_flags':case['compiler_flags'],'link_flags':case['link_flags']}).validate_inputs()
    # Archives include evaluation code, input sources and annotations. Annotation
    # archive stays in supervisor space and is never indexed by a trial worker.
    evaluation_files=file_digest(ROOT/'scripts/blind_eval');benchmark_files=file_digest(benchmark)
    schema_path=ROOT/'benchmarks/blind/ground_truth.schema.json';schema_digest=__import__('hashlib').sha256(schema_path.read_bytes()).hexdigest()
    with tarfile.open(args.output/'freeze/evaluation_and_benchmarks.tar.gz','w:gz') as archive:
        archive.add(benchmark,arcname='benchmarks/blind',filter=lambda info: None if '__pycache__' in info.name else info)
        archive.add(ROOT/'scripts/blind_eval',arcname='scripts/blind_eval',filter=lambda info: None if '__pycache__' in info.name else info)
        archive.add(schema_path,arcname='ground_truth.schema.json')
    jobs=[(case,cfg,n) for case in cases for cfg in ('A','B','C') for n in range(1,args.repetitions+1)]
    random.Random(20260929).shuffle(jobs)
    registration={'schema_version':1,'category':'native_blind_semantic_pipeline','started_at':datetime.now(timezone.utc).isoformat(),
        'freeze_manifest':str(freeze),'evaluation_version':'blind-native-v2','benchmark_directory':str(benchmark),
        'repetitions_per_case_per_configuration':args.repetitions,'planned_trials':len(jobs),
        'workers':args.workers,'schedule_seed':20260929,'model_seed':'unspecified','explicit_anchor':True,
        'candidate_recall_evaluation':False,'ground_truth_visible_to_pipeline':False,'resume':False,'failed_trial_retry':False,
        'ablation':DESCRIPTIONS,'ablation_scope':'evaluation-only projection subtraction; Gate/prompts/tools remain unchanged',
        'held_constant':['callback ABI enrichment','NUL projection','existing ordering validators','bounded evidence preflight','tool registry','all stage ceilings'],
        'evaluation_code_digests':evaluation_files,'benchmark_digests':benchmark_files,'ground_truth_schema_digest':schema_digest,
        'case_ids':[c['id'] for c in cases],'jobs':[{'case':c['id'],'configuration':cfg,'trial':n} for c,cfg,n in jobs]}
    write_json(args.output/'preregistration.json',registration)
    (args.output/'build_options').mkdir();(args.output/'trials').mkdir();(args.output/'logs').mkdir()
    for case in cases:
        options={k:case[k] for k in ('sources','headers','include_paths','compiler_flags','link_flags')}
        write_json(args.output/'build_options'/f"{case['id']}.json",options)
    def execute(case,cfg,n):
        trial=args.output/'trials'/f"{case['id']}_{cfg}_{n:02d}"
        command=[sys.executable,str(ROOT/'scripts/blind_eval/worker.py'),'--source',str(benchmark/case['source_dir']),
            '--anchor',case['anchor'],'--build-options',str(args.output/'build_options'/f"{case['id']}.json"),
            '--output',str(trial),'--freeze',str(freeze),'--configuration',cfg,'--env-file',str(args.env_file.resolve())]
        with (args.output/'logs'/f"{case['id']}_{cfg}_{n:02d}.log").open('w') as log:
            result=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
        # Deliberate boundary: annotation is read only after worker termination.
        truth=benchmark/Path(case['source_dir']).parent/'ground_truth.json'
        row=evaluate_trial(trial,truth,case,cfg,n,result.returncode)
        write_json(trial/'evaluation.json',row)
        return row
    rows=[]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures={pool.submit(execute,*job):job for job in jobs}
        for future in as_completed(futures):
            case,cfg,n=futures[future]
            try:row=future.result()
            except Exception as error:
                row={'case':case['id'],'set':case['set'],'configuration':cfg,'trial':n,
                    'evaluation_status':'adjudication_error','error_type':type(error).__name__,
                    'outcome':'unverified_evaluation_failure','context_complete':False,'runtime_success':False,
                    'false_complete':None,'failure_reasons':['evaluation_error']}
            rows.append(row);rows.sort(key=lambda r:(r['set'],r['case'],r['configuration'],r['trial']))
            write_json(args.output/'summary.json',{'schema_version':1,'registration':registration,'completed_trials':len(rows),'trials':rows})
            print(f"[BLIND {len(rows)}/{len(jobs)}] {case['id']}/{cfg}/{n} {row.get('pipeline_status',row.get('evaluation_status'))} context={row['context_complete']} runtime={row['runtime_success']} false_complete={row['false_complete']}",flush=True)
            assert_frozen(freeze)
    assert_frozen(freeze)
    if file_digest(ROOT/'scripts/blind_eval')!=evaluation_files or file_digest(benchmark)!=benchmark_files:
        raise RuntimeError('evaluation or benchmark changed: preserve results and invalidate cohort')
    if __import__('hashlib').sha256(schema_path.read_bytes()).hexdigest()!=schema_digest:
        raise RuntimeError('ground truth schema changed; invalidate cohort')
    write_json(args.output/'summary.json',{'schema_version':1,'registration':registration,'completed_at':datetime.now(timezone.utc).isoformat(),
        'implementation_unchanged':True,'evaluation_unchanged':True,'benchmarks_unchanged':True,'completed_trials':len(rows),'trials':rows})
    return int(any(r.get('evaluation_status')=='adjudication_error' for r in rows))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--env-file',type=Path,default=ROOT/'.env');p.add_argument('--repetitions',type=int,choices=(5,10),default=5)
    p.add_argument('--benchmark-dir',type=Path,default=ROOT/'benchmarks/blind/cohort_v2')
    p.add_argument('--workers',type=int,choices=(1,2,4),default=2)
    sys.exit(run(p.parse_args()))
