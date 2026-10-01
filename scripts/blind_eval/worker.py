"""Native pipeline worker: source/build inputs only, no truth/expected metadata.

Ground truth is exclusively read by the supervisor AFTER this process exits.
This file does not import any benchmark generator or development fixture.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from blind_eval.ablation import apply
from blind_eval.identity import assert_frozen
from harness_generation.artifacts import ArtifactStore
from harness_generation.cli import main
from harness_generation.records import write_json
from harness_generation.semantic_discovery.provider_config import load_environment_file,agent_configuration
from harness_generation.semantic_discovery.models import ValidationBudget
from harness_generation.harness_context.models import ContextBudget
from harness_generation.sfg_adapter import load_sfg_artifacts
from sfg_builder.parser import CProjectParser,write_functions_json


def run(args):
    start=time.monotonic();assert_frozen(args.freeze);apply(args.configuration)
    load_environment_file(args.env_file);cfg=agent_configuration('openai-compatible')
    frozen=json.loads(args.freeze.read_text());budgets=frozen['budgets']
    if cfg.to_dict()!=frozen['provider']:
        raise ValueError('provider configuration differs from freeze; new cohort required')
    assert ValidationBudget(**budgets['validation']).to_dict()==budgets['validation']
    assert ContextBudget(**budgets['context']).to_dict()==budgets['context']
    args.output.mkdir(parents=True,exist_ok=False)
    project=args.output/'project';shutil.copytree(args.source,project,symlinks=True)
    # Deny annotation payloads in the actual indexed source tree.
    if any(p.suffix=='.json' or 'ground_truth' in p.name or 'expected' in p.name for p in project.rglob('*')):
        raise ValueError('annotation payload in pipeline source tree')
    store=ArtifactStore(args.output/'artifacts')
    row={'schema_version':1,'category':'native_blind_semantic_pipeline','configuration':args.configuration,
         'explicit_anchor':True,'candidate_recall_evaluation':False,'started_at':datetime.now(timezone.utc).isoformat(),
         'production_fingerprint':frozen['source_fingerprint'],'source':str(project),'stage_exits':{},
         'ground_truth_read':False,'resume':False,'retry_failed':False,'status':'not_started','provider':cfg.to_dict()}
    def persist():
        row['elapsed_seconds']=time.monotonic()-start;write_json(args.output/'pipeline.json',row)
    try:
        write_functions_json(CProjectParser().parse(project),store.functions,project=project)
        for path,field in ((store.annotations,'annotations'),(store.flows,'flows')):
            write_json(path,{'schema_version':1,field:[]})
        write_json(store.sfg,{'schema_version':1,'nodes':[],'edges':[],'functions':[]})
        matches=[f for f in load_sfg_artifacts(store.root).functions if f['name']==args.anchor and f.get('defined')]
        if len(matches)!=1:
            row['status']='static_anchor_unavailable';persist();return 1
        anchor=matches[0]['id'];row['anchor']=anchor
        options=json.loads(args.build_options.read_text())
        build={'schema_version':1,'project_root':str(project),'source_files':options['sources'],'header_files':options.get('headers',[]),
               'include_paths':options.get('include_paths',[]),'compiler':'clang','archiver':'ar',
               'compiler_flags':options.get('compiler_flags',['-std=c11']),'archive_name':'libblind_target.a',
               'link_flags':options.get('link_flags',[]),'timeout':30.0}
        build_path=args.output/'target_build.json';write_json(build_path,build)
        base=['--artifacts',str(store.root)]
        provider=['--provider','openai-compatible','--model',cfg.model,'--thinking',cfg.thinking]
        opts=lambda b:[v for k,value in b.items() for v in ('--'+k.replace('_','-'),str(value))]
        stages=[('candidates',[]),('candidate-validate',provider+opts(budgets['validation'])+['--candidate',anchor]),
                ('semantic-slice',provider+opts(budgets['validation'])+['--candidate',anchor]),
                ('minimal-ft',[]),('harness-context',provider+opts(budgets['context'])+['--requirement-mode','grouped'])]
        for command,extra in stages:
            tick=time.monotonic();code=main([command,*base,*extra]);row['stage_exits'][command]=code
            row.setdefault('stage_seconds',{})[command]=time.monotonic()-tick;persist()
            if code:
                row['status']=command+'_failed';persist();return 1
        headers=[v for h in options.get('headers',[]) for v in ('--header',h)]
        tick=time.monotonic();code=main(['context-generate',*base,*provider,*headers,'--target-build',str(build_path),'--build','--runtime'])
        row['stage_exits']['context-generate']=code;row.setdefault('stage_seconds',{})['context-generate']=time.monotonic()-tick
        row['status']='pipeline_completed' if not code else 'generation_failed';persist()
        return code
    except Exception as error:
        row.update(status='pipeline_exception',exception_type=type(error).__name__);persist();return 1
    finally:
        assert_frozen(args.freeze)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--anchor',required=True)
    p.add_argument('--build-options',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--freeze',type=Path,required=True);p.add_argument('--env-file',type=Path,default=ROOT/'.env')
    p.add_argument('--configuration',choices=('A','B','C'),required=True)
    args=p.parse_args();sys.exit(run(args))
