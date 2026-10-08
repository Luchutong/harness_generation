#!/usr/bin/env python3
"""Fixed-evidence gate replay, followed by small fixed-FT native development tests.

Offline producer uses the frozen baseline once. Both gate workers load exactly
the same FT/facts/requirements/resolutions/evidence. Native trials instead mine
fresh Context on the same explicit offline FT; no upstream model, no retry and
no mock fallback. Generation only runs after the actual frozen Context gate.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DIRECT = '#include <stddef.h>\nint parse(const unsigned char *data,size_t size){return size?data[0]:0;}\n'
SHARED = '''#include <stdlib.h>
#include <stddef.h>
typedef struct Context {const unsigned char *data;size_t size;} Context;
Context *create(void){return calloc(1,sizeof(Context));}
void destroy(Context *ctx){free(ctx);}
void feed(Context *ctx,const unsigned char *data,size_t size){ctx->data=data;ctx->size=size;}
int parse(Context *ctx){return ctx->size?ctx->data[0]:0;}
void usage(const unsigned char *data,size_t size){Context *ctx=create();feed(ctx,data,size);parse(ctx);destroy(ctx);}
'''
OWNED = '''#include <stdlib.h>
#include <stddef.h>
typedef struct Node {unsigned value;} Node;
Node *parse(const unsigned char *data,size_t size){Node *p=malloc(sizeof(Node));if(p)p->value=size?data[0]:0;return p;}
void node_free(Node *p){free(p);}
'''
GUARD = '''#include <stdlib.h>
#include <stddef.h>
typedef struct Context {unsigned ready;unsigned other;} Context;
Context *create(void){return calloc(1,sizeof(Context));}
void destroy(Context *ctx){free(ctx);}
void prime(Context *ctx){BODY}
int parse(Context *ctx,const unsigned char *data,size_t size){if(ctx->ready!=1)__builtin_trap();return size?data[0]^ctx->other:ctx->other;}
void usage(const unsigned char *data,size_t size){Context *ctx=create();prime(ctx);parse(ctx,data,size);destroy(ctx);}
'''
NEGATIVES = {
    'wrong_field': 'ctx->other=1;',
    'conditional_write': 'if(ctx->other)ctx->ready=1;ctx->other=0;',
    'wrong_object': 'Context other={0};other.ready=1;ctx->other=0;',
}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def hashes(root):
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
        for folder in ('harness_generation','sfg_builder') for p in sorted((root/folder).rglob('*.py'))}


def imports(root):
    sys.path[:0]=[str(root),str(root/'tests')]


def prepare(args):
    from test_harness_context import setup,mine,context_specs,argument,owner,order
    from harness_generation.harness_context.models import resource_id
    (args.output/'fixture').mkdir(parents=True,exist_ok=True)
    source=GUARD.replace('BODY',NEGATIVES.get(args.case,'ctx->ready=1;ctx->other=0;'))
    roles={'parse':('core','accepted_anchor'),'create':('support','resource_creation'),
        'destroy':('support','resource_cleanup'),'prime':('support','required_initialization'),'usage':('exclude','diagnostic_only')}
    if args.case=='retained_buffer':
        from test_context_semantics import shared_ready
        prepared,run,_=shared_ready(args.output/'fixture')
    elif args.case=='cleanup_wrong_object':
        source=OWNED.replace('void node_free(Node *p){free(p);}', 'static Node *saved;\nvoid node_free(Node *p){p=saved;free(p);}')
        prepared=setup(args.output/'fixture',source)
        from test_harness_context import direct_specs,lifecycle_value
        ids=prepared[0][-1];fid=ids['parse'];cleanup=ids['node_free'];rid=resource_id(fid)
        specs=direct_specs(fid)
        specs[fid,'return_semantics']['value']=dict(success='nonnull',nullable=True,owned=True,error_cleanup=False)
        specs[fid,'ownership']['value']['entries'].append(owner(returned=True,ownership='owned',release=cleanup,resource=rid))
        specs[fid,'lifecycle']={'value':lifecycle_value(fid,rid,'Node',None,fid,cleanup),
            'dependencies':[dict(function_id=cleanup,necessity='required',reason='cleanup')]}
        specs[fid,'call_order']={'value':{'constraints':[order(fid,cleanup)]}}
        specs[cleanup,'argument_construction']={'value':{'arguments':[argument('p','derived')]}}
        specs[cleanup,'ownership']={'value':{'entries':[owner('p',ownership='transferred')]}}
        run,_=mine(prepared,specs,query_type='Node',persist=True)
    elif args.case=='direct':
        from test_harness_context import direct_specs
        prepared=setup(args.output/'fixture',DIRECT)
        run,_=mine(prepared,direct_specs(prepared[0][-1]['parse']),persist=True)
    else:
        prepared=setup(args.output/'fixture',source,roles=roles,discover_callers=True)
        ids=prepared[0][-1];fid=ids['parse'];prime=ids['prime'];specs=context_specs(ids)
        specs[fid,'state']['value']['preconditions'][0]['api']=prime
        specs[fid,'lifecycle']['value']['resources'][0]['initialization']=dict(api=prime,mandatory=True)
        specs[fid,'lifecycle']['dependencies'].append(dict(function_id=prime,necessity='required',reason='initialization'))
        specs[fid,'call_order']['value']['constraints'].append(order(prime,fid))
        specs[prime,'argument_construction']={'value':{'arguments':[argument('ctx','derived')]}}
        specs[prime,'ownership']={'value':{'entries':[owner('ctx')]}}
        specs[prime,'support_decision']={'value':dict(decision='required',reason='initialization',required_by=[fid]),
            'dependencies':[dict(function_id=prime,necessity='required',reason='initialization',required_by=fid)]}
        req=next(r for r in __import__('harness_generation.harness_context',fromlist=['HarnessRequirementBuilder']).HarnessRequirementBuilder().build(prepared[1],prepared[3])['requirements'])
        prepared[5].activate(req);prepared[5].execute('find_resource_flows',{'function':fid})
        run,_=mine(prepared,specs,query_type='Context',persist=True)
    from harness_generation.harness_context.persistence import context_directory
    directory=context_directory(prepared[0][0],prepared[1]['ft_id'])
    result={'case':args.case,'expected_allowed':args.case in {'direct','correct_initializer'},
        'artifact_root':str(prepared[0][0].root),'minimal_ft':prepared[1],
        'requirements':run.requirements['requirements'], 'facts':run.context['facts'],
        'resolutions':json.loads((directory/'resolutions.json').read_text())['resolutions'],
        'evidence':prepared[4].evidence,'discoveries':prepared[4].discoveries,
        'budget':prepared[4].budget.to_dict(),'producer_status':run.completeness['status']}
    write(args.output/'fixed_inputs.json',result)
    return 0


def replay(args):
    from harness_generation.sfg_adapter import load_sfg_artifacts
    from harness_generation.minimal_ft import ProjectSnapshot
    from harness_generation.harness_context import MiningState,ContextBudget,HarnessContextCompletenessValidator
    from harness_generation.harness_context.evidence import build_context
    from harness_generation.harness_context.api_closure import build_api_closure
    from harness_generation.harness_context.completeness import missing_requirement_tasks
    from harness_generation.semantic_discovery.models import digest
    data=json.loads(args.inputs.read_text());input_digest=digest({k:data[k] for k in ('minimal_ft','requirements','facts','resolutions','evidence','discoveries')})
    snapshot=ProjectSnapshot.from_artifacts(load_sfg_artifacts(Path(data['artifact_root'])))
    state=MiningState(ContextBudget(**data['budget']));state.evidence=data['evidence'];state.discoveries=data['discoveries']
    ft,rows,resolutions=data['minimal_ft'],data['requirements'],data['resolutions']
    closure=build_api_closure(ft,rows,resolutions,snapshot,state)
    context=build_context(ft,rows,data['facts'],snapshot,state.evidence);context['dependencies']=closure['unresolved_api_dependencies']
    report=HarnessContextCompletenessValidator().validate(context,closure,ft,snapshot,rows,resolutions,state)
    tasks=missing_requirement_tasks(report)
    row={'case':data['case'],'arm':args.arm,'expected_allowed':data['expected_allowed'],'allowed':report['generation_allowed'],
        'status':report['status'],'false_allow':report['generation_allowed'] and not data['expected_allowed'],
        'false_block':not report['generation_allowed'] and data['expected_allowed'],'followup_tasks':len(tasks),
        'input_digest':input_digest,'input_file_sha256':hashlib.sha256(args.inputs.read_bytes()).hexdigest(),
        'hard_codes':sorted({r['code'] for r in report['hard_missing']}),'validation_errors':report['validation_errors']}
    write(args.output/'report.json',report);write(args.output/'trial.json',row)
    print(json.dumps(row,ensure_ascii=False),flush=True)
    return 0


def native(args):
    from test_harness_context import setup
    from harness_generation.harness_context import MiningState,ContextBudget,HarnessContextMiningLoop
    from harness_generation.harness_context.persistence import run_configuration
    from harness_generation.semantic_discovery.provider_config import load_environment_file,agent_configuration,native_agent_model
    from harness_generation.semantic_discovery.models import digest
    (args.output/'fixture').mkdir(parents=True,exist_ok=True)
    source={'direct':DIRECT,'shared':SHARED,'owned':OWNED}[args.case]
    roles=None
    if args.case=='shared':
        roles={'parse':('core','accepted_anchor'),'feed':('core','external_input_injection'),
            'create':('support','resource_creation'),'destroy':('support','resource_cleanup'),'usage':('exclude','diagnostic_only')}
    budget=ContextBudget();prepared=setup(args.output/'fixture',source,budget=budget,roles=roles,discover_callers=args.case=='shared')
    store,ft,metadata,snapshot,state,tools=prepared[0][0],prepared[1],prepared[2],prepared[3],prepared[4],prepared[5]
    load_environment_file(args.env_file);config=agent_configuration('openai-compatible');model=native_agent_model(config)
    configuration=run_configuration(ft,metadata,snapshot,budget,model,requirement_mode='grouped')
    run=HarnessContextMiningLoop(model,state,group_requirements=True).run(ft,snapshot,tools,store=store,configuration=configuration)
    row={'arm':args.arm,'case':args.case,'repeat':args.repeat,'context_status':run.completeness['status'],
        'context_complete':run.completeness['generation_allowed'],'hard_gaps':len(run.completeness['hard_missing']),
        'metrics':run.metadata['metrics'],'minimal_ft_digest':digest(ft),'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
        'budget':budget.to_dict(),'model':config.to_dict(),'blind_experiment':False,'upstream_preparation':'explicit_offline_ft',
        'model_calls':state.model_calls,'tool_calls':state.tool_calls,'tokens':state.tokens,
        'execution_failures':run.metadata.get('execution_failures',[]),'provider_errors':[],
        'compile_success':False,'runtime_success':False,
        'native_responses':0,'repeated_model_queries':0,'model_query_count':0,'compile_runtime_attempted':False}
    seen=set()
    for p in sorted((store.root/'harness_contexts').glob('*/agent_runs/*/attempt_*/trace.json')):
        meta=json.loads(p.with_name('metadata.json').read_text())
        if not meta.get('group_cost_owner',True):continue
        trace=json.loads(p.read_text())
        row['native_responses']+=sum(e['kind']=='model_response' for e in trace['events'])
        row['provider_errors'] += [e for e in trace['events'] if e['kind']=='model_error']
        for e in trace['events']:
            if e['kind']!='tool_call':continue
            key=json.dumps([e.get('tool'),e.get('arguments')],sort_keys=True)
            if e.get('round',0)>0:
                row['model_query_count']+=1;row['repeated_model_queries']+=key in seen
            seen.add(key)
    write(args.output/'trial.json',row)
    if row['context_complete']:
        from harness_generation.context_generation.cli import main
        row['compile_runtime_attempted']=True
        status=main(['--artifacts',str(store.root),'--provider','openai-compatible','--model',config.model,
            '--thinking',config.thinking,'--env-file',str(args.env_file),'--build','--runtime'])
        row['generation_exit']=status
        marker=next((store.root/'context_generations').glob('*/*/*/metadata.json'),None)
        if marker:
            row['generation_metadata']=json.loads(marker.read_text())
            response=marker.parent/'response.json'
            if response.exists():row['generation_response_usage']=json.loads(response.read_text()).get('usage',{})
            for kind in ('build','runtime'):
                p=marker.parent/'build'/(kind+'.json')
                if p.exists():
                    result=json.loads(p.read_text());row[kind+'_success']=result.get('status')=='passed'
                    if kind=='build':row['compile_success']=row['build_success']
                    row[kind+'_status']=result.get('status')
    write(args.output/'trial.json',row)
    print(json.dumps({k:row[k] for k in ('arm','case','repeat','context_status','native_responses','model_calls','tool_calls','compile_success','runtime_success')},ensure_ascii=False),flush=True)
    return 0


def coordinate(args):
    roots={'baseline':args.baseline.resolve(),'revision':args.revision.resolve()};frozen={a:hashes(r) for a,r in roots.items()}
    args.output.mkdir(parents=True,exist_ok=False)
    frozen_runner=args.output/'runner_frozen.py'
    frozen_runner.write_bytes(Path(__file__).read_bytes())
    cases=['direct','correct_initializer',*NEGATIVES,'retained_buffer','cleanup_wrong_object'] if args.phase=='offline' else ['direct','shared','owned']
    schedule=[{'case':c,'repeat':i,'arm':a} for c in cases for i in range(1,(1 if args.phase=='offline' else args.repetitions)+1)
        for a in (('baseline','revision') if i%2 else ('revision','baseline'))]
    write(args.output/'registration.json',{'phase':args.phase,'blind_experiment':False,'cases':cases,'schedule':schedule,
        'source_hashes':frozen,'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'same_budget':True,'retries':False,'mock_fallback':False,
        'code_generation_budget':{'model_calls':1,'max_tokens':8192},
        'fixed_inputs_root':str(args.fixed_inputs_root.resolve()) if args.fixed_inputs_root else None})
    rows=[]
    for c in cases if args.phase=='offline' and not args.fixed_inputs_root else []:
        target=args.output/'fixed'/c;target.mkdir(parents=True)
        with (target/'prepare.log').open('w') as log:
            p=subprocess.run([sys.executable,str(frozen_runner),'--worker','prepare','--implementation',str(roots['baseline']),
                '--case',c,'--output',str(target)],stdout=log,stderr=subprocess.STDOUT)
        if p.returncode:raise RuntimeError('offline producer failed: '+c)
    for n,t in enumerate(schedule,1):
        assert all(hashes(r)==frozen[a] for a,r in roots.items()),'frozen source changed'
        target=args.output/(str(n).zfill(2)+'_'+t['case']+'_'+t['arm']+'_'+str(t['repeat']));target.mkdir()
        command=[sys.executable,str(frozen_runner),'--worker','replay' if args.phase=='offline' else 'native',
            '--implementation',str(roots[t['arm']]),'--arm',t['arm'],'--case',t['case'],'--repeat',str(t['repeat']),
            '--output',str(target),'--env-file',str(args.env_file.resolve())]
        if args.phase=='offline':command+=['--inputs',str((args.fixed_inputs_root.resolve() if args.fixed_inputs_root else args.output/'fixed')/t['case']/'fixed_inputs.json')]
        with (target/'worker.log').open('w') as log:result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
        row=json.loads((target/'trial.json').read_text()) if (target/'trial.json').exists() else {**t,'worker_error':True,'worker_exit':result.returncode}
        rows.append(row);write(args.output/'summary.json',{'phase':args.phase,'completed':len(rows)==len(schedule),'trials':rows})
        print(json.dumps({k:v for k,v in row.items() if k not in {'generation_metadata','model','metrics'}},ensure_ascii=False),flush=True)
        if args.phase=='native' and any(code in str(row.get('provider_errors',[])) for code in ('401','403')):
            write(args.output/'stop.json',{'reason':'provider_authentication_failure','trial':n});return 1
    return 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--worker',choices=('prepare','replay','native'));p.add_argument('--phase',choices=('offline','native'))
    p.add_argument('--implementation',type=Path);p.add_argument('--baseline',type=Path);p.add_argument('--revision',type=Path)
    p.add_argument('--arm');p.add_argument('--case');p.add_argument('--repeat',type=int,default=1);p.add_argument('--repetitions',type=int,default=2)
    p.add_argument('--inputs',type=Path);p.add_argument('--env-file',type=Path,default=ROOT/'.env');p.add_argument('--output',type=Path,required=True)
    p.add_argument('--fixed-inputs-root',type=Path,help='Reuse already frozen offline producer inputs without rerunning mining')
    args=p.parse_args();args.output=args.output.resolve()
    if args.worker:
        imports(args.implementation.resolve());return {'prepare':prepare,'replay':replay,'native':native}[args.worker](args)
    return coordinate(args)


if __name__=='__main__':raise SystemExit(main())
