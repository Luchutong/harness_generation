#!/usr/bin/env python3
"""Fixed-budget fresh native development trials, with bounded repetitions."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from smoke_context_pipeline import evaluate
from harness_generation.semantic_discovery.provider_config import load_environment_file,agent_configuration
from harness_generation.harness_context.models import ContextBudget, PROMPT_VERSION
from harness_generation.harness_context.argument_graph import VERSION, DEPENDENCY_VERSION
from harness_generation.harness_context.reconciliation import VERSION as RECONCILER_VERSION, RECIPE_VERSION
from scripts.blind_eval.identity import fingerprint
from harness_generation.harness_context.invocations import VERSION as INVOCATION_VERSION
from harness_generation.harness_context.value_roles import VERSION as VALUE_VERSION
from harness_generation.harness_context.parameter_semantics import VERSION as SEMANTIC_VERSION
from harness_generation.harness_context.input_flow import VERSION as INPUT_FLOW_VERSION
from harness_generation.harness_context.proposals import VERSION as PROPOSAL_VERSION
from harness_generation.semantic_slicing.core_proofs import VERSION as CORE_PROOF_VERSION
from harness_generation.harness_context.terminal import VERSION as TERMINAL_VERSION
from harness_generation.semantic_discovery.models import ValidationBudget


def runtime_fingerprint():
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((ROOT/'scripts').rglob('*.py'))}


CASES={
    'bounded_scalar':'''#include <stdlib.h>
#include <stddef.h>
int parse(const unsigned char *src,size_t cb) { if(cb>4096) abort(); return cb ? src[cb-1] : 0; }
void usage(const unsigned char *raw,size_t extent) { size_t prefix=extent<4096?extent:4096; parse(raw,prefix); }
''',
    'creator_with_args':'''#include <stdlib.h>
#include <stddef.h>
typedef struct Options { unsigned flags; } Options;
typedef struct Policy { unsigned mode; } Policy;
typedef struct State { unsigned mode; } State;
State *acquire(const Options *o,const Policy *p) { State *s=calloc(1,sizeof(State)); if(s) s->mode=o->flags+p->mode; return s; }
void dispose(State *s) { free(s); }
int parse(State *s,const unsigned char *src,size_t cb) { return cb ? src[0] ^ s->mode : s->mode; }
void usage(const unsigned char *raw,size_t extent) { Options o={0}; Policy p={0}; State *s=acquire(&o,&p); parse(s,raw,extent); dispose(s); }
''',
    'out_parameter':'''#include <stdlib.h>
#include <stddef.h>
typedef struct Options { unsigned mode; } Options;
typedef struct State { unsigned mode; } State;
int acquire(State **out,const Options *o) { (void)o; *out=calloc(1,sizeof(State)); return *out != NULL; }
void dispose(State *s) { free(s); }
int parse(State *s,const unsigned char *src,size_t cb) { return cb ? src[0] ^ s->mode : s->mode; }
void usage(const unsigned char *raw,size_t extent) { Options o={0}; State *s; acquire(&s,&o); parse(s,raw,extent); dispose(s); }
''',
    'shared_context':'''#include <stdlib.h>
#include <stddef.h>
typedef struct State { const unsigned char *bytes; size_t count; } State;
State *acquire(void) { return calloc(1,sizeof(State)); }
void dispose(State *s) { free(s); }
void supply(State *s,const unsigned char *src,size_t cb) { s->bytes=src; s->count=cb; }
int parse(State *s) { return s->count ? s->bytes[0] : 0; }
void usage(const unsigned char *raw,size_t extent) { State *a=acquire(); State *b=a; supply(b,raw,extent); parse(a); dispose(b); }
''',
    'owned_return':'''#include <stdlib.h>
#include <stddef.h>
typedef struct Result { unsigned value; } Result;
Result *parse(const unsigned char *src,size_t cb) { Result *r=malloc(sizeof(Result)); if(r) r->value=cb ? src[0] : 0; return r; }
void dispose(Result *r) { free(r); }
void observe(Result *r) { r->value ^= 1; }
void usage(const unsigned char *raw,size_t extent) { Result *r=parse(raw,extent); observe(r); dispose(r); }
''',
    'callback_context':'''#include <stdlib.h>
#include <stddef.h>
typedef struct User { unsigned bias; } User;
typedef int (*Handler)(void *user,const unsigned char *src,size_t cb);
User *acquire(unsigned bias) { User *u=malloc(sizeof(User)); if(u) u->bias=bias; return u; }
void dispose(User *u) { free(u); }
int handle(void *user,const unsigned char *src,size_t cb) { User *u=user; return cb ? src[0]^u->bias : u->bias; }
int parse(const unsigned char *src,size_t cb,Handler handler,void *user) { return handler(user,src,cb); }
void usage(const unsigned char *raw,size_t extent) { User *u=acquire(0); parse(raw,extent,handle,u); dispose(u); }
'''}


def collect_graphs(output, completed_roots=None):
    graphs=[]
    for path in output.glob('*_phase1/harness_contexts/*/argument_graph.json'):
        if completed_roots is not None and not any(path.is_relative_to(root) for root in completed_roots):
            continue
        graph=json.loads(path.read_text());root=path.parent
        metadata=json.loads((root/'metadata.json').read_text())
        canonical_path=root/'canonical_construction.json'
        canonical=json.loads(canonical_path.read_text()) if canonical_path.exists() else None
        traces=list(root.glob('agent_runs/*/attempt_*/trace.json'))
        prompts=0; errors=[]
        for trace in traces:
            doc=json.loads(trace.read_text())
            prompts+=sum('"argument_graph"' in m.get('content','') for m in doc['messages'] if isinstance(m.get('content'),str))
            errors.extend(e for e in doc['events'] if e['kind']=='model_error')
        # Group traces repeat request observations; deduplicate for this summary.
        errors={json.dumps(e,sort_keys=True):e for e in errors}
        graphs.append({'artifact':str(path),'ft_id':graph['ft_id'],'graph_version':graph['version'],
            'nodes':len(graph['nodes']),'edges':len(graph['edges']),
            'resolved_parameters':len(graph['dependency_graph']['resolved_parameters']),
            'holes':graph['dependency_graph']['unresolved_parameters'],
            'resource_origins':len(graph['resource_origins']), 'cycles':graph['dependency_graph']['cycles'],
            'graph_visible_in_saved_prompts':prompts>0,'execution_failures':metadata['execution_failures'],
            'provider_errors':list(errors.values()),'context_metrics':metadata['metrics']})
        if canonical:
            graphs[-1]['canonical_artifact']=str(canonical_path)
            graphs[-1]['canonical_parameters']=canonical['parameters']
            graphs[-1]['equivalence_classes']=canonical['equivalence_classes']
            graphs[-1]['reconciliation_diagnostics']=canonical['diagnostics']
        context=json.loads((root/'harness_context.json').read_text())
        closure=json.loads((root/'api_closure.json').read_text())
        active=set(context['core_apis'])|{r['function_id'] for r in closure['required_support_apis']}
        graphs[-1]['canonical_active_parameters']=[r for r in canonical['parameters'] if r['function_id'] in active] if canonical else []
        graphs[-1]['invocation_preconditions']=context.get('invocation_contract',{}).get('preconditions',[])
        graphs[-1]['input_flow_diagnostics']=context.get('external_input_flow',{}).get('diagnostics',[])
    return graphs


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--env-file',type=Path,default=ROOT/'.env')
    parser.add_argument('--workers',type=int,choices=(1,2),default=2)
    parser.add_argument('--case',action='append',choices=tuple(CASES))
    parser.add_argument('--repetitions',type=int,choices=(1,2,3,5),default=1)
    args=parser.parse_args();load_environment_file(args.env_file)
    cfg=agent_configuration('openai-compatible')
    options=argparse.Namespace(provider='openai-compatible',model=cfg.model,thinking=cfg.thinking,
                             validation_budget={},context_budget=ContextBudget().to_dict())
    selected=args.case or list(CASES)
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    frozen=fingerprint()
    runtime_frozen=runtime_fingerprint()
    registration={'category':'targeted_native_development_smoke','blind_generalization_evidence':False,
        'repetitions':args.repetitions,'cases':selected,'provider':cfg.to_dict(),'production_fingerprint':frozen,
        'graph_version':VERSION,'dependency_graph_version':DEPENDENCY_VERSION,'prompt_version':PROMPT_VERSION,
        'reconciler_version':RECONCILER_VERSION,'recipe_version':RECIPE_VERSION,
        'invocation_version':INVOCATION_VERSION,'value_version':VALUE_VERSION,
        'semantic_version':SEMANTIC_VERSION,'input_flow_version':INPUT_FLOW_VERSION,
        'proposal_version':PROPOSAL_VERSION,'core_proof_version':CORE_PROOF_VERSION,'terminal_version':TERMINAL_VERSION,
        'validation_budget':ValidationBudget().to_dict(),'code_max_tokens':8192,
        'runtime_dependencies':runtime_frozen,
        'context_budget':ContextBudget().to_dict(),'workers':args.workers,'resume':False,'failed_retry':False,
        'started_at':datetime.now(timezone.utc).isoformat()}
    def save(rows,complete=False):
        data={'registration':registration,'trials':sorted(rows,key=lambda r:r['case']),
              'graphs':collect_graphs(output,[Path(row['artifacts']) for row in rows if 'artifacts' in row]),
              'completed':complete,'implementation_unchanged':fingerprint()==frozen and runtime_fingerprint()==runtime_frozen}
        (output/'summary.json').write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    (output/'registration.json').write_text(json.dumps(registration,ensure_ascii=False,indent=2)+'\n')
    rows=[]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        jobs={pool.submit(evaluate,output,name if args.repetitions==1 else f'{name}_r{rep:02d}',CASES[name],options):(name,rep)
            for rep in range(1,args.repetitions+1) for name in selected}
        for future in as_completed(jobs):
            name,rep=jobs[future]
            try:
                row=future.result()
            except Exception as error:
                row={'case':name,'status':'smoke_supervisor_error','error_type':type(error).__name__}
            row['api_model']=name;row['repetition']=rep
            rows.append(row);save(rows)
            print('[GRAPH-SMOKE]',name,row.get('status'),flush=True)
            if fingerprint()!=frozen or runtime_fingerprint()!=runtime_frozen:
                raise RuntimeError('implementation changed during smoke')
    save(rows,complete=True)
    print(json.dumps({'completed_trials':len(rows),'graph_artifacts':len(collect_graphs(output))}),flush=True)


if __name__=='__main__':main()
