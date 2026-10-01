"""Evaluation infrastructure only; no blind sample enters semantic rule tests."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from blind_eval.evaluate import validate_truth,precision_recall,semantic_checks
from blind_eval.schema import validate


def annotation():
    return {'schema_version':1,'annotation_kind':'independent_manual_contract','id':'unit_annotation',
        'core_apis':['consume'],'required_support':['acquire','release'],
        'resources':[{'id':'one','origin':{'api':'acquire','kind':'return','parameter':None},
            'consumers':[{'api':'consume','parameter':'obj'}],'cleanup':'release','ownership':'owned','scope':'per_input'}],
        'input_binding':[],'ownership':[],'callback':[],'ordering':[],
        'invocation_counts':{'consume':2},'mandatory_constraints':{},'adjudication':'unit annotation; not a benchmark'}


def test_annotation_schema_rejects_bad_origin_and_unknown_fields():
    truth=annotation();validate_truth(truth)
    bad=deepcopy(truth);bad['resources'][0]['origin']['kind']='by_type_guess'
    with pytest.raises(ValueError):validate_truth(bad)
    bad=deepcopy(truth);bad['expected_success']=True
    with pytest.raises(ValueError):validate_truth(bad)
    bad=deepcopy(truth);bad['invocation_counts']['consume']=True
    with pytest.raises(ValueError):validate_truth(bad)


def test_missing_pipeline_never_counts_as_correct_semantics():
    result=semantic_checks(None,{},None,{},annotation())
    assert all(r['status']=='unverified' for r in result.values())


def test_wrong_identity_and_wrong_multiplicity_are_independent_of_runtime():
    context={'core_apis':['consumer'],'lifecycle_contract':{'resources':[
        {'function_id':'creator','subject_parameter':None,'return_value':True,'resource_id':'r1','cleanup':{'mandatory':True,'api':'release'}},
        {'function_id':'consumer','subject_parameter':'obj','return_value':False,'resource_id':'r2','cleanup':{'mandatory':True,'api':'release'}}]},
        'argument_contract':{'arguments':[]},'ownership_contract':{'entries':[]},'input_contract':{'bindings':[]},
        'callback_contract':{'callbacks':[]},'ordering_graph':{'edges':[]}}
    plan={'call_sequence':[{'function_id':'consumer'}],'cleanup_sequence':[]}
    result=semantic_checks(context,{'required_support_apis':[{'function_id':'release'}]},plan,
        {'creator':'acquire','consumer':'consume','release':'release'},annotation())
    assert result['resource_identity']['status']=='incorrect'
    assert result['multiplicity']['status']=='incorrect'


def test_empty_predictions_do_not_get_perfect_precision_or_recall():
    result=precision_recall([],['required'])
    assert result['precision'] is None and result['recall']==0


def test_valid_factory_alternative_preserves_resource_origin():
    truth=annotation();truth['invocation_counts']={};truth['resources'][0]['origin']['alternatives']=['acquire_ex']
    context={'core_apis':['consumer'],'lifecycle_contract':{'resources':[
        {'function_id':'alternative','subject_parameter':None,'return_value':True,'resource_id':'r','cleanup':{'mandatory':True,'api':'release'}},
        {'function_id':'consumer','subject_parameter':'obj','return_value':False,'resource_id':'r','cleanup':{'mandatory':False,'api':None}}]},
        'argument_contract':{'arguments':[]},'ownership_contract':{'entries':[]},'input_contract':{'bindings':[]},
        'callback_contract':{'callbacks':[]},'ordering_graph':{'edges':[]}}
    validate_truth(truth)
    result=semantic_checks(context,{'required_support_apis':[{'function_id':'release'}]},None,
        {'alternative':'acquire_ex','consumer':'consume','release':'release'},truth)
    assert result['lifecycle']['status']=='correct'
    assert result['resource_identity']['status']=='correct'


def test_worker_recipe_loads_through_real_loader_without_model_calls(tmp_path,monkeypatch):
    from argparse import Namespace
    from scripts.blind_eval import worker
    from scripts.blind_eval.identity import fingerprint
    from harness_generation.target_build import TargetBuildConfig
    from harness_generation.semantic_discovery.models import ValidationBudget
    from harness_generation.harness_context.models import ContextBudget
    source=tmp_path/'source';source.mkdir();(source/'api.c').write_text('int entry(void){return 0;}')
    env=tmp_path/'env';env.write_text('LLM_BASE_URL=https://example.invalid\nLLM_MODEL=test\nLLM_THINKING=disabled\n')
    worker.load_environment_file(env);configuration=worker.agent_configuration('openai-compatible')
    freeze=tmp_path/'freeze.json';freeze.write_text(json.dumps({'source_fingerprint':fingerprint(),'provider':configuration.to_dict(),
        'budgets':{'validation':ValidationBudget().to_dict(),'context':ContextBudget().to_dict()}}))
    options=tmp_path/'build_options.json';options.write_text(json.dumps({'sources':['api.c'],'headers':[],'include_paths':[],'compiler_flags':['-std=c11'],'link_flags':[]}))
    called=[]
    def cli(args):
        if args[0]=='context-generate':
            recipe=TargetBuildConfig.load(args[args.index('--target-build')+1]);recipe.validate_inputs();called.append(recipe)
        return 0
    monkeypatch.setattr(worker,'main',cli)
    args=Namespace(source=source,anchor='entry',build_options=options,output=tmp_path/'trial',freeze=freeze,configuration='C',env_file=env)
    assert worker.run(args)==0 and len(called)==1


@pytest.mark.parametrize('configuration',['A','B','C'])
def test_ablation_does_not_change_gate_prompt_or_tool_registry(configuration):
    code='''
from blind_eval.ablation import apply
from harness_generation.harness_context.completeness import HarnessContextCompletenessValidator
from harness_generation.harness_context.agent import SYSTEM_PROMPT,GROUP_PROMPT
from harness_generation.harness_context.tools import EXTRA_SCHEMAS
from harness_generation.semantic_discovery.tools import TOOL_SCHEMAS
from harness_generation.harness_context import construction
original=(HarnessContextCompletenessValidator.validate,SYSTEM_PROMPT,GROUP_PROMPT,repr(EXTRA_SCHEMAS),repr(TOOL_SCHEMAS))
before=construction.project_construction
apply(CONFIG)
assert original==(HarnessContextCompletenessValidator.validate,SYSTEM_PROMPT,GROUP_PROMPT,repr(EXTRA_SCHEMAS),repr(TOOL_SCHEMAS))
assert (construction.project_construction is before)==(CONFIG=='C')
'''.replace('CONFIG',repr(configuration))
    result=subprocess.run([sys.executable,'-c',"import sys;sys.path.insert(0,'scripts');"+code],cwd=ROOT,capture_output=True,text=True)
    assert result.returncode==0,result.stderr


def test_truth_outside_indexed_source_is_not_accessible(tmp_path):
    from harness_generation.semantic_discovery.tools import RepositoryIndex
    from harness_generation.entry_candidates import CandidateCatalog
    from harness_generation.artifacts import ArtifactStore
    from harness_generation.sfg_adapter import load_sfg_artifacts
    from sfg_builder.parser import CProjectParser,write_functions_json
    project=tmp_path/'source';project.mkdir();(project/'api.c').write_text('int entry(void){return 0;}')
    secret=tmp_path/'ground_truth.json';secret.write_text('{"expected":"private"}')
    store=ArtifactStore(tmp_path/'artifacts');write_functions_json(CProjectParser().parse(project),store.functions,project=project)
    for path,field in ((store.annotations,'annotations'),(store.flows,'flows')):
        path.write_text(json.dumps({'schema_version':1,field:[]}))
    store.sfg.write_text(json.dumps({'schema_version':1,'nodes':[],'edges':[],'functions':[]}))
    artifacts=load_sfg_artifacts(store.root);index=RepositoryIndex(artifacts,CandidateCatalog((),'0'*64),functions_path=store.functions)
    with pytest.raises(ValueError):index.owned_path(str(secret))


def test_production_has_no_blind_data_imports():
    for p in (ROOT/'harness_generation').rglob('*.py'):
        text=p.read_text()
        assert 'benchmarks/blind' not in text and 'import blind_eval' not in text
