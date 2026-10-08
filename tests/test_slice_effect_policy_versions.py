"""Upstream effect projection/interpreter versions are independently mandatory."""
from copy import deepcopy
import json
import pytest
from harness_generation.records import write_json
from harness_generation.semantic_discovery.models import digest
from harness_generation.semantic_slicing.persistence import (
 effect_question_policy_versions,load_compatible_slice,run_configuration,save_run)
from harness_generation.semantic_slicing.effect_questions import VERSION as QUESTION_VERSION
from harness_generation.harness_context.proof_grounding import VERSION as INTERPRETER_VERSION
from harness_generation.minimal_ft.persistence import load_slice_input
from test_semantic_slicing import DIRECT,fixture,queries,run,terminal,tool
from test_minimal_ft import prepare,build


def published(tmp_path):
 sample=fixture(tmp_path,DIRECT)
 fid=sample[3].function_id
 result,model,tools=run(sample,[queries(tool('get_function','source',function=fid)),terminal({fid:('core','accepted_anchor')})])
 configuration=run_configuration(sample[2],tools.frontier,tools.budget,model,32)
 save_run(sample[0],result,configuration)
 return sample,result,tools,configuration


def test_slice_configuration_independently_names_question_and_source_interpreter_versions(tmp_path):
 sample,result,tools,configuration=published(tmp_path)
 assert effect_question_policy_versions()=={'effect_question_version':QUESTION_VERSION,
  'effect_question_source_interpreter_version':INTERPRETER_VERSION}
 for key,value in effect_question_policy_versions().items():assert configuration[key]==value
 assert load_compatible_slice(sample[0],tools.frontier,configuration,tools.index,tools.budget)==result.result


@pytest.mark.parametrize('key',['effect_question_version','effect_question_source_interpreter_version'])
@pytest.mark.parametrize('damage',['missing','stale'])
def test_consistently_rehashed_stale_metadata_cannot_be_resumed_even_if_caller_passes_it(tmp_path,key,damage):
 sample,result,tools,configuration=published(tmp_path)
 stale=deepcopy(configuration)
 if damage=='missing':del stale[key]
 else:stale[key]='retained-prior-version'
 path=sample[0].semantic_slice_run(result.result['candidate_id'])/'metadata.json'
 marker=json.loads(path.read_text())
 marker['configuration']=stale;marker['configuration_fingerprint']=digest(stale)
 write_json(path,marker)
 before=path.read_bytes()
 assert load_compatible_slice(sample[0],tools.frontier,stale,tools.index,tools.budget) is None
 assert load_compatible_slice(sample[0],tools.frontier,configuration,tools.index,tools.budget) is None
 assert path.read_bytes()==before


@pytest.mark.parametrize('key',['effect_question_version','effect_question_source_interpreter_version'])
@pytest.mark.parametrize('damage',['missing','stale'])
def test_minimal_ft_rejects_consistently_rehashed_unsupported_upstream_question_policy(tmp_path,key,damage):
 sample=prepare(tmp_path,source=DIRECT)
 assert build(sample).valid
 store,cid,_=sample
 path=store.semantic_slice_run(cid)/'metadata.json'
 marker=json.loads(path.read_text())
 if damage=='missing':del marker['configuration'][key]
 else:marker['configuration'][key]='retained-prior-version'
 marker['configuration_fingerprint']=digest(marker['configuration']);write_json(path,marker)
 before=path.read_bytes()
 source=load_slice_input(store,cid)
 errors=[e for e in source.load_errors if e['code']=='slice_effect_question_policy_mismatch']
 assert [e['field'] for e in errors]==['metadata.configuration.'+key]
 result=build(sample)
 assert not result.valid
 assert any(e['code']=='slice_effect_question_policy_mismatch' for e in result.minimal_ft['validation_errors'])
 assert path.read_bytes()==before
