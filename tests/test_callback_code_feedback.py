"""Bound project callbacks are repaired explicitly under the same FrozenPlan."""
from copy import deepcopy
import json
import re

import pytest

from harness_generation.context_generation.code_repair import translate
from harness_generation.context_generation.stage4 import (ContextStage4Generator, PROMPT_VERSION,
    callback_binding_feedback)
from harness_generation.context_generation.validation import validate_code
from harness_generation.semantic_discovery.models import digest
from test_callback_boundaries import callback_plan, CODE
from test_frozen_plan_code_repair import ScriptedCodeLLM


@pytest.fixture(scope="module")
def bound_plan(tmp_path_factory):
    _, plan = callback_plan(tmp_path_factory.mktemp("bound_callback_feedback"))
    return plan


def wrapper_code():
    return CODE.replace('extern "C" int parse(',
        'static int dispatch_wrapper(void *user,const unsigned char *src,size_t cb) { return handle(user,src,cb); }\n'
        'extern "C" int parse(').replace('parse(data,size,handle,u)', 'parse(data,size,dispatch_wrapper,u)')


def freeze(plan):
    plan['plan_id'] = 'plan_' + digest({k:v for k,v in plan.items() if k != 'plan_id'})[:24]
    return plan


@pytest.mark.parametrize('errors', [
    ['canonical_callback_binding_mismatch'], ['project_api_outside_fuzzer_entry'],
    ['canonical_callback_binding_mismatch', 'project_api_outside_fuzzer_entry'],
])
def test_callback_diagnostics_name_exact_dispatch_parameter_and_bound_symbol(bound_plan, errors):
    before = deepcopy(bound_plan)
    diagnostics = {'status':'invalid_code', 'code_validation':{'status':'invalid','errors':errors}}
    prompt = ContextStage4Generator(None).render_repair(bound_plan, wrapper_code(), diagnostics)
    feedback = prompt.parameters['repair_data']['callback_binding_feedback']
    row, = feedback['bindings']
    dispatch = next(c for c in bound_plan['call_sequence'] if c['symbol'] == 'parse')
    producer = next(d for d in bound_plan['api_declarations'] if d['symbol'] == 'handle')
    assert row['callee_function_id'] == dispatch['function_id'] and row['callee_symbol'] == 'parse'
    assert row['argument_index'] == 2 and row['argument_index_base'] == 0 and row['parameter'] == 'handler'
    assert row['expected_producer_api'] == producer['function_id']
    assert row['expected_producer_symbol'] == producer['symbol']
    assert row['expected_producer_signature'] == producer['signature']
    assert row['callback_via_function_id'] == dispatch['function_id']
    assert 'LLVMFuzzerTestOneInput' in row['binding_scope']
    assert row['helper_wrapper_allowed'] is row['stub_replacement_allowed'] is row['separate_direct_producer_call_allowed'] is False
    assert feedback['plan_id'] == bound_plan['plan_id'] and feedback['plan_digest'] == digest(bound_plan)
    assert prompt.parameters['harness_plan'] == before == bound_plan
    assert diagnostics == prompt.parameters['repair_data']['diagnostics']
    assert prompt.prompt_version == PROMPT_VERSION == 'frozen-plan-code-v14'
    assert 'wrapper that calls the same producer still changes' in prompt.content


def test_feedback_resolves_symbols_from_plan_declarations_without_identifier_guessing(bound_plan):
    plan = deepcopy(bound_plan)
    producer = next(d for d in plan['api_declarations'] if d['symbol'] == 'handle')
    producer['symbol'] = 'project_consumer_exact'
    producer['signature'] = producer['signature'].replace('handle(', 'project_consumer_exact(')
    freeze(plan)
    row, = callback_binding_feedback(plan)
    assert row['expected_producer_symbol'] == 'project_consumer_exact'
    assert row['expected_producer_api'].endswith(':handle')  # The ID is not the source symbol authority.


def test_unbound_callback_or_other_error_does_not_receive_a_guessed_project_binding(bound_plan):
    plan = deepcopy(bound_plan)
    for call in plan['call_sequence']:
        for argument in call['arguments']:
            recipe = argument.get('canonical_recipe') or {}
            if recipe.get('kind') == 'callback_object':
                recipe['producer_api'] = None
    freeze(plan)
    assert callback_binding_feedback(plan) == []
    generator = ContextStage4Generator(None)
    errors = {'code_validation':{'errors':['canonical_callback_binding_mismatch']}}
    assert 'callback_binding_feedback' not in generator.render_repair(plan, CODE, errors).parameters['repair_data']
    unrelated = {'code_validation':{'errors':['required_invocation_count_mismatch']}}
    assert 'callback_binding_feedback' not in generator.render_repair(bound_plan, CODE, unrelated).parameters['repair_data']
    assert 'canonical recipe has no producer_api' in generator.render(plan).content
    assert 'Plan explicitly permits' in generator.render(plan).content


def test_missing_declaration_does_not_turn_a_function_id_into_an_invented_symbol(bound_plan):
    plan = deepcopy(bound_plan)
    plan['api_declarations'] = [d for d in plan['api_declarations'] if d['symbol'] != 'handle']
    row, = callback_binding_feedback(plan)
    assert row['expected_producer_symbol'] is None and row['expected_producer_signature'] is None
    assert 'do not invent a symbol' in row['required_action']


def test_explicit_feedback_driven_correction_passes_existing_validator_with_two_attempts(tmp_path, bound_plan):
    bad = wrapper_code()
    assert set(validate_code(bad, bound_plan)['errors']) >= {
        'canonical_callback_binding_mismatch', 'project_api_outside_fuzzer_entry'}
    original = deepcopy(bound_plan)
    def correct(prompt):
        row, = prompt.parameters['repair_data']['callback_binding_feedback']['bindings']
        assert row['expected_producer_symbol'] == 'handle' and row['parameter'] == 'handler'
        assert row['argument_index'] == 2
        assert prompt.parameters['harness_plan'] == original
        return CODE  # Explicit offline model proposal, never generated by the framework.
    llm = ScriptedCodeLLM([bad, correct, bad])
    destination = tmp_path / 'isolated_callback_translation'
    destination.mkdir()
    status, calls, error, attempts = translate(destination, bound_plan, ContextStage4Generator(llm), max_code_repairs=1)
    assert status == 'passed' and calls == 2 and error is None and len(llm.calls) == 2
    assert [a['status'] for a in attempts] == ['invalid_code', 'passed']
    assert len(llm.steps) == 1 and bound_plan == original
    assert all(a['plan_digest'] == digest(original) for a in attempts)
    assert (destination/'code_attempts/attempt_0001/harness.cpp').read_text() == bad.strip() + '\n'
    assert validate_code((destination/'harness.cpp').read_text(), original)['status'] == 'valid'


def test_repeated_wrapper_remains_invalid_and_cannot_buy_a_third_code_call(tmp_path, bound_plan):
    bad = wrapper_code()
    llm = ScriptedCodeLLM([bad, bad, CODE])
    destination = tmp_path / 'unchanged_callback_wrapper'
    destination.mkdir()
    status, calls, _, attempts = translate(destination, bound_plan, ContextStage4Generator(llm), max_code_repairs=1)
    assert status == 'invalid_code' and calls == 2 and len(llm.calls) == 2 and len(llm.steps) == 1
    assert [a['status'] for a in attempts] == ['invalid_code', 'invalid_code']
    assert 'canonical_callback_binding_mismatch' in json.loads((destination/'code_validation.json').read_text())['errors']


def test_modified_frozen_identity_is_rejected_before_feedback_or_model_call(bound_plan):
    plan = deepcopy(bound_plan)
    plan['callback_policy']['implementation'] = 'different callback decision'
    llm = ScriptedCodeLLM([CODE])
    with pytest.raises(ValueError, match='immutable'):
        ContextStage4Generator(llm).render_repair(plan, CODE, {'code_validation':{'errors':['canonical_callback_binding_mismatch']}})
    assert llm.calls == []
