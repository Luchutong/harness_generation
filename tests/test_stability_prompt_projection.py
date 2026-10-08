"""Agent transport reductions preserve exact gaps and never modify Gate data."""
from copy import deepcopy

from harness_generation.harness_context.prompt_projection import (agenda_view, obligation_view, task_view, terminal_guidance)
from harness_generation.harness_context.requirements import HarnessRequirementBuilder
from test_harness_context import setup


def test_prompt_reduction_preserves_exact_missing_subject_and_original():
    diagnostic = {'code': 'input_resource_without_binding', 'subject_function_id': 'api:1',
        'subject_parameter': 'input', 'question': 'repeated question',
        'graph_holes': [{'code': 'no_origin', 'parameter_id': 'param_1', 'candidate_dump': [1, 2]}]}
    proof = {'obligation_id': 'o1', 'proof_status': 'missing', 'diagnostics': [diagnostic]}
    task = {'requirement_id': 'r1', 'blocked_roots': ['o2'], 'missing_proofs': [proof], 'question': 'repeated'}
    agenda = {'slots': [{'slot': 'r0', 'missing_proofs': [proof], 'retained_entries': [{'subject_id': 's1'}]}]}
    before = deepcopy((task, agenda))
    reduced = agenda_view(agenda)
    assert reduced['slots'][0]['missing_proofs'][0]['diagnostics'][0] == {
        'code': 'input_resource_without_binding', 'subject_function_id': 'api:1', 'subject_parameter': 'input',
        'graph_holes': [{'code': 'no_origin', 'parameter_id': 'param_1'}]}
    assert reduced['slots'][0]['retained_entries'] == [{'subject_id': 's1'}]
    assert 'missing_proofs' not in task_view(task, include_proofs=False)
    assert (task, agenda) == before
    view = {'proved': [], 'blocked': [dict(proof, question='duplicated')], 'missing_evidence': [], 'graph_digest': 'd1'}
    assert obligation_view(view)['blocked'][0]['obligation_id'] == 'o1'
    assert 'diagnostics' not in obligation_view(view)['blocked'][0]


def test_pointer_producer_has_input_question_but_cleanup_does_not(tmp_path):
    source = '''#include <stddef.h>
#include <stdlib.h>
typedef struct Handle { const unsigned char *data; size_t size; } Handle;
Handle *open_bytes(const unsigned char *data, size_t size) { Handle *h=malloc(sizeof(*h)); if(h){h->data=data;h->size=size;} return h; }
int parse(Handle *h) { return h->size ? h->data[0] : 0; }
void close_handle(Handle *h) { free(h); }
'''
    prepared = setup(tmp_path, source)
    snapshot = prepared[3]
    names = {f['name']: fid for fid, f in snapshot.functions.items()}
    builder = HarnessRequirementBuilder()
    kinds = lambda name: {r['kind'] for r in builder.function_requirements(prepared[1], snapshot, names[name], core=False)}
    assert 'input_binding' in kinds('open_bytes')
    assert 'input_binding' not in kinds('close_handle')
    assert 'input_binding' not in kinds('parse')


def test_terminal_guidance_has_one_slot_per_requirement_and_no_budget_override():
    guidance = terminal_guidance([{'kind': 'ownership'}, {'kind': 'input_binding'}])
    assert guidance['slots'] == {'r0': 'ownership', 'r1': 'input_binding'}
    assert 'budget' not in guidance


def test_internal_helper_is_covered_by_parent_without_an_extra_call(tmp_path):
    from harness_generation.context_generation.validation import validate_code
    from test_context_generation import ready, DIRECT_CODE
    _, _, plan = ready(tmp_path)
    parent = plan['call_sequence'][0]
    helper = deepcopy(parent)
    helper.update(function_id='helper:1', symbol='consume_internal', invocation_kind='internal',
                  via_function_id=parent['function_id'], calls_per_input=None,
                  calls_per_invocation={'min': 1, 'max': None})
    plan['call_sequence'].append(helper)
    declaration = deepcopy(plan['api_declarations'][0])
    declaration.update(function_id='helper:1', symbol='consume_internal',
                       signature='int consume_internal(const unsigned char *data, size_t size)')
    plan['api_declarations'].append(declaration)
    code = DIRECT_CODE.replace('extern "C" int LLVMFuzzerTestOneInput',
        'extern "C" int consume_internal(const unsigned char *data, size_t size);\nextern "C" int LLVMFuzzerTestOneInput')
    assert validate_code(code, plan)['status'] == 'valid'
    extra = code
    extra = extra.replace('(void)parse(data, size);', '(void)parse(data, size);\n(void)consume_internal(data, size);')
    assert 'required_invocation_count_mismatch' in validate_code(extra, plan)['errors']


def test_context_semantic_correction_reuses_original_round_budget(tmp_path):
    import json
    from harness_generation.harness_context.agent import HarnessContextAgent
    from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, canonical
    from test_harness_context import direct_specs
    from test_context_grouping import GroupedFixtureModel

    prepared = setup(tmp_path)
    rows = HarnessRequirementBuilder().build(prepared[1], prepared[3])['requirements']

    class FirstBadApplicability(GroupedFixtureModel):
        attempts = 0
        def complete(self, messages, schemas):
            response = super().complete(messages, schemas)
            self.attempts += 1
            if self.attempts != 1:
                return response
            call = response.tool_calls[0]
            values = json.loads(call.arguments)
            index = next(i for i, r in enumerate(rows) if r['kind'] == 'input_binding')
            values['resolutions']['r' + str(index)]['status'] = 'not_applicable'
            return AgentModelResponse(tool_calls=(AgentToolCall(call.id, call.name, canonical(values)),))

    model = FirstBadApplicability(direct_specs(prepared[0][-1]['parse']))
    runs = HarnessContextAgent(model, prepared[4]).investigate_group(rows, prepared[5])
    assert all(r.result['status'] == 'resolved' for r in runs)
    assert prepared[4].model_calls == 2
    assert any(e['kind'] == 'semantic_recovery' for e in runs[0].trace['events'])
    assert any(e.get('error_category') == 'terminal_validation_error' for e in runs[0].trace['events'])
    assert runs[0].metadata['proof_investigation']['configured_round_limit'] == 4
