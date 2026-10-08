"""Stable semantic choices and output/input construction boundaries."""
import pytest

from harness_generation.semantic_discovery.models import canonical
from harness_generation.semantic_slicing import SemanticSliceTools, build_frontier
from harness_generation.semantic_slicing.models import validate_submission
from harness_generation.semantic_slicing.proposals import choices
from harness_generation.harness_context.proposals import registry
from harness_generation.harness_context.repairs import merge_resolution, fact_conflicts
from test_semantic_slicing import fixture, DIRECT
from test_proposal_boundaries import activated
from test_semantic_slicing import run, terminal, queries, tool
from harness_generation.semantic_discovery import AgentModelResponse, AgentToolCall
from harness_generation.semantic_discovery.models import ValidationBudget


def slice_tools(sample):
    store, artifacts, catalog, candidate, validation, _ = sample
    tools = SemanticSliceTools(artifacts, catalog,
        build_frontier(store, artifacts, catalog, candidate, validation))
    tools._frontier({'candidate_id': validation['candidate_id'], 'function_id': candidate.function_id})
    tools.execute('find_callers', {'function': candidate.function_id})
    return tools


def test_old_unresolved_selection_survives_new_source_and_uses_current_evidence(tmp_path):
    sample = fixture(tmp_path, DIRECT)
    tools, ids = slice_tools(sample), sample[-1]
    old = next(c for c in choices(tools) if c['function_id'] == ids['wrapper'] and c['role'] == 'unresolved')
    assert old['evidence_ids'] == []
    tools.execute('get_function', {'function': ids['wrapper']})
    current = next(c for c in choices(tools) if c['function_id'] == ids['wrapper'] and c['role'] == 'unresolved')
    assert current['evidence_ids'] and current['choice_id'] == old['choice_id']
    anchor = next(c for c in choices(tools) if c['function_id'] == ids['parse'] and c['role'] == 'core')
    result = validate_submission(canonical({'classification': [
        {'choice_id': anchor['choice_id'], 'open_questions': []},
        {'choice_id': old['choice_id'], 'open_questions': ['No independent target dependence proved.']}]}), tools)
    row = next(r for r in result['classification'] if r['function_id'] == ids['wrapper'])
    assert row['role'] == 'unresolved' and row['evidence_ids'] == current['evidence_ids']


def test_withdrawn_decisive_proof_does_not_leave_an_accepted_historical_choice(tmp_path):
    sample = fixture(tmp_path, DIRECT)
    tools, ids = slice_tools(sample), sample[-1]
    tools.execute('get_function', {'function': ids['wrapper']})
    old = next(c for c in choices(tools) if c['function_id'] == ids['wrapper'] and c['role'] == 'exclude')
    tools.evidence = {eid:r for eid,r in tools.evidence.items() if eid not in old['evidence_ids']}
    with pytest.raises(ValueError, match='slice_role_choice_not_issued'):
        validate_submission(canonical({'classification': [
            {'choice_id': old['choice_id'], 'open_questions': []}]}), tools)


def test_choice_from_another_source_snapshot_is_rejected(tmp_path):
    a, b = tmp_path/'a', tmp_path/'b'
    a.mkdir(); b.mkdir()
    original = slice_tools(fixture(a, DIRECT))
    other = slice_tools(fixture(b, DIRECT.replace('return parse(data, size);', 'return 123;')))
    foreign = next(c for c in choices(original) if c['role'] == 'unresolved')
    with pytest.raises(ValueError, match='slice_role_choice_not_issued'):
        validate_submission(canonical({'classification': [
            {'choice_id': foreign['choice_id'], 'open_questions': ['Different source.']}]}), other)


@pytest.mark.parametrize('rounds', [3, 2])
def test_missing_unresolved_question_uses_existing_round_or_one_registered_last_extra(tmp_path, rounds):
    sample = fixture(tmp_path, DIRECT)
    ids = sample[-1]
    mapping = {ids['parse']: ('core', 'accepted_anchor'), ids['wrapper']: ('unresolved', 'insufficient_evidence')}
    bad = terminal(mapping, mutate=lambda p:p['classification'][1].update(open_questions=[]))
    def good(messages, schemas):
        assert [s['function']['name'] for s in schemas] == ['submit_semantic_slice']
        response = terminal(mapping)(messages, schemas)
        call = response.tool_calls[0]
        return AgentModelResponse(tool_calls=(AgentToolCall('fixed_submission', call.name, call.arguments),))
    result, model, _ = run(sample, [queries(tool('find_callers','discover',function=ids['parse'])), bad, good], ValidationBudget(max_rounds=rounds))
    assert result.result['run_status'] == 'completed_with_unresolved'
    assert len(model.calls) == 3
    assert result.result['budget']['tool_calls'] == 2
    if rounds == 3:
        assert result.metadata['protocol_recoveries'] == 1
        assert not result.metadata['extra_terminal_repair_attempts']
    else:
        assert not result.metadata['protocol_recoveries']
        assert result.metadata['extra_terminal_repair_attempts'] == 1
    assert result.result['classification'][1]['open_questions']


def test_unresolved_choice_schema_requires_its_question(tmp_path):
    from harness_generation.semantic_slicing.proposals import terminal_schema
    from harness_generation.semantic_discovery.models import DecisionSchemaError
    tools = slice_tools(fixture(tmp_path, DIRECT))
    row = next(c for c in choices(tools) if c['role']=='unresolved')
    alternatives = terminal_schema(tools)['function']['parameters']['properties']['classification']['items']['anyOf']
    matching = [a for a in alternatives if row['choice_id'] in a['properties']['choice_id']['enum']]
    assert len(matching) == 1 and matching[0]['properties']['open_questions']['minItems'] == 1
    with pytest.raises(DecisionSchemaError):
        validate_submission(canonical({'classification':[dict(choice_id=row['choice_id'],open_questions=[])]}),tools)


@pytest.mark.parametrize('producer', ['assemble', 'allocate_result'])
def test_return_output_does_not_require_a_second_same_type_creator_call(tmp_path, producer):
    source = f'''#include <stdlib.h>
typedef struct Product {{unsigned n;}} Product;
Product *{producer}(unsigned n) {{Product *p=calloc(1,sizeof(Product));if(p)p->n=n;return p;}}
Product *parse(const unsigned char *bytes,unsigned extent) {{return {producer}(extent?bytes[0]:0);}}
void discard(Product *p) {{free(p);}}
'''
    prepared, _, tools = activated(tmp_path, source, kind='lifecycle')
    ids = prepared[0][-1]
    tools.execute('find_callees', {'function': ids['parse']})
    tools.execute('find_type_usages', {'type': 'Product'})
    tools.execute('get_function', {'function': ids[producer]})
    tools.execute('get_function', {'function': ids['discard']})
    signed = registry(tools)
    assert not any(c['function_id'] == ids[producer] and c['reason'] in {'creation','initialization'}
        for c in signed['support_candidates'])
    assert any(c['function_id'] == ids['discard'] and c['reason'] == 'cleanup'
        for c in signed['support_candidates'])


def test_external_creator_for_input_resource_remains_available(tmp_path):
    source = '''#include <stdlib.h>
typedef struct Product {unsigned n;} Product;
Product *assemble(unsigned n) {Product *p=calloc(1,sizeof(Product));if(p)p->n=n;return p;}
int parse(Product *object,const unsigned char *bytes,unsigned extent) {return object->n+(extent?bytes[0]:0);}
'''
    prepared, _, tools = activated(tmp_path, source, kind='lifecycle')
    ids = prepared[0][-1]
    tools.execute('find_type_usages', {'type': 'Product'})
    tools.execute('get_function', {'function': ids['assemble']})
    candidate = next(c for c in registry(tools)['support_candidates']
        if c['function_id'] == ids['assemble'] and c['reason'] == 'creation')
    assert {s['parameter'] for s in candidate['subject_bindings']} == {'object'}
    assert not candidate['necessity_proven']


def support_resolution(reason, decision, parents=('public_api',)):
    req = dict(requirement_id='support_req', subject_function_id='helper_api', kind='support_decision')
    result = dict(requirement_id=req['requirement_id'], status='resolved',
        facts=[dict(requirement_id=req['requirement_id'], function_id=req['subject_function_id'],
            predicate=req['kind'], value=dict(reason=reason, decision=decision, required_by=list(parents)),
            evidence_ids=['complete_helper_body'])], discovered_api_dependencies=[], open_questions=[])
    return req, result


def test_different_support_roles_preserve_rejection_without_new_conflict():
    req, old = support_resolution('creation', 'rejected')
    _, patch = support_resolution('initialization', 'rejected')
    merged, audit = merge_resolution(old, patch, req)
    assert len(merged['facts']) == 2 and not audit['conflicts']
    assert not fact_conflicts(merged['facts'])
    again, _ = merge_resolution(merged, patch, req)
    assert again == merged


def test_required_and_rejected_same_support_relation_still_block():
    req, old = support_resolution('creation', 'rejected')
    _, patch = support_resolution('creation', 'required')
    merged, audit = merge_resolution(old, patch, req)
    assert audit['conflicts'] and len(merged['facts']) == 2


def test_support_relation_to_another_parent_is_an_independent_subject():
    req, old = support_resolution('creation', 'required', ('first_api',))
    _, patch = support_resolution('creation', 'rejected', ('second_api',))
    merged, audit = merge_resolution(old, patch, req)
    assert len(merged['facts']) == 2 and not audit['conflicts']
