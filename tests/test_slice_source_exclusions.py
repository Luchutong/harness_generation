"""Only exact issued source relations can contradict unrelated EXCLUDE."""
from copy import deepcopy
import json

import pytest

from harness_generation.semantic_discovery.models import canonical, ValidationBudget
from harness_generation.semantic_slicing.models import validate_submission
from harness_generation.semantic_slicing.proposals import choices
from harness_generation.semantic_slicing.source_exclusions import exclusion_blockers, ExclusionEvidenceError
from harness_generation.semantic_discovery.tools import RepositoryIndex
from harness_generation.semantic_slicing import SemanticSliceTools, build_frontier
from test_semantic_slicing import fixture, run, queries, tool, terminal


SOURCE = '''#include <stdlib.h>
#include <stddef.h>
typedef struct User { unsigned bias; } User;
typedef int (*Handler)(void *user,const unsigned char *src,size_t cb);
User *acquire(unsigned bias) { User *u=malloc(sizeof(User)); if(u) u->bias=bias; return u; }
void dispose(User *u) { free(u); }
int handle(void *user,const unsigned char *src,size_t cb) { User *u=user; return cb ? src[0]^u->bias : u->bias; }
int parse(const unsigned char *src,size_t cb,Handler handler,void *user) { return handler(user,src,cb); }
void usage(const unsigned char *raw,size_t extent) { User *u=acquire(0); parse(raw,extent,handle,u); dispose(u); }
'''


def live_slice_tools(sample):
    store, artifacts, catalog, candidate, validation, _ = sample
    tools = SemanticSliceTools(artifacts, catalog, build_frontier(store, artifacts, catalog, candidate, validation),
        index=RepositoryIndex(artifacts, catalog, functions_path=store.functions))
    tools._frontier({'candidate_id': validation['candidate_id'], 'function_id': candidate.function_id})
    tools.execute('find_callers', {'function': candidate.function_id})
    return tools


def prepared(tmp_path, source=SOURCE, anchor='parse'):
    sample = fixture(tmp_path, source, anchor=anchor)
    tools = live_slice_tools(sample)
    output = tools.execute('read_source_range', {'file': 'api.c', 'line_start': 1, 'line_end': source.count('\n')})
    assert not output.get('error')
    return sample, tools, sample[-1]


def selected(tools, fid, role, question='Which exact necessity remains unproved?'):
    choice = next(c for c in choices(tools) if c['function_id'] == fid and c['role'] == role)
    return {'choice_id': choice['choice_id'], 'open_questions': [question] if role == 'unresolved' else []}


def test_exact_callback_acquired_subject_blocks_exclude_without_promoting_role(tmp_path):
    _, tools, ids = prepared(tmp_path)
    before = deepcopy(tools.evidence), tools.source_chars
    blockers = exclusion_blockers(tools)
    assert set(blockers) == {ids['dispose']}
    certificate, = blockers[ids['dispose']]
    assert certificate['parent_function_id'] == ids['handle'] and certificate['subject_parameter'] == 'user'
    assert certificate['creator_function_id'] == ids['acquire'] and certificate['caller_function_id'] == ids['usage']
    assert certificate['required_fields'] == ['bias'] and certificate['via_function_id'] == ids['parse']
    assert certificate['creator_call_offset'] < certificate['core_call_offset'] < certificate['cleanup_call_offset']
    assert set(certificate['evidence_ids']) <= tools.evidence.keys()
    assert (tools.evidence, tools.source_chars) == before
    options = choices(tools)
    assert not any(c['function_id'] == ids['dispose'] and c['role'] == 'exclude' for c in options)
    assert any(c['function_id'] == ids['dispose'] and c['role'] == 'support' for c in options)
    unresolved = next(c for c in options if c['function_id'] == ids['dispose'] and c['role'] == 'unresolved')
    assert unresolved['exclusion_blockers'][0]['proof_id'] == certificate['proof_id']
    answer = validate_submission(canonical({'classification': [selected(tools, ids['parse'], 'core'),
        selected(tools, ids['handle'], 'core'), selected(tools, ids['dispose'], 'unresolved')]}), tools)
    assert next(r for r in answer['classification'] if r['function_id'] == ids['dispose'])['role'] == 'unresolved'


def test_legacy_expanded_exclude_cannot_bypass_source_constraint(tmp_path):
    _, tools, ids = prepared(tmp_path)
    rows = [{'function_id': ids['parse'], 'role': 'core', 'reason_codes': ['accepted_anchor'],
             'evidence_ids': [eid for eid, r in tools.evidence.items() if r.get('function_id') == ids['parse']], 'open_questions': []},
            {'function_id': ids['dispose'], 'role': 'exclude', 'reason_codes': ['unrelated_behavior'],
             'evidence_ids': exclusion_blockers(tools)[ids['dispose']][0]['evidence_ids'], 'open_questions': []}]
    with pytest.raises(ExclusionEvidenceError) as rejected:
        validate_submission(canonical({'classification': rows}), tools)
    error = rejected.value.to_dict()['errors'][0]
    assert error['function_id'] == ids['dispose'] and error['contradictions'][0]['proof_status'] == 'proven'


def test_withdrawn_native_choice_reports_source_certificate_as_schema_feedback(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    tools, ids = live_slice_tools(sample), sample[-1]
    tools.execute('find_callees', {'function': ids['usage']})
    tools.execute('get_function', {'function': ids['dispose']})
    old = selected(tools, ids['dispose'], 'exclude')
    tools.execute('read_source_range', {'file': 'api.c', 'line_start': 1, 'line_end': 9})
    with pytest.raises(ExclusionEvidenceError) as rejected:
        validate_submission(canonical({'classification': [selected(tools, ids['parse'], 'core'), old]}), tools)
    error = rejected.value.to_dict()['errors'][0]
    assert error['received'] == old['choice_id'] and error['contradictions'][0]['function_id'] == ids['dispose']
    # A foreign identity does not gain the schema-correction affordance.
    with pytest.raises(ValueError, match='slice_role_choice_not_issued') as foreign:
        validate_submission(canonical({'classification': [{'choice_id': 'slice_choice_foreign', 'open_questions': []}]}), tools)
    assert not isinstance(foreign.value, ExclusionEvidenceError)


@pytest.mark.parametrize('change', [
    ('dispose(u); }', 'User *v=acquire(1); dispose(v); }'),
    ('dispose(u); }', 'u=acquire(1); dispose(u); }'),
    ('dispose(u); }', 'escape(u); dispose(u); }'),
    ('free(u);', 'if(u->bias) free(u);'),
    ('free(u);', 'free(u); free(u);'),
    ('free(u);', 'free(&u);'),
    ('User *u=malloc(sizeof(User));', 'static User saved; User *u=&saved;'),
    ('return handler(user,src,cb);', 'if(cb) return handler(user,src,cb); return 0;'),
    ('parse(raw,extent,handle,u);', 'parse(raw,extent,0,u);'),
    ('parse(raw,extent,handle,u); dispose(u);', 'dispose(u); parse(raw,extent,handle,u);'),
    ('return cb ? src[0]^u->bias : u->bias;', 'return cb ? src[0] : 0;'),
    ('return cb ? src[0]^u->bias : u->bias;', 'unsigned result=cb ? src[0]^u->bias : u->bias; free(u); return result;'),
    ('return cb ? src[0]^u->bias : u->bias;', 'unsigned result=cb ? src[0]^u->bias : u->bias; if(cb) free(u); return result;'),
])
def test_type_effect_or_unknown_paths_cannot_become_exclusion_necessity(tmp_path, change):
    source = SOURCE.replace(*change)
    _, tools, ids = prepared(tmp_path, source)
    assert not exclusion_blockers(tools)
    assert any(c['function_id'] == ids['dispose'] and c['role'] == 'exclude' for c in choices(tools))


@pytest.mark.parametrize('helper', [
    'static User *saved; void escape(User *u) { saved=u; }',
    'void escape(User *u) { if(u->bias) free(u); }',
    'void escape(User *u) { (void)u->bias; }',
])
def test_additional_defined_caller_resource_uses_do_not_get_silently_skipped(tmp_path, helper):
    source = SOURCE.replace('void usage(', helper + '\nvoid usage(').replace(
        'parse(raw,extent,handle,u); dispose(u);', 'parse(raw,extent,handle,u); escape(u); dispose(u);')
    _, tools, ids = prepared(tmp_path, source)
    assert not exclusion_blockers(tools)
    assert any(c['function_id'] == ids['dispose'] and c['role'] == 'exclude' for c in choices(tools))


def test_direct_caller_global_alias_cannot_hide_between_core_and_cleanup(tmp_path):
    source = SOURCE.replace('User *acquire(', 'static User *saved;\nUser *acquire(').replace(
        'parse(raw,extent,handle,u); dispose(u);', 'parse(raw,extent,handle,u); saved=u; dispose(u);')
    _, tools, ids = prepared(tmp_path, source)
    assert not exclusion_blockers(tools)
    assert any(c['function_id'] == ids['dispose'] and c['role'] == 'exclude' for c in choices(tools))


def test_fresh_creator_export_with_global_alias_is_not_an_exclusive_local_chain(tmp_path):
    source = SOURCE.replace('User *acquire(', 'static User *saved;\nUser *acquire(').replace(
        'return u; }', 'saved=u; return u; }')
    _, tools, ids = prepared(tmp_path, source)
    assert not exclusion_blockers(tools)
    assert any(c['function_id'] == ids['dispose'] and c['role'] == 'exclude' for c in choices(tools))


@pytest.mark.parametrize('declaration, extra', [
    ('static User *saved[1];', 'saved[0]=u;'),
    ('static User *saved; static User **out=&saved;', '*out=u;'),
    ('static struct { User *value; } storage;', 'storage.value=u;'),
    ('static User *saved; void retain(User *value) { saved=value; }', 'retain(u);'),
    ('void consume(User *value) { if(value->bias) free(value); }', 'consume(u);'),
    ('', 'static User *retained=u;'),
    ('', 'u++;'),
    ('', 'u+=1;'),
])
def test_fresh_creator_extra_pointer_exports_or_rebindings_withdraw_necessity(tmp_path, declaration, extra):
    source = SOURCE.replace('User *acquire(', declaration + '\nUser *acquire(').replace(
        'return u; }', extra + ' return u; }')
    _, tools, ids = prepared(tmp_path, source)
    assert not exclusion_blockers(tools)
    assert any(c['function_id'] == ids['dispose'] and c['role'] == 'exclude' for c in choices(tools))


@pytest.mark.parametrize('extra', [
    'u++;', 'u+=1;', 'user++;', 'user=(void*)((char*)user+1);',
    'u=(User*)((char*)user+1);',
    'saved[0]=u;',
])
def test_core_pointer_rebinding_or_array_export_cannot_support_exclusion_proof(tmp_path, extra):
    source = SOURCE.replace('User *acquire(', 'static User *saved[1];\nUser *acquire(').replace(
        'User *u=user; return cb', 'User *u=user; ' + extra + ' return cb')
    _, tools, ids = prepared(tmp_path, source)
    assert not exclusion_blockers(tools)
    assert any(c['function_id'] == ids['dispose'] and c['role'] == 'exclude' for c in choices(tools))


@pytest.mark.parametrize('declaration, extra', [
    ('static User *saved[1]; void retain(User *value) { saved[0]=value; }', 'retain(u);'),
    ('static unsigned *saved;', 'saved=&u->bias;'),
    ('static User *saved;', 'saved=&u[0];'),
    ('static unsigned *saved; void retain(unsigned *value) { saved=value; }', 'retain(&u->bias);'),
])
def test_core_local_alias_or_interior_address_retention_is_not_exclusive(tmp_path, declaration, extra):
    source = SOURCE.replace('User *acquire(', declaration + '\nUser *acquire(').replace(
        'User *u=user; return cb', 'User *u=user; ' + extra + ' return cb')
    _, tools, ids = prepared(tmp_path, source)
    assert not exclusion_blockers(tools)
    assert any(c['function_id'] == ids['dispose'] and c['role'] == 'exclude' for c in choices(tools))


def test_no_argument_global_consumer_cannot_hide_between_core_and_cleanup(tmp_path):
    source = SOURCE.replace('User *acquire(', 'static User *saved;\nUser *acquire(').replace(
        'return u; }', 'saved=u; return u; }').replace('void usage(',
        'void kill_saved(void) { free(saved); }\nvoid usage(').replace(
        'parse(raw,extent,handle,u); dispose(u);', 'parse(raw,extent,handle,u); kill_saved(); dispose(u);')
    _, tools, ids = prepared(tmp_path, source)
    assert not exclusion_blockers(tools)
    assert any(c['function_id'] == ids['dispose'] and c['role'] == 'exclude' for c in choices(tools))


def test_multiple_observed_origins_do_not_collapse_for_exclusion_proof(tmp_path):
    source = SOURCE + '\nvoid second(const unsigned char *p,size_t n){User *v=acquire(1);parse(p,n,handle,v);dispose(v);}\n'
    _, tools, _ = prepared(tmp_path, source)
    assert not exclusion_blockers(tools)


def test_type_only_source_without_caller_keeps_decision_open(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    tools, ids = live_slice_tools(sample), sample[-1]
    tools.execute('read_source_range', {'file': 'api.c', 'line_start': 1, 'line_end': 8})
    assert not exclusion_blockers(tools)
    assert any(c['function_id'] == ids['dispose'] and c['role'] == 'exclude' for c in choices(tools))


@pytest.mark.parametrize('damage', ['truncated', 'content', 'foreign_id'])
def test_forged_or_partial_records_withdraw_the_certificate_and_cache(tmp_path, damage):
    _, tools, ids = prepared(tmp_path)
    assert ids['dispose'] in exclusion_blockers(tools)
    eid, record = next((eid, r) for eid, r in tools.evidence.items() if r['tool'] == 'read_source_range')
    if damage == 'truncated':
        record['truncated'] = True
    elif damage == 'content':
        record['content'] = record['content'].replace('dispose(u);', 'dispose(0);')
    else:
        tools.evidence['ev_foreign'] = tools.evidence.pop(eid)
        tools.evidence['ev_foreign']['evidence_id'] = 'ev_foreign'
    assert not exclusion_blockers(tools)


def test_relation_uses_source_identities_instead_of_api_spelling(tmp_path):
    source = SOURCE
    for old, new in [('acquire', 'reserve'), ('dispose', 'retire'), ('handle', 'react'), ('parse', 'decode')]:
        source = source.replace(old, new)
    _, tools, ids = prepared(tmp_path, source, anchor='decode')
    proof, = exclusion_blockers(tools)[ids['retire']]
    assert proof['parent_function_id'] == ids['react'] and proof['creator_function_id'] == ids['reserve']


def test_native_wrong_exclude_can_only_correct_in_an_existing_round(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    ids = sample[-1]
    def wrong(messages, schemas):
        from harness_generation.semantic_discovery.models import digest
        seed = next(json.loads(m['content']) for m in messages if m['role'] == 'tool'
                    and 'slice_role_choices' in json.loads(m['content']))
        anchor_choice = next(c for c in seed['slice_role_choices'] if c['function_id'] == ids['parse'] and c['role'] == 'core')
        old_exclude = 'slice_choice_' + digest([sample[2].source_fingerprint, ids['parse'], ids['dispose'],
            'exclude', ['unrelated_behavior']])[:24]
        return queries(tool('submit_semantic_slice', 'old_exclude', classification=[
            {'choice_id': anchor_choice['choice_id'], 'open_questions': []},
            {'choice_id': old_exclude, 'open_questions': []}]))
    def correct(messages, schemas):
        assert [s['function']['name'] for s in schemas] == ['submit_semantic_slice']
        feedback = next(json.loads(m['content']) for m in reversed(messages) if m['role'] == 'tool' and 'errors' in json.loads(m['content']))
        assert feedback['errors'][0]['contradictions'][0]['function_id'] == ids['dispose']
        inventory = next(json.loads(m['content'])['slice_role_choices'] for m in reversed(messages)
            if m['role'] == 'tool' and 'slice_role_choices' in json.loads(m['content']))
        rows = []
        for fid, role in [(ids['parse'], 'core'), (ids['dispose'], 'unresolved')]:
            choice = next(c for c in inventory if c['function_id'] == fid and c['role'] == role)
            rows.append({'choice_id': choice['choice_id'], 'open_questions': ['Need exact cleanup necessity.'] if role == 'unresolved' else []})
        return queries(tool('submit_semantic_slice', 'corrected', classification=rows))
    outcome, model, _ = run(sample, [queries(tool('read_source_range', 'whole_source', file='api.c', line_start=1, line_end=9)),
        wrong, correct], ValidationBudget(max_rounds=3))
    assert len(model.calls) == 3 and outcome.metadata['protocol_recoveries'] == 1
    assert outcome.result['excluded_functions'] == [] and outcome.result['support_functions'] == []
    assert ids['dispose'] in outcome.result['unresolved_frontier']


def test_resume_configuration_records_exclusion_proof_policy_and_rejects_old_version(tmp_path):
    from harness_generation.semantic_slicing.models import SLICE_POLICY_VERSION
    from harness_generation.semantic_slicing.persistence import load_compatible_slice, run_configuration, save_run
    from harness_generation.semantic_slicing.source_exclusions import VERSION
    sample = fixture(tmp_path, SOURCE)
    result, model, tools = run(sample, [
        queries(tool('read_source_range', 'whole_source', file='api.c', line_start=1, line_end=9)),
        terminal({sample[-1]['parse']: ('core', 'accepted_anchor')})])
    config = run_configuration(sample[2], tools.frontier, tools.budget, model, 32)
    assert config['policy_version'] == SLICE_POLICY_VERSION
    assert config['source_exclusion_proof_version'] == VERSION
    save_run(sample[0], result, config)
    assert load_compatible_slice(sample[0], tools.frontier, config, tools.index, tools.budget)
    old = {**config, 'source_exclusion_proof_version': 'source-exclusion-contradiction-v2'}
    assert load_compatible_slice(sample[0], tools.frontier, old, tools.index, tools.budget) is None
