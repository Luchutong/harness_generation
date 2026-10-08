"""An unexamined returned-object effect stays unknown rather than unrelated."""
from copy import deepcopy

import pytest

from harness_generation.semantic_discovery.models import canonical
from harness_generation.semantic_slicing.models import validate_submission
from harness_generation.semantic_slicing.proposals import choices
from harness_generation.semantic_slicing.effect_questions import returned_resource_questions, SliceExclusionEffectError
from test_semantic_slicing import fixture
from test_slice_source_exclusions import live_slice_tools, prepared, selected

SOURCE = '''#include <stdlib.h>
typedef unsigned long size_t;
typedef struct Node { int value; } Node;
Node *parse(const unsigned char *data,size_t size) { Node *p=malloc(sizeof(Node)); if(p) p->value=size ? data[0] : 0; return p; }
void finish(Node *p) { delegate(p); }
void delegate(Node *p) { free(p); }
'''


def test_missing_forwarded_body_withholds_only_unrelated_choice_and_writes_no_facts(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    tools, ids = live_slice_tools(sample), sample[-1]
    tools.execute('get_function', {'function': ids['parse']})
    tools.execute('read_source_range', {'file': 'api.c', 'line_start': 5, 'line_end': 5})
    before = deepcopy(tools.evidence), tools.source_chars, set(tools.authorized_ids)
    questions = returned_resource_questions(tools)
    assert set(questions) == {ids['finish']}
    question, = questions[ids['finish']]
    assert question['proof_status'] == 'missing' and question['subject_parameter'] == 'p'
    assert set(question['evidence_ids']) <= tools.evidence.keys()
    options = [c for c in choices(tools) if c['function_id'] == ids['finish']]
    assert {c['role'] for c in options} == {'unresolved'}
    assert options[0]['unresolved_effect_questions'] == [question]
    assert (tools.evidence, tools.source_chars, tools.authorized_ids) == before
    submitted = validate_submission(canonical({'classification': [selected(tools, ids['parse'], 'core'),
        selected(tools, ids['finish'], 'unresolved')]}), tools)
    assert next(c for c in submitted['classification'] if c['function_id'] == ids['finish'])['role'] == 'unresolved'
    # A real tool query issues the missing helper and makes its effect known;
    # the projection never reads or authorizes it implicitly.
    tools.execute('find_callees', {'function': ids['finish']})
    tools.execute('get_function', {'function': ids['delegate']})
    assert not returned_resource_questions(tools)
    assert any(c['function_id'] == ids['finish'] and c['role'] == 'support' for c in choices(tools))


def test_legacy_expanded_exclude_cannot_bypass_uncertain_pointer_effect(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    tools, ids = live_slice_tools(sample), sample[-1]
    tools.execute('get_function', {'function': ids['parse']})
    tools.execute('read_source_range', {'file': 'api.c', 'line_start': 5, 'line_end': 5})
    question = returned_resource_questions(tools)[ids['finish']][0]
    rows = [{'function_id': ids['parse'], 'role': 'core', 'reason_codes': ['accepted_anchor'],
        'evidence_ids': [eid for eid, r in tools.evidence.items() if r.get('function_id') == ids['parse']], 'open_questions': []},
        {'function_id': ids['finish'], 'role': 'exclude', 'reason_codes': ['unrelated_behavior'],
         'evidence_ids': question['evidence_ids'], 'open_questions': []}]
    with pytest.raises(SliceExclusionEffectError) as error:
        validate_submission(canonical({'classification': rows}), tools)
    assert error.value.to_dict()['error'] == 'slice_exclusion_effect_unproven'
    assert error.value.terminal_extra_repair_allowed is False


@pytest.mark.parametrize('body', ['(void)p;', 'unknown_counter();', 'consume_scalar(p->value);', 'free(p);'])
def test_type_or_unrelated_uncertainty_alone_never_withholds_exclude(tmp_path, body):
    source = SOURCE.replace('delegate(p);', body)
    _, tools, ids = prepared(tmp_path, source)
    assert not returned_resource_questions(tools)
    assert any(c['function_id'] == ids['finish'] and c['role'] == 'exclude' for c in choices(tools))


def test_complete_indirect_callback_effect_is_unknown_without_promoting_cleanup(tmp_path):
    source = SOURCE.replace('void finish(Node *p) { delegate(p); }',
        'void finish(Node *p) { void (*handler)(Node *)=delegate; handler(p); }')
    _, tools, ids = prepared(tmp_path, source)
    assert ids['finish'] in returned_resource_questions(tools)
    assert not any(c['function_id'] == ids['finish'] and c['role']=='exclude' for c in choices(tools))


@pytest.mark.parametrize('body', [
    'Node *q=0; q=p; unknown(q);',
    'Node *q=0; if (p->value) q=p; unknown(q);',
    'Node *q=0; while (p->value) { q=p; break; } unknown(q);',
    'Node *q=p; { q=0; } q=p; unknown(q);',
    'unknown(p+0);',
    'unknown(0+p);',
    'unknown(&p[0]);',
    'Node *q=p+0; unknown(q);',
    'unknown(&p);',
    'Node *q=p; unknown(&q);',
    'unknown(&p->value);',
])
def test_assigned_or_possible_alias_retains_missing_effect_question(tmp_path, body):
    source = SOURCE.replace('delegate(p);', body)
    _, tools, ids = prepared(tmp_path, source)
    assert ids['finish'] in returned_resource_questions(tools)
    assert not any(c['function_id']==ids['finish'] and c['role']=='exclude' for c in choices(tools))


@pytest.mark.parametrize('body', [
    'Node *q=p; q=0; unknown(q);',
    'p=0; unknown(p);',
    'Node *q=p; { Node *q=0; unknown(q); }',
    'Node *q=p; { q=0; } unknown(q);',
])
def test_rebound_or_shadowed_pointer_is_not_forwarded_subject(tmp_path, body):
    source = SOURCE.replace('delegate(p);', body)
    _, tools, ids = prepared(tmp_path, source)
    assert not returned_resource_questions(tools)
    assert any(c['function_id']==ids['finish'] and c['role']=='exclude' for c in choices(tools))
