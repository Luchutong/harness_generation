"""Owned tree roots are released by structure, independent of API/field names."""
import re

import pytest

from harness_generation.harness_context.proof_grounding import analyze, cleanup_checks
from harness_generation.harness_context.resource_identity import parameter_release_proof
from harness_generation.semantic_slicing.support_effects import bindings
from test_harness_context import owner
from test_proof_reliability import analysis_fixture


SOURCE = '''#include <stdlib.h>
typedef struct Node {struct Node *up;unsigned tag;unsigned count;struct Node **children;char *payload;} Node;
typedef struct Hooks {void (*dispose)(void *,void *);void *cookie;} Hooks;
static void discard(void *p,void *cookie){(void)cookie;free(p);}
void walk(Hooks *hooks,Node *node){
 Node *saved;
 if(!node)return;
 node->up=0;
 while(node){
  switch(node->tag){
   case 1:
    if(!node->count){hooks->dispose(node->children,hooks->cookie);break;}
    node=node->children[--node->count];continue;
   case 2:hooks->dispose(node->payload,hooks->cookie);break;
   default:break;
  };
  saved=node;node=node->up;hooks->dispose(saved,hooks->cookie);
 }
}
void finish(Node *node){Hooks hooks={0};hooks.dispose=discard;walk(&hooks,node);}
Node *parse(const unsigned char *bytes,unsigned extent){return calloc(1,sizeof(Node));}
'''


def inspect(tmp_path, source=SOURCE):
    snapshot, ids, records, issued = analysis_fixture(tmp_path, source)
    summary = analyze(snapshot.functions[ids['finish']], snapshot, issued)
    claim = {'ownership_contract': {'entries': [dict(function_id=ids['parse'],fact_id='fact_result',
        evidence_ids=['ev_parse','ev_finish'], **owner(returned=True,ownership='owned',release=ids['finish']))]}}
    return snapshot, ids, records, issued, summary, cleanup_checks(claim,snapshot,records)


@pytest.mark.parametrize('renamed', [False, True])
def test_exact_owned_postorder_root_release_through_bound_callback(tmp_path, renamed):
    source = SOURCE
    if renamed:
        names = dict(Node='Record',up='ancestor',tag='variant',count='remaining',children='entries',
            payload='text',dispose='deallocate',cookie='userdata',discard='drop_storage',
            walk='traverse',node='cursor',saved='previous')
        source = re.sub(r'\b('+'|'.join(names)+r')\b', lambda m:names[m[0]], source)
    snapshot, ids, _, issued, summary, checks = inspect(tmp_path,source)
    assert all(not p['uncertain'] and p['release_counts']['parameter:' + ('cursor' if renamed else 'node')] == (1,1)
        for p in summary['paths'])
    assert summary['traversal_proofs']
    assert checks[0]['status']=='proved'
    assert parameter_release_proof(snapshot.functions[ids['finish']], 'cursor' if renamed else 'node', snapshot, issued)
    effects=bindings(snapshot.functions[ids['parse']],snapshot.functions[ids['finish']],snapshot.functions,issued,
        release_summary=summary)
    assert effects['cleanup']


@pytest.mark.parametrize('before,after', [
    ('node->up=0;', ''),
    ('struct Node *up;', 'unsigned up;'),
    ('if(!node->count)', 'if(node->count)'),
    ('[--node->count]', '[node->count--]'),
    ('[--node->count]', '[1+(--node->count)]'),
    ('node=node->children', 'node=other->children'),
    ('default:break;', 'default:return;'),
    ('default:break;', ''),
    ('saved=node;', 'saved=0;'),
    ('node=node->up;', 'node=node->children[0];'),
    ('hooks->dispose(saved,hooks->cookie);', 'if(node)hooks->dispose(saved,hooks->cookie);'),
    ('hooks->dispose(saved,hooks->cookie);', 'hooks->dispose(hooks->cookie,saved);'),
    ('free(p);', 'free(cookie);'),
    ('void discard(void *p,void *cookie)', 'int discard(void *p,void *cookie)'),
    ('hooks.dispose=discard;', ''),
    ('walk(&hooks,node);', 'walk(&hooks,node);free(node);'),
])
def test_wrong_object_rank_branch_callback_and_double_release_never_prove(tmp_path,before,after):
    _,_,_,_,summary,checks=inspect(tmp_path,SOURCE.replace(before,after))
    assert checks[0]['status']!='proved'


@pytest.mark.parametrize('helper',['discard','walk'])
def test_full_issued_delegate_and_callback_bodies_are_required(tmp_path,helper):
    snapshot,ids,_,issued,_,_=inspect(tmp_path)
    del issued[ids[helper]]
    assert not parameter_release_proof(snapshot.functions[ids['finish']], 'node', snapshot, issued)


def test_unused_indeterminate_pointer_does_not_destroy_other_object_proof(tmp_path):
    _,_,_,_,_,checks=inspect(tmp_path,SOURCE.replace('Hooks hooks={0};','Node *unused;Hooks hooks={0};'))
    assert checks[0]['status']=='proved'
