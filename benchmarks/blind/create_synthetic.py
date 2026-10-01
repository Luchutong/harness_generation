"""Evaluation-only, preregistered API models and independent annotations.

Never imported by any pipeline/agent. Only source/ is copied into trial projects.
Annotations describe mandatory semantic contracts, not predicted framework output.
"""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parent
PREFIX = '#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n'


def resource(label, creator, cleanup, uses, *, output=None):
    return {"id": label, "origin": {"api": creator, "kind": "out_parameter" if output else "return", "parameter": output},
            "consumers": [{"api": api, "parameter": param} for api, param in uses],
            "cleanup": cleanup, "ownership": "owned", "scope": "per_input"}


def binding(api, parameter, size=None, *, source="fuzz_data", via=None):
    return {"api": api, "parameter": parameter, "source": source, "size_parameter": size, "via_api": via}


def register(name, dimension, source, anchor, core, support, resources, inputs, *, callbacks=(), ordering=(), counts=None, extra=None):
    directory = ROOT / 'synthetic' / name
    (directory / 'source').mkdir(parents=True, exist_ok=False)
    (directory / 'source' / 'api.c').write_text(PREFIX + source)
    spec = {"id": name, "set": "blind_synthetic", "semantic_dimension": dimension, "source_dir": f"synthetic/{name}/source",
            "anchor": anchor, "headers": [], "sources": ["api.c"], "include_paths": [], "compiler_flags": ["-std=c11"], "link_flags": []}
    truth = {"schema_version": 1, "annotation_kind": "independent_manual_contract", "id": name,
             "core_apis": list(core), "required_support": list(support), "resources": list(resources),
             "input_binding": list(inputs), "ownership": [], "callback": list(callbacks),
             "ordering": [{"before": a, "after": b} for a, b in ordering], "invocation_counts": counts or {},
             "mandatory_constraints": extra or {}, "adjudication": "strict necessary-contract checks; unknown is unverified, never automatically correct"}
    for r in resources:
        truth['ownership'].append({"api": r['origin']['api'], "parameter": r['origin']['parameter'],
                                   "return_value": r['origin']['kind'] == 'return',
                                   "ownership": 'owned' if r['origin']['kind']=='return' else 'borrowed',
                                   "release_api": r['cleanup'] if r['origin']['kind']=='return' else None})
        truth['ownership'].extend({"api": u['api'], "parameter": u['parameter'], "return_value": False, "ownership": 'borrowed', "release_api": None} for u in r['consumers'])
    (directory / 'ground_truth.json').write_text(json.dumps(truth, indent=2)+'\n')
    return spec


def main():
    specs = []
    specs.append(register('creator_arguments', 'creator arguments + configuration', '''
typedef struct DcOptions { unsigned limit; } DcOptions;
typedef struct DcCtx { unsigned limit; unsigned flags; } DcCtx;
DcCtx *dc_open(const DcOptions *options, unsigned flags) {
    if (!options) return NULL;
    DcCtx *c=malloc(sizeof(*c)); if (!c) return NULL;
    c->limit=options->limit; c->flags=flags; return c;
}
int dc_decode(DcCtx *c, const unsigned char *bytes, size_t length) {
    if (c->limit && length>c->limit) return -1;
    unsigned sum=0; for(size_t i=0;i<length;i++) sum=(sum*33u)^bytes[i];
    return (int)(sum & 0x7fff);
}
void dc_close(DcCtx *c) { free(c); }
int dc_example(const unsigned char *p,size_t n) {
    DcOptions opts={0}; DcCtx *c=dc_open(&opts,0); if(!c) return -1;
    int r=dc_decode(c,p,n); dc_close(c); return r;
}
''', 'dc_decode', ['dc_decode'], ['dc_open','dc_close'],
        [resource('decoder','dc_open','dc_close',[('dc_decode','c')])], [binding('dc_decode','bytes','length')],
        ordering=[('dc_open','dc_decode'),('dc_decode','dc_close')], extra={'non_null_arguments': [{'api':'dc_open','parameter':'options'}]}))

    specs.append(register('out_initialization', 'out-parameter origin + status return', '''
typedef struct OpOptions { unsigned mask; } OpOptions;
typedef struct OpState { unsigned mask; } OpState;
int op_initialize(OpState **out,const OpOptions *opts) {
    if(!out || !opts) return -1; *out=NULL;
    OpState *p=calloc(1,sizeof(*p)); if(!p) return -2;
    p->mask=opts->mask; *out=p; return 0;
}
int op_feed(OpState *p,const unsigned char *data,size_t len) { return len ? (data[0]^p->mask)&255 : 0; }
void op_dispose(OpState *p) { free(p); }
int op_example(const unsigned char *d,size_t n) {
    OpOptions o={0}; OpState *p=NULL; if(op_initialize(&p,&o)) return -1;
    int r=op_feed(p,d,n); op_dispose(p); return r;
}
''','op_feed',['op_feed'],['op_initialize','op_dispose'],
        [resource('parser','op_initialize','op_dispose',[('op_feed','p')],output='out')], [binding('op_feed','data','len')],
        ordering=[('op_initialize','op_feed'),('op_feed','op_dispose')],extra={'init_success':'zero','non_null_arguments':[{'api':'op_initialize','parameter':'opts'}]}))

    specs.append(register('helper_initialization', 'malloc + memset + defaults helper', '''
typedef struct HcState { const unsigned char *data; size_t size; unsigned base; } HcState;
static void hc_defaults(HcState *p) { p->base=17; }
HcState *hc_create(void) {
    HcState *p=malloc(sizeof(*p)); if(!p) return NULL;
    memset(p,0,sizeof(*p)); hc_defaults(p); return p;
}
void hc_put(HcState *p,const unsigned char *data,size_t size) { p->data=data; p->size=size; }
int hc_process(HcState *p) { return p->size ? (p->data[p->size-1]+p->base)&255 : 0; }
void hc_release(HcState *p) { free(p); }
void hc_example(const unsigned char *d,size_t n) {
    HcState *p=hc_create(); if(!p) return; hc_put(p,d,n); hc_process(p); hc_release(p);
}
''','hc_process',['hc_put','hc_process'],['hc_create','hc_release'],
        [resource('parser','hc_create','hc_release',[('hc_put','p'),('hc_process','p')])],
        [binding('hc_put','data','size'),binding('hc_process','p',source='context',via='hc_put')],
        ordering=[('hc_create','hc_put'),('hc_put','hc_process'),('hc_process','hc_release')]))

    specs.append(register('custom_allocator', 'allocator identity + custom deallocation', '''
typedef struct Arena { void *(*allocate)(void *cookie,size_t n); void (*release)(void *cookie,void *p); void *cookie; } Arena;
typedef struct AlParser { const Arena *arena; unsigned value; } AlParser;
AlParser *al_create(const Arena *arena) {
    if(!arena || !arena->allocate || !arena->release) return NULL;
    AlParser *p=arena->allocate(arena->cookie,sizeof(*p)); if(!p) return NULL;
    p->arena=arena; p->value=0; return p;
}
int al_decode(AlParser *p,const unsigned char *data,size_t n) { if(n) p->value=data[0]; return p->value; }
void al_destroy(AlParser *p,const Arena *arena) { if(p && arena==p->arena) arena->release(arena->cookie,p); }
static void *al_heap(void *cookie,size_t n) { (void)cookie; return malloc(n); }
static void al_free(void *cookie,void *p) { (void)cookie; free(p); }
void al_example(const unsigned char *d,size_t n) {
    Arena arena={al_heap,al_free,NULL}; AlParser *p=al_create(&arena); if(!p) return;
    al_decode(p,d,n); al_destroy(p,&arena);
}
''','al_decode',['al_decode'],['al_create','al_destroy'],[resource('parser','al_create','al_destroy',[('al_decode','p')])],
        [binding('al_decode','data','n')], callbacks=[{'api':'al_create','parameter':'arena.allocate','kind':'allocator','return_policy':'nonzero_allocated_storage'},
                                                  {'api':'al_create','parameter':'arena.release','kind':'allocator_release','return_policy':'void'}],
        ordering=[('al_create','al_decode'),('al_decode','al_destroy')],extra={'same_argument_storage':[{'left':['al_create','arena'],'right':['al_destroy','arena']}]}))

    specs.append(register('reference_counting','refcount ownership + conditional final release','''
typedef struct RcObj { unsigned refs; unsigned value; } RcObj;
RcObj *rc_new(unsigned value) { RcObj *p=malloc(sizeof(*p)); if(p) {p->refs=1;p->value=value;} return p; }
RcObj *rc_ref(RcObj *p) { if(p) p->refs++; return p; }
void rc_unref(RcObj *p) { if(p && --p->refs==0) free(p); }
RcObj *rc_parse(const unsigned char *data,size_t n) { return rc_new(n ? data[0] : 0); }
void rc_example(const unsigned char *d,size_t n) { RcObj *p=rc_parse(d,n); rc_unref(p); }
''','rc_parse',['rc_parse'],['rc_unref'],[resource('object','rc_parse','rc_unref',[])], [binding('rc_parse','data','n')],
        ordering=[('rc_parse','rc_unref')], counts={'rc_parse':1,'rc_unref':1},extra={'release_semantics':'decrement_one_reference; free_only_at_zero'}))

    specs.append(register('opaque_context','incomplete public type + private layout + creator arguments','''
#include "opaque.h"
struct HiddenParser { unsigned mode; };
HiddenParser *hidden_create(unsigned mode) { HiddenParser *p=malloc(sizeof(*p)); if(p) p->mode=mode; return p; }
int hidden_decode(HiddenParser *p,const unsigned char *bytes,size_t length) { return length ? (bytes[0]^p->mode)&255 : 0; }
void hidden_destroy(HiddenParser *p) { free(p); }
void hidden_example(const unsigned char *d,size_t n) { HiddenParser *p=hidden_create(0); if(p) {hidden_decode(p,d,n);hidden_destroy(p);} }
''','hidden_decode',['hidden_decode'],['hidden_create','hidden_destroy'],[resource('parser','hidden_create','hidden_destroy',[('hidden_decode','p')])],
        [binding('hidden_decode','bytes','length')],ordering=[('hidden_create','hidden_decode'),('hidden_decode','hidden_destroy')],extra={'opaque_requires_creator':True}))
    opaque=ROOT/specs[-1]['source_dir'];(opaque/'opaque.h').write_text('#include <stddef.h>\ntypedef struct HiddenParser HiddenParser;\nHiddenParser *hidden_create(unsigned mode);\nint hidden_decode(HiddenParser *p,const unsigned char *bytes,size_t length);\nvoid hidden_destroy(HiddenParser *p);\n')
    specs[-1]['headers']=['opaque.h']

    specs.append(register('callback_setter','setter registration + function pointer argument','''
typedef int (*ScNotify)(void *user,unsigned byte);
typedef struct ScParser { ScNotify notify; void *user; } ScParser;
ScParser *sc_create(void) { ScParser *p=malloc(sizeof(*p)); if(p) {p->notify=NULL;p->user=NULL;} return p; }
void sc_set_reader(ScParser *p,ScNotify notify,void *user) { p->notify=notify;p->user=user; }
int sc_parse(ScParser *p,const unsigned char *data,size_t size) {
    if(!p->notify) return -1; if(size) return p->notify(p->user,data[0]); return 0;
}
void sc_destroy(ScParser *p) { free(p); }
static int sc_sink(void *u,unsigned b) { (void)u;(void)b;return 0; }
void sc_example(const unsigned char *d,size_t n) { ScParser *p=sc_create(); if(!p)return;sc_set_reader(p,sc_sink,NULL);sc_parse(p,d,n);sc_destroy(p); }
''','sc_parse',['sc_parse'],['sc_create','sc_set_reader','sc_destroy'],[resource('parser','sc_create','sc_destroy',[('sc_set_reader','p'),('sc_parse','p')])],
        [binding('sc_parse','data','size')],callbacks=[{'api':'sc_parse','parameter':'p.notify','registration_api':'sc_set_reader','kind':'notification','return_policy':'zero_allowed'}],
        ordering=[('sc_create','sc_set_reader'),('sc_set_reader','sc_parse'),('sc_parse','sc_destroy')]))

    specs.append(register('nested_callback_table','two-level field path + multiple callback ABIs','''
typedef int (*DeepRead)(void *u,const unsigned char *p,size_t n);
typedef long (*DeepSeek)(void *u,long offset);
struct DeepReader { DeepRead read; DeepSeek seek; };
typedef struct DeepIO { struct DeepReader reader; void *userdata; } DeepIO;
int deep_parse(DeepIO *io,const unsigned char *bytes,size_t size) {
    if(!io->reader.read || !io->reader.seek) return -1;
    if(io->reader.seek(io->userdata,0)<0) return -2;
    return io->reader.read(io->userdata,bytes,size);
}
''','deep_parse',['deep_parse'],[],[],[binding('deep_parse','bytes','size')],
        callbacks=[{'api':'deep_parse','parameter':'io.reader.read','kind':'notification','return_policy':'zero_allowed'},
                   {'api':'deep_parse','parameter':'io.reader.seek','kind':'seek','return_policy':'nonnegative'}],extra={'public_storage':[{'api':'deep_parse','parameter':'io','type':'DeepIO','initialization':'all_callback_fields'}]}))

    specs.append(register('pull_callback','callback supplies input + cursor lifetime','''
typedef size_t (*PlRead)(void *opaque,unsigned char *out,size_t capacity);
typedef struct PlParser { PlRead read; void *opaque; } PlParser;
typedef struct PlCursor { const unsigned char *data; size_t size; size_t position; } PlCursor;
PlParser *pl_open(PlRead read,void *opaque) { if(!read) return NULL;PlParser *p=malloc(sizeof(*p));if(p){p->read=read;p->opaque=opaque;}return p; }
int pl_parse(PlParser *p) { unsigned char out[8];unsigned sum=0;size_t n;while((n=p->read(p->opaque,out,sizeof(out)))!=0){if(n>sizeof(out))return -1;for(size_t i=0;i<n;i++)sum+=out[i];}return sum&255; }
void pl_close(PlParser *p) { free(p); }
size_t pl_memory_read(void *opaque,unsigned char *out,size_t capacity) { PlCursor *c=opaque;size_t n=c->size-c->position;if(n>capacity)n=capacity;if(n)memcpy(out,c->data+c->position,n);c->position+=n;return n; }
void pl_example(const unsigned char *d,size_t n) { PlCursor c={d,n,0};PlParser *p=pl_open(pl_memory_read,&c);if(p){pl_parse(p);pl_close(p);} }
''','pl_parse',['pl_parse'],['pl_open','pl_close'],[resource('parser','pl_open','pl_close',[('pl_parse','p')])],
        [binding('pl_parse','p',source='callback',via='pl_open')],callbacks=[{'api':'pl_open','parameter':'read','kind':'input_reader','return_policy':'bounded_bytes_then_eof','fuzz_input_required':True}],
        ordering=[('pl_open','pl_parse'),('pl_parse','pl_close')],extra={'callback_userdata_lifetime':'through_parse','input_reader_cannot_be_zero_stub':True}))

    specs.append(register('repeated_feeds','repeated state transition + finish protocol','''
typedef struct MfParser { unsigned parts; unsigned sum; } MfParser;
MfParser *mf_begin(void) { return calloc(1,sizeof(MfParser)); }
void mf_feed(MfParser *p,const unsigned char *bytes,size_t length) { p->parts++;for(size_t i=0;i<length;i++)p->sum+=bytes[i]; }
int mf_finish(MfParser *p) { if(p->parts!=2)return -1;return p->sum&255; }
void mf_end(MfParser *p) { free(p); }
void mf_example(const unsigned char *d,size_t n) { MfParser *p=mf_begin();if(!p)return;size_t m=n/2;mf_feed(p,d,m);mf_feed(p,d+m,n-m);mf_finish(p);mf_end(p); }
''','mf_finish',['mf_feed','mf_finish'],['mf_begin','mf_end'],[resource('parser','mf_begin','mf_end',[('mf_feed','p'),('mf_finish','p')])],
        [binding('mf_feed','bytes','length'),binding('mf_finish','p',source='context',via='mf_feed')],
        ordering=[('mf_begin','mf_feed'),('mf_feed','mf_finish'),('mf_finish','mf_end')],counts={'mf_feed':2,'mf_finish':1},extra={'feeds_cover_input_exactly_once':True}))

    specs.append(register('simultaneous_resources','two same-type instances + independent identity','''
typedef struct TwState { const unsigned char *data; size_t size; } TwState;
TwState *tw_make(void) { return calloc(1,sizeof(TwState)); }
void tw_fill(TwState *s,const unsigned char *data,size_t size) { s->data=data;s->size=size; }
int tw_compare(TwState *left,TwState *right) { if(left==right)return -1;return (left->size?left->data[0]:0)^(right->size?right->data[0]:0); }
void tw_drop(TwState *s) { free(s); }
void tw_example(const unsigned char *d,size_t n) { TwState *a=tw_make();TwState *b=tw_make();if(a&&b){tw_fill(a,d,n);tw_fill(b,d,n);tw_compare(a,b);}tw_drop(a);tw_drop(b); }
''','tw_compare',['tw_fill','tw_compare'],['tw_make','tw_drop'],
        [resource('left','tw_make','tw_drop',[('tw_compare','left')]),resource('right','tw_make','tw_drop',[('tw_compare','right')])],
        [binding('tw_fill','data','size'),binding('tw_compare','left',source='context',via='tw_fill'),binding('tw_compare','right',source='context',via='tw_fill')],
        ordering=[('tw_make','tw_fill'),('tw_fill','tw_compare'),('tw_compare','tw_drop')],counts={'tw_make':2,'tw_fill':2,'tw_drop':2},extra={'distinct_resources':[['left','right']]}))

    specs.append(register('memory_stream','in-memory stream object + pull API','''
typedef struct SvStream { const unsigned char *data;size_t size;size_t position; } SvStream;
SvStream *sv_open_memory(const unsigned char *data,size_t size) { SvStream *s=malloc(sizeof(*s));if(s){s->data=data;s->size=size;s->position=0;}return s; }
size_t sv_read(SvStream *s,unsigned char *out,size_t capacity) { size_t n=s->size-s->position;if(n>capacity)n=capacity;if(n)memcpy(out,s->data+s->position,n);s->position+=n;return n; }
int sv_parse_stream(SvStream *s) { unsigned char buf[4];unsigned sum=0;size_t n;while((n=sv_read(s,buf,sizeof(buf))))for(size_t i=0;i<n;i++)sum+=buf[i];return sum&255; }
void sv_close(SvStream *s) { free(s); }
void sv_example(const unsigned char *d,size_t n) { SvStream *s=sv_open_memory(d,n);if(s){sv_parse_stream(s);sv_close(s);} }
''','sv_parse_stream',['sv_open_memory','sv_parse_stream'],['sv_close'],[resource('stream','sv_open_memory','sv_close',[('sv_parse_stream','s')])],
        [binding('sv_open_memory','data','size'),binding('sv_parse_stream','s',source='context',via='sv_open_memory')],
        ordering=[('sv_open_memory','sv_parse_stream'),('sv_parse_stream','sv_close')]))
    (ROOT/'synthetic_manifest.json').write_text(json.dumps({'schema_version':1,'set':'blind_synthetic','selected_before_native_calls':True,'cases':specs},indent=2)+'\n')


if __name__ == '__main__':
    main()
