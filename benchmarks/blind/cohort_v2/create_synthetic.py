"""New semantic structures after the invalidated infrastructure pilot.

No fixture or annotation is imported by production or native workers. Public
headers document API preconditions; expected annotations/reference programs
remain outside each indexed source directory.
"""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
CASES=[]
COMMON='#include "api.h"\n#include <stdlib.h>\n#include <string.h>\n'


def resource(label,creator,consumers,cleanup,parameter=None):
    return {'id':label,'origin':{'api':creator,'kind':'out_parameter' if parameter else 'return','parameter':parameter},
            'consumers':[{'api':a,'parameter':p} for a,p in consumers],
            'cleanup':cleanup,'ownership':'owned','scope':'per_input'}


def own(api,param=None,kind='owned',release=None):
    return {'api':api,'parameter':param,'return_value':param is None,'ownership':kind,'release_api':release}


def binding(api,param,length=None,source='fuzz_data',via=None):
    return {'api':api,'parameter':param,'source':source,'size_parameter':length,'via_api':via}


def cb(api,param,kind='notification',policy='zero_allowed',**extra):
    return {'api':api,'parameter':param,'kind':kind,'return_policy':policy,**extra}


def add(case,dimension,anchor,header,body,reference,*,core=None,support=(),resources=(),inputs=(),ownership=(),callbacks=(),ordering=(),counts=None,constraints=None):
    directory=ROOT/'synthetic'/case;source=directory/'source';source.mkdir(parents=True,exist_ok=False)
    (source/'api.h').write_text('#ifndef BLIND_API_H\n#define BLIND_API_H\n#include <stddef.h>\n#include <stdint.h>\n#ifdef __cplusplus\nextern "C" {\n#endif\n'+header+'\n#ifdef __cplusplus\n}\n#endif\n#endif\n')
    (source/'api.c').write_text(COMMON+body+'\n')
    (directory/'reference.c').write_text('#include "source/api.h"\n#include <stdlib.h>\n#include <string.h>\n'+reference+'\nint main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}\n')
    truth={'schema_version':1,'annotation_kind':'independent_manual_contract','id':case,'core_apis':core or [anchor],
        'required_support':list(support),'resources':list(resources),'input_binding':list(inputs),'ownership':list(ownership),
        'callback':list(callbacks),'ordering':[{'before':a,'after':b} for a,b in ordering],
        'invocation_counts':counts or {},'mandatory_constraints':constraints or {},
        'adjudication':'independent source/API contract; metadata missing or alternatives unproved remain unverified; source/ contains no expected annotations'}
    (directory/'ground_truth.json').write_text(json.dumps(truth,indent=2)+'\n')
    CASES.append({'id':case,'set':'blind_synthetic','semantic_dimension':dimension,'source_dir':f'synthetic/{case}/source',
        'anchor':anchor,'sources':['api.c'],'headers':['api.h'],'include_paths':['.'],'compiler_flags':['-std=c11'],'link_flags':[]})


def main():
    add('configured_decoder','creator args + output status + private configuration','bx_decode',
        '''typedef struct BxDecoder BxDecoder;
typedef struct BxConfig { size_t maximum; unsigned mode; } BxConfig;
/* Decoder objects must originate from bx_open; config storage is borrowed. */
BxDecoder *bx_open(const BxConfig *config,unsigned *status);
int bx_decode(BxDecoder *decoder,const unsigned char *bytes,size_t count);
void bx_close(BxDecoder *decoder);''',
        '''struct BxDecoder {size_t maximum;unsigned mode;unsigned magic;};
BxDecoder *bx_open(const BxConfig *config,unsigned *status){if(status)*status=1;if(!config||config->mode>3)return NULL;BxDecoder*p=malloc(sizeof(*p));if(!p)return NULL;p->maximum=config->maximum?config->maximum:4096;p->mode=config->mode;p->magic=43;if(status)*status=0;return p;}
int bx_decode(BxDecoder *decoder,const unsigned char *bytes,size_t count){if(!decoder||decoder->magic!=43)return -2;if(count>decoder->maximum)return -1;unsigned n=decoder->mode;for(size_t i=0;i<count;i++)n+=bytes[i];return (int)(n&255);}
void bx_close(BxDecoder *decoder){free(decoder);}''',
        'static void run(const unsigned char*b,size_t n){BxConfig c={0,0};unsigned status;BxDecoder*p=bx_open(&c,&status);if(p){bx_decode(p,b,n);bx_close(p);}}',
        support=['bx_open','bx_close'],resources=[resource('decoder','bx_open',[('bx_decode','decoder'),('bx_close','decoder')],'bx_close')],
        inputs=[binding('bx_decode','bytes','count')],ownership=[own('bx_open',release='bx_close'),own('bx_decode','decoder','borrowed')],
        ordering=[('bx_open','bx_decode'),('bx_decode','bx_close')],constraints={'non_null_arguments':[{'api':'bx_open','parameter':'config'}],'creator_only':True})

    add('output_handle','out-parameter + failure-cleared output + capacity','oh_ingest',
        '''typedef struct OhHandle OhHandle;
int oh_acquire(OhHandle **output,size_t capacity);
int oh_ingest(OhHandle *handle,const void *payload,size_t bytes);
void oh_release(OhHandle *handle);''',
        '''struct OhHandle {size_t capacity;unsigned tag;};
int oh_acquire(OhHandle **output,size_t capacity){if(!output)return -1;*output=NULL;if(capacity>4096)return -1;OhHandle*h=malloc(sizeof(*h));if(!h)return -1;h->capacity=capacity?capacity:4096;h->tag=9;*output=h;return 0;}
int oh_ingest(OhHandle *handle,const void *payload,size_t bytes){if(!handle||handle->tag!=9)return -2;if(bytes>handle->capacity)return -1;const unsigned char*p=payload;unsigned n=0;for(size_t i=0;i<bytes;i++)n^=p[i];return (int)n;}
void oh_release(OhHandle *handle){free(handle);}''',
        'static void run(const unsigned char*b,size_t n){OhHandle*h=NULL;if(!oh_acquire(&h,n)){oh_ingest(h,b,n);oh_release(h);}}',
        support=['oh_acquire','oh_release'],resources=[resource('handle','oh_acquire',[('oh_ingest','handle'),('oh_release','handle')],'oh_release','output')],
        inputs=[binding('oh_ingest','payload','bytes')],ownership=[own('oh_acquire','output','borrowed'),own('oh_ingest','handle','borrowed')],
        ordering=[('oh_acquire','oh_ingest'),('oh_ingest','oh_release')],constraints={'non_null_arguments':[{'api':'oh_acquire','parameter':'output'}],'creator_only':True})

    add('helper_allocated','helper malloc + helper initialization + copied feed','ha_finish',
        '''typedef struct HaState HaState;
HaState *ha_construct(void);
int ha_append(HaState *state,const unsigned char *data,size_t size);
int ha_finish(HaState *state);
void ha_destruct(HaState *state);''',
        '''struct HaState {unsigned sum;unsigned initialized;unsigned feeds;};
static void *ha_memory(size_t n){return malloc(n);}
static void ha_defaults(HaState*p){p->initialized=27;p->sum=17;}
HaState *ha_construct(void){HaState*p=ha_memory(sizeof(*p));if(p){memset(p,0,sizeof(*p));ha_defaults(p);}return p;}
int ha_append(HaState *state,const unsigned char *data,size_t size){if(!state||state->initialized!=27)return -1;for(size_t i=0;i<size;i++)state->sum+=data[i];state->feeds++;return 0;}
int ha_finish(HaState *state){if(!state||state->initialized!=27||!state->feeds)return -1;return (int)(state->sum&255);}
void ha_destruct(HaState *state){free(state);}''',
        'static void run(const unsigned char*b,size_t n){HaState*p=ha_construct();if(p){ha_append(p,b,n);ha_finish(p);ha_destruct(p);}}',
        core=['ha_append','ha_finish'],support=['ha_construct','ha_destruct'],resources=[resource('state','ha_construct',[('ha_append','state'),('ha_finish','state'),('ha_destruct','state')],'ha_destruct')],
        inputs=[binding('ha_append','data','size')],ownership=[own('ha_construct',release='ha_destruct'),own('ha_append','state','borrowed'),own('ha_finish','state','borrowed')],
        ordering=[('ha_construct','ha_append'),('ha_append','ha_finish'),('ha_finish','ha_destruct')],constraints={'creator_only':True})

    add('saved_allocator','custom allocator copied into resource + callback release','sa_parse',
        '''typedef struct SaParser SaParser;
typedef struct SaAllocator {void *(*allocate)(void *cookie,size_t size);void (*release)(void *cookie,void *memory);void *cookie;} SaAllocator;
SaParser *sa_open(const SaAllocator *allocator);
int sa_parse(SaParser *parser,const unsigned char *data,size_t length);
void sa_close(SaParser *parser);''',
        '''struct SaParser {SaAllocator allocator;unsigned tag;};
SaParser *sa_open(const SaAllocator *allocator){if(!allocator||!allocator->allocate||!allocator->release)return NULL;SaParser*p=allocator->allocate(allocator->cookie,sizeof(*p));if(p){p->allocator=*allocator;p->tag=19;}return p;}
int sa_parse(SaParser *parser,const unsigned char *data,size_t length){if(!parser||parser->tag!=19)return -1;unsigned v=0;for(size_t i=0;i<length;i++)v+=data[i];return (int)(v&255);}
void sa_close(SaParser *parser){if(parser){SaAllocator a=parser->allocator;a.release(a.cookie,parser);}}''',
        'static void*alloc(void*c,size_t n){(void)c;return malloc(n);}static void release(void*c,void*p){(void)c;free(p);}static void run(const unsigned char*b,size_t n){SaAllocator a={alloc,release,NULL};SaParser*p=sa_open(&a);if(p){sa_parse(p,b,n);sa_close(p);}}',
        support=['sa_open','sa_close'],resources=[resource('parser','sa_open',[('sa_parse','parser'),('sa_close','parser')],'sa_close')],
        inputs=[binding('sa_parse','data','length')],ownership=[own('sa_open',release='sa_close'),own('sa_parse','parser','borrowed')],
        callbacks=[cb('sa_open','allocator.allocate','allocator','non_null_memory'),cb('sa_open','allocator.release','allocator','void')],
        ordering=[('sa_open','sa_parse'),('sa_parse','sa_close')],constraints={'creator_only':True,'allocation_release_pair_required':True})

    add('aliased_refcount','owned returned reference aliases input object + double unref','ar_decode',
        '''typedef struct ArObject ArObject;
ArObject *ar_new(void);
ArObject *ar_retain(ArObject *object);
ArObject *ar_decode(ArObject *object,const unsigned char *bytes,size_t count);
void ar_unref(ArObject *object);''',
        '''struct ArObject {unsigned references;unsigned value;};
ArObject *ar_new(void){ArObject*p=malloc(sizeof(*p));if(p){p->references=1;p->value=0;}return p;}
ArObject *ar_retain(ArObject *object){if(object)object->references++;return object;}
ArObject *ar_decode(ArObject *object,const unsigned char *bytes,size_t count){if(!object)return NULL;for(size_t i=0;i<count;i++)object->value+=bytes[i];return ar_retain(object);}
void ar_unref(ArObject *object){if(object&&!--object->references)free(object);}''',
        'static void run(const unsigned char*b,size_t n){ArObject*p=ar_new();if(p){ArObject*q=ar_decode(p,b,n);ar_unref(q);ar_unref(p);}}',
        support=['ar_new','ar_unref'],resources=[resource('original','ar_new',[('ar_decode','object'),('ar_unref','object')],'ar_unref'),resource('returned_reference','ar_decode',[('ar_unref','object')],'ar_unref')],
        inputs=[binding('ar_decode','bytes','count')],ownership=[own('ar_new',release='ar_unref'),own('ar_decode',release='ar_unref'),own('ar_decode','object','borrowed')],
        ordering=[('ar_new','ar_decode'),('ar_decode','ar_unref')],counts={'ar_unref':2},constraints={'return_aliases_input_but_owns_new_reference':True,'creator_only':True})

    add('private_session','opaque layout + creator name argument + internal state','ps_decode',
        '''typedef struct PsSession PsSession;
PsSession *ps_start(const char *name);
int ps_decode(PsSession *session,const unsigned char *data,size_t size);
void ps_stop(PsSession *session);''',
        '''struct PsSession {unsigned salt;unsigned valid;};
PsSession *ps_start(const char *name){PsSession*s=malloc(sizeof(*s));if(s){s->salt=name?(unsigned)strlen(name):0;s->valid=31;}return s;}
int ps_decode(PsSession *session,const unsigned char *data,size_t size){if(!session||session->valid!=31)return -1;unsigned v=session->salt;for(size_t i=0;i<size;i++)v^=data[i];return (int)(v&255);}
void ps_stop(PsSession *session){free(session);}''',
        'static void run(const unsigned char*b,size_t n){PsSession*s=ps_start(NULL);if(s){ps_decode(s,b,n);ps_stop(s);}}',
        support=['ps_start','ps_stop'],resources=[resource('session','ps_start',[('ps_decode','session'),('ps_stop','session')],'ps_stop')],
        inputs=[binding('ps_decode','data','size')],ownership=[own('ps_start',release='ps_stop'),own('ps_decode','session','borrowed')],
        ordering=[('ps_start','ps_decode'),('ps_decode','ps_stop')],constraints={'creator_only':True,'public_layout_incomplete':True})

    add('registration_object','setter takes registration object + private parser state','ro_parse',
        '''typedef struct RoParser RoParser;
typedef struct RoRegistration {void (*on_byte)(void *cookie,unsigned byte);void *cookie;} RoRegistration;
RoParser *ro_create(void);
void ro_register(RoParser *parser,const RoRegistration *registration);
int ro_parse(RoParser *parser,const unsigned char *data,size_t size);
void ro_destroy(RoParser *parser);''',
        '''struct RoParser {RoRegistration handler;unsigned ready;};
RoParser *ro_create(void){RoParser*p=malloc(sizeof(*p));if(p){memset(p,0,sizeof(*p));p->ready=7;}return p;}
void ro_register(RoParser *parser,const RoRegistration *registration){if(parser&&registration)parser->handler=*registration;}
int ro_parse(RoParser *parser,const unsigned char *data,size_t size){if(!parser||parser->ready!=7||!parser->handler.on_byte)return -1;for(size_t i=0;i<size;i++)parser->handler.on_byte(parser->handler.cookie,data[i]);return 0;}
void ro_destroy(RoParser *parser){free(parser);}''',
        'static void notify(void*c,unsigned v){(void)c;(void)v;}static void run(const unsigned char*b,size_t n){RoRegistration r={notify,NULL};RoParser*p=ro_create();if(p){ro_register(p,&r);ro_parse(p,b,n);ro_destroy(p);}}',
        support=['ro_create','ro_register','ro_destroy'],resources=[resource('parser','ro_create',[('ro_register','parser'),('ro_parse','parser'),('ro_destroy','parser')],'ro_destroy')],
        inputs=[binding('ro_parse','data','size')],ownership=[own('ro_create',release='ro_destroy'),own('ro_parse','parser','borrowed')],
        callbacks=[cb('ro_register','registration.on_byte',policy='void',registration_api='ro_register')],
        ordering=[('ro_create','ro_register'),('ro_register','ro_parse'),('ro_parse','ro_destroy')],constraints={'creator_only':True})

    add('three_level_callbacks','three nested layout levels + void notification callback','tc_decode',
        '''typedef struct TcCallbacks {struct Transport {struct Receiver {void (*consume)(void *state,unsigned byte);void *state;} receiver;} transport;} TcCallbacks;
int tc_decode(const TcCallbacks *callbacks,const unsigned char *bytes,size_t size);''',
        '''int tc_decode(const TcCallbacks *callbacks,const unsigned char *bytes,size_t size){if(!callbacks||!callbacks->transport.receiver.consume)return -1;for(size_t i=0;i<size;i++)callbacks->transport.receiver.consume(callbacks->transport.receiver.state,bytes[i]);return 0;}''',
        'static void consume(void*s,unsigned b){(void)s;(void)b;}static void run(const unsigned char*b,size_t n){TcCallbacks c={0};c.transport.receiver.consume=consume;tc_decode(&c,b,n);}',
        inputs=[binding('tc_decode','bytes','size')],ownership=[own('tc_decode','callbacks','borrowed')],
        callbacks=[cb('tc_decode','callbacks.transport.receiver.consume',policy='void')],constraints={'non_null_arguments':[{'api':'tc_decode','parameter':'callbacks'}]})

    add('signed_pull_reader','signed read result + retained callback context + EOF/error','sr_parse',
        '''typedef struct SrReader SrReader;
typedef ptrdiff_t (*SrRead)(void *state,unsigned char *destination,size_t capacity);
SrReader *sr_open(SrRead read,void *state);
int sr_parse(SrReader *reader);
void sr_close(SrReader *reader);''',
        '''struct SrReader {SrRead read;void *state;};
SrReader *sr_open(SrRead read,void *state){if(!read)return NULL;SrReader*r=malloc(sizeof(*r));if(r){r->read=read;r->state=state;}return r;}
int sr_parse(SrReader *reader){if(!reader)return -1;unsigned char buffer[17];unsigned sum=0;for(size_t turn=0;turn<4096;turn++){ptrdiff_t n=reader->read(reader->state,buffer,sizeof(buffer));if(n<0||n>(ptrdiff_t)sizeof(buffer))return -1;if(!n)break;for(ptrdiff_t i=0;i<n;i++)sum+=buffer[i];}return (int)(sum&255);}
void sr_close(SrReader *reader){free(reader);}''',
        'struct Cursor{const unsigned char*b;size_t n,pos;};static ptrdiff_t read_bytes(void*s,unsigned char*d,size_t cap){struct Cursor*c=s;size_t n=c->n-c->pos;if(n>cap)n=cap;memcpy(d,c->b+c->pos,n);c->pos+=n;return (ptrdiff_t)n;}static void run(const unsigned char*b,size_t n){struct Cursor c={b,n,0};SrReader*r=sr_open(read_bytes,&c);if(r){sr_parse(r);sr_close(r);}}',
        support=['sr_open','sr_close'],resources=[resource('reader','sr_open',[('sr_parse','reader'),('sr_close','reader')],'sr_close')],
        inputs=[binding('sr_parse','reader',source='callback',via='sr_open')],ownership=[own('sr_open',release='sr_close'),own('sr_parse','reader','borrowed')],
        callbacks=[cb('sr_open','read','reader','bounded_read_or_eof',fuzz_input_required=True)],ordering=[('sr_open','sr_parse'),('sr_parse','sr_close')],constraints={'creator_only':True,'reader_must_advance_input':True})

    add('three_feed_transaction','three required state transitions + independently chunked input','tf_commit',
        '''typedef struct TfTransaction TfTransaction;
TfTransaction *tf_begin(void);
int tf_feed(TfTransaction *transaction,const unsigned char *bytes,size_t size);
int tf_commit(TfTransaction *transaction);
void tf_end(TfTransaction *transaction);''',
        '''struct TfTransaction {unsigned phase;unsigned sum;};
TfTransaction *tf_begin(void){TfTransaction*t=malloc(sizeof(*t));if(t){t->phase=0;t->sum=0;}return t;}
int tf_feed(TfTransaction *transaction,const unsigned char *bytes,size_t size){if(!transaction||transaction->phase>=3)return -1;for(size_t i=0;i<size;i++)transaction->sum+=bytes[i];transaction->phase++;return 0;}
int tf_commit(TfTransaction *transaction){if(!transaction||transaction->phase!=3)return -1;return (int)(transaction->sum&255);}
void tf_end(TfTransaction *transaction){free(transaction);}''',
        'static void run(const unsigned char*b,size_t n){TfTransaction*t=tf_begin();if(t){size_t q=n/3;tf_feed(t,b,q);tf_feed(t,b+q,q);tf_feed(t,b+2*q,n-2*q);tf_commit(t);tf_end(t);}}',
        core=['tf_feed','tf_commit'],support=['tf_begin','tf_end'],resources=[resource('transaction','tf_begin',[('tf_feed','transaction'),('tf_commit','transaction'),('tf_end','transaction')],'tf_end')],
        inputs=[binding('tf_feed','bytes','size')],ownership=[own('tf_begin',release='tf_end'),own('tf_feed','transaction','borrowed'),own('tf_commit','transaction','borrowed')],
        ordering=[('tf_begin','tf_feed'),('tf_feed','tf_commit'),('tf_commit','tf_end')],counts={'tf_feed':3,'tf_commit':1},constraints={'creator_only':True,'three_feeds_before_commit':True})

    add('paired_snapshots','two same-type instances + different creator arguments + non-alias','sp_compare',
        '''typedef struct SpSnapshot SpSnapshot;
SpSnapshot *sp_new(unsigned seed);
void sp_feed(SpSnapshot *snapshot,const unsigned char *bytes,size_t count);
int sp_compare(const SpSnapshot *left,const SpSnapshot *right);
void sp_delete(SpSnapshot *snapshot);''',
        '''struct SpSnapshot {unsigned seed,sum,ready;};
SpSnapshot *sp_new(unsigned seed){SpSnapshot*s=malloc(sizeof(*s));if(s){s->seed=seed;s->sum=0;s->ready=0;}return s;}
void sp_feed(SpSnapshot *snapshot,const unsigned char *bytes,size_t count){if(!snapshot)return;for(size_t i=0;i<count;i++)snapshot->sum+=bytes[i];snapshot->ready=1;}
int sp_compare(const SpSnapshot *left,const SpSnapshot *right){if(!left||!right||left==right||!left->ready||!right->ready)return -1;return left->sum==right->sum;}
void sp_delete(SpSnapshot *snapshot){free(snapshot);}''',
        'static void run(const unsigned char*b,size_t n){SpSnapshot*a=sp_new(1),*c=sp_new(2);if(a&&c){sp_feed(a,b,n);sp_feed(c,b,n);sp_compare(a,c);}sp_delete(c);sp_delete(a);}',
        core=['sp_feed','sp_compare'],support=['sp_new','sp_delete'],resources=[resource('left','sp_new',[('sp_compare','left')],'sp_delete'),resource('right','sp_new',[('sp_compare','right')],'sp_delete')],
        inputs=[binding('sp_feed','bytes','count')],ownership=[own('sp_new',release='sp_delete'),own('sp_compare','left','borrowed'),own('sp_compare','right','borrowed')],
        ordering=[('sp_new','sp_feed'),('sp_feed','sp_compare'),('sp_compare','sp_delete')],counts={'sp_new':2,'sp_feed':2,'sp_compare':1,'sp_delete':2},constraints={'creator_only':True,'distinct_resources':[['left','right']]})

    add('out_memory_stream','out-parameter stream + separate memory binding + pull parser','ms_parse',
        '''typedef struct MsStream MsStream;
int ms_create(MsStream **output);
void ms_bind(MsStream *stream,const unsigned char *bytes,size_t length);
size_t ms_read(MsStream *stream,unsigned char *destination,size_t capacity);
int ms_parse(MsStream *stream);
void ms_destroy(MsStream *stream);''',
        '''struct MsStream {const unsigned char *bytes;size_t length,position;unsigned ready;};
int ms_create(MsStream **output){if(!output)return -1;*output=calloc(1,sizeof(MsStream));return *output?0:-1;}
void ms_bind(MsStream *stream,const unsigned char *bytes,size_t length){stream->bytes=bytes;stream->length=length;stream->position=0;stream->ready=1;}
size_t ms_read(MsStream *stream,unsigned char *destination,size_t capacity){size_t n=stream->length-stream->position;if(n>capacity)n=capacity;if(n)memcpy(destination,stream->bytes+stream->position,n);stream->position+=n;return n;}
int ms_parse(MsStream *stream){if(!stream||!stream->ready)return -1;unsigned char b[11];size_t n;unsigned sum=0;while((n=ms_read(stream,b,sizeof(b))))for(size_t i=0;i<n;i++)sum+=b[i];return (int)(sum&255);}
void ms_destroy(MsStream *stream){free(stream);}''',
        'static void run(const unsigned char*b,size_t n){MsStream*s=NULL;if(!ms_create(&s)){ms_bind(s,b,n);ms_parse(s);ms_destroy(s);}}',
        core=['ms_bind','ms_parse'],support=['ms_create','ms_destroy'],resources=[resource('stream','ms_create',[('ms_bind','stream'),('ms_parse','stream'),('ms_destroy','stream')],'ms_destroy','output')],
        inputs=[binding('ms_bind','bytes','length')],ownership=[own('ms_create','output','borrowed'),own('ms_bind','bytes','borrowed'),own('ms_parse','stream','borrowed')],
        ordering=[('ms_create','ms_bind'),('ms_bind','ms_parse'),('ms_parse','ms_destroy')],constraints={'non_null_arguments':[{'api':'ms_create','parameter':'output'}],'creator_only':True})
    (ROOT/'synthetic_manifest.json').write_text(json.dumps({'schema_version':1,'set':'blind_synthetic','cases':CASES},indent=2)+'\n')


if __name__=='__main__':main()
