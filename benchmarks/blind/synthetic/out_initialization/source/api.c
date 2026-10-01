#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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
