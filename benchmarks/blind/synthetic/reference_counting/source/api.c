#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct RcObj { unsigned refs; unsigned value; } RcObj;
RcObj *rc_new(unsigned value) { RcObj *p=malloc(sizeof(*p)); if(p) {p->refs=1;p->value=value;} return p; }
RcObj *rc_ref(RcObj *p) { if(p) p->refs++; return p; }
void rc_unref(RcObj *p) { if(p && --p->refs==0) free(p); }
RcObj *rc_parse(const unsigned char *data,size_t n) { return rc_new(n ? data[0] : 0); }
void rc_example(const unsigned char *d,size_t n) { RcObj *p=rc_parse(d,n); rc_unref(p); }
