#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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
