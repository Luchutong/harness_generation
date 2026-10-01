#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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
