#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct MfParser { unsigned parts; unsigned sum; } MfParser;
MfParser *mf_begin(void) { return calloc(1,sizeof(MfParser)); }
void mf_feed(MfParser *p,const unsigned char *bytes,size_t length) { p->parts++;for(size_t i=0;i<length;i++)p->sum+=bytes[i]; }
int mf_finish(MfParser *p) { if(p->parts!=2)return -1;return p->sum&255; }
void mf_end(MfParser *p) { free(p); }
void mf_example(const unsigned char *d,size_t n) { MfParser *p=mf_begin();if(!p)return;size_t m=n/2;mf_feed(p,d,m);mf_feed(p,d+m,n-m);mf_finish(p);mf_end(p); }
