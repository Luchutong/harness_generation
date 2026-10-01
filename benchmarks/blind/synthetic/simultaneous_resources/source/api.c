#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct TwState { const unsigned char *data; size_t size; } TwState;
TwState *tw_make(void) { return calloc(1,sizeof(TwState)); }
void tw_fill(TwState *s,const unsigned char *data,size_t size) { s->data=data;s->size=size; }
int tw_compare(TwState *left,TwState *right) { if(left==right)return -1;return (left->size?left->data[0]:0)^(right->size?right->data[0]:0); }
void tw_drop(TwState *s) { free(s); }
void tw_example(const unsigned char *d,size_t n) { TwState *a=tw_make();TwState *b=tw_make();if(a&&b){tw_fill(a,d,n);tw_fill(b,d,n);tw_compare(a,b);}tw_drop(a);tw_drop(b); }
