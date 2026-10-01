#include "source/api.h"
#include <stdlib.h>
#include <string.h>
struct Cursor{const unsigned char*b;size_t n,pos;};static ptrdiff_t read_bytes(void*s,unsigned char*d,size_t cap){struct Cursor*c=s;size_t n=c->n-c->pos;if(n>cap)n=cap;memcpy(d,c->b+c->pos,n);c->pos+=n;return (ptrdiff_t)n;}static void run(const unsigned char*b,size_t n){struct Cursor c={b,n,0};SrReader*r=sr_open(read_bytes,&c);if(r){sr_parse(r);sr_close(r);}}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
