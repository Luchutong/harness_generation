#include "source/api.h"
#include <stdlib.h>
#include <string.h>
static void*alloc(void*c,size_t n){(void)c;return malloc(n);}static void release(void*c,void*p){(void)c;free(p);}static void run(const unsigned char*b,size_t n){SaAllocator a={alloc,release,NULL};SaParser*p=sa_open(&a);if(p){sa_parse(p,b,n);sa_close(p);}}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
