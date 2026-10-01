#include "source/api.c"
static int ref_read(void *u,const unsigned char *p,size_t n){(void)u;return n ? p[0] : 0;}
static long ref_seek(void *u,long o){(void)u;return o;}
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {DeepIO io={{ref_read,ref_seek},NULL};deep_parse(&io,data,n);}return 0;}
