#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {MfParser *p=mf_begin();if(p){size_t m=n/2;mf_feed(p,data,m);mf_feed(p,data+m,n-m);mf_finish(p);mf_end(p);}}return 0;}
