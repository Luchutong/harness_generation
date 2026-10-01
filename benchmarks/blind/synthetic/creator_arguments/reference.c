#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {DcOptions o={0};DcCtx *p=dc_open(&o,0);if(p){dc_decode(p,data,n);dc_close(p);}}return 0;}
