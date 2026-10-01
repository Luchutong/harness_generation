#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {HcState *p=hc_create();if(p){hc_put(p,data,n);hc_process(p);hc_release(p);}}return 0;}
