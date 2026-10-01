#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {RcObj *p=rc_parse(data,n);rc_unref(p);}return 0;}
