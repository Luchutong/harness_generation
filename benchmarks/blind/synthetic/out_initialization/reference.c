#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {OpOptions o={0};OpState *p=NULL;if(op_initialize(&p,&o)==0){op_feed(p,data,n);op_dispose(p);}}return 0;}
