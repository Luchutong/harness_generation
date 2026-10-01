#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {HiddenParser *p=hidden_create(0);if(p){hidden_decode(p,data,n);hidden_destroy(p);}}return 0;}
