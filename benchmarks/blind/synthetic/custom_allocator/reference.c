#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {Arena a={al_heap,al_free,NULL};AlParser *p=al_create(&a);if(p){al_decode(p,data,n);al_destroy(p,&a);}}return 0;}
