#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {ScParser *p=sc_create();if(p){sc_set_reader(p,sc_sink,NULL);sc_parse(p,data,n);sc_destroy(p);}}return 0;}
