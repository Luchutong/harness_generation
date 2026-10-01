#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {SvStream *p=sv_open_memory(data,n);if(p){sv_parse_stream(p);sv_close(p);}}return 0;}
