#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {PlCursor c={data,n,0};PlParser *p=pl_open(pl_memory_read,&c);if(p){pl_parse(p);pl_close(p);}}return 0;}
