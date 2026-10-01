#include "source/api.c"
int main(void){unsigned char data[256];for(unsigned i=0;i<256;i++)data[i]=(unsigned char)i;for(size_t n=0;n<=256;n++) {TwState *a=tw_make(),*c=tw_make();if(a&&c){tw_fill(a,data,n);tw_fill(c,data,n);tw_compare(a,c);}tw_drop(a);tw_drop(c);}return 0;}
