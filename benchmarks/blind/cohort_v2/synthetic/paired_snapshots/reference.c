#include "source/api.h"
#include <stdlib.h>
#include <string.h>
static void run(const unsigned char*b,size_t n){SpSnapshot*a=sp_new(1),*c=sp_new(2);if(a&&c){sp_feed(a,b,n);sp_feed(c,b,n);sp_compare(a,c);}sp_delete(c);sp_delete(a);}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
