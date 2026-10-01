#include "source/api.h"
#include <stdlib.h>
#include <string.h>
static void run(const unsigned char*b,size_t n){BxConfig c={0,0};unsigned status;BxDecoder*p=bx_open(&c,&status);if(p){bx_decode(p,b,n);bx_close(p);}}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
