#include "source/api.h"
#include <stdlib.h>
#include <string.h>
static void consume(void*s,unsigned b){(void)s;(void)b;}static void run(const unsigned char*b,size_t n){TcCallbacks c={0};c.transport.receiver.consume=consume;tc_decode(&c,b,n);}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
