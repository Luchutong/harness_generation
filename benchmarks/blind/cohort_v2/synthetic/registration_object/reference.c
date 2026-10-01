#include "source/api.h"
#include <stdlib.h>
#include <string.h>
static void notify(void*c,unsigned v){(void)c;(void)v;}static void run(const unsigned char*b,size_t n){RoRegistration r={notify,NULL};RoParser*p=ro_create();if(p){ro_register(p,&r);ro_parse(p,b,n);ro_destroy(p);}}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
