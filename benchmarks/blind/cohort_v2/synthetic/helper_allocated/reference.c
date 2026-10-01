#include "source/api.h"
#include <stdlib.h>
#include <string.h>
static void run(const unsigned char*b,size_t n){HaState*p=ha_construct();if(p){ha_append(p,b,n);ha_finish(p);ha_destruct(p);}}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
