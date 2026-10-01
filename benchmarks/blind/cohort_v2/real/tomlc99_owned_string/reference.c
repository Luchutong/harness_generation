#include "source/toml.h"
#include <stdlib.h>
#include <string.h>
static void run(const unsigned char*b,size_t n){char*s=malloc(n+1);if(!s)return;memcpy(s,b,n);s[n]=0;char err[128];toml_table_t*t=toml_parse(s,err,sizeof(err));if(t)toml_free(t);free(s);}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
