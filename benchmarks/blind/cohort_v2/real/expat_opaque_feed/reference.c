#include "source/expat.h"
#include <stdlib.h>
#include <string.h>
static void run(const unsigned char*b,size_t n){XML_Parser p=XML_ParserCreate(NULL);if(p){XML_Parse(p,(const char*)b,(int)n,1);XML_ParserFree(p);}}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
