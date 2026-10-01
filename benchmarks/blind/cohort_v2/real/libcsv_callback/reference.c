#include "source/csv.h"
#include <stdlib.h>
#include <string.h>
static void field(void*s,size_t n,void*u){(void)s;(void)n;(void)u;}static void row(int c,void*u){(void)c;(void)u;}static void run(const unsigned char*b,size_t n){struct csv_parser p;if(!csv_init(&p,0)){csv_parse(&p,b,n,field,row,NULL);csv_free(&p);}}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
