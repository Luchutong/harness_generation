#include "source/mpack/mpack.h"
#include <stdlib.h>
#include <string.h>
static void run(const unsigned char*b,size_t n){mpack_tree_t t;mpack_tree_init_data(&t,(const char*)b,n);mpack_tree_parse(&t);mpack_tree_destroy(&t);}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
