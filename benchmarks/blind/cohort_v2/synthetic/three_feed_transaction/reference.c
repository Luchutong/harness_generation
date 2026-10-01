#include "source/api.h"
#include <stdlib.h>
#include <string.h>
static void run(const unsigned char*b,size_t n){TfTransaction*t=tf_begin();if(t){size_t q=n/3;tf_feed(t,b,q);tf_feed(t,b+q,q);tf_feed(t,b+2*q,n-2*q);tf_commit(t);tf_end(t);}}
int main(void){unsigned char b[256];for(size_t i=0;i<256;i++)b[i]=(unsigned char)i;for(size_t n=0;n<=256;n++)run(b,n);return 0;}
