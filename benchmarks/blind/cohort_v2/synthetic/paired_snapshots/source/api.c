#include "api.h"
#include <stdlib.h>
#include <string.h>
struct SpSnapshot {unsigned seed,sum,ready;};
SpSnapshot *sp_new(unsigned seed){SpSnapshot*s=malloc(sizeof(*s));if(s){s->seed=seed;s->sum=0;s->ready=0;}return s;}
void sp_feed(SpSnapshot *snapshot,const unsigned char *bytes,size_t count){if(!snapshot)return;for(size_t i=0;i<count;i++)snapshot->sum+=bytes[i];snapshot->ready=1;}
int sp_compare(const SpSnapshot *left,const SpSnapshot *right){if(!left||!right||left==right||!left->ready||!right->ready)return -1;return left->sum==right->sum;}
void sp_delete(SpSnapshot *snapshot){free(snapshot);}
