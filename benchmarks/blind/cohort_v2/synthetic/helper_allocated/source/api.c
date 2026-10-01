#include "api.h"
#include <stdlib.h>
#include <string.h>
struct HaState {unsigned sum;unsigned initialized;unsigned feeds;};
static void *ha_memory(size_t n){return malloc(n);}
static void ha_defaults(HaState*p){p->initialized=27;p->sum=17;}
HaState *ha_construct(void){HaState*p=ha_memory(sizeof(*p));if(p){memset(p,0,sizeof(*p));ha_defaults(p);}return p;}
int ha_append(HaState *state,const unsigned char *data,size_t size){if(!state||state->initialized!=27)return -1;for(size_t i=0;i<size;i++)state->sum+=data[i];state->feeds++;return 0;}
int ha_finish(HaState *state){if(!state||state->initialized!=27||!state->feeds)return -1;return (int)(state->sum&255);}
void ha_destruct(HaState *state){free(state);}
