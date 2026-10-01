#include "api.h"
#include <stdlib.h>
#include <string.h>
struct PsSession {unsigned salt;unsigned valid;};
PsSession *ps_start(const char *name){PsSession*s=malloc(sizeof(*s));if(s){s->salt=name?(unsigned)strlen(name):0;s->valid=31;}return s;}
int ps_decode(PsSession *session,const unsigned char *data,size_t size){if(!session||session->valid!=31)return -1;unsigned v=session->salt;for(size_t i=0;i<size;i++)v^=data[i];return (int)(v&255);}
void ps_stop(PsSession *session){free(session);}
