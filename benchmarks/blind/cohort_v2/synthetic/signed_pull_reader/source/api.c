#include "api.h"
#include <stdlib.h>
#include <string.h>
struct SrReader {SrRead read;void *state;};
SrReader *sr_open(SrRead read,void *state){if(!read)return NULL;SrReader*r=malloc(sizeof(*r));if(r){r->read=read;r->state=state;}return r;}
int sr_parse(SrReader *reader){if(!reader)return -1;unsigned char buffer[17];unsigned sum=0;for(size_t turn=0;turn<4096;turn++){ptrdiff_t n=reader->read(reader->state,buffer,sizeof(buffer));if(n<0||n>(ptrdiff_t)sizeof(buffer))return -1;if(!n)break;for(ptrdiff_t i=0;i<n;i++)sum+=buffer[i];}return (int)(sum&255);}
void sr_close(SrReader *reader){free(reader);}
