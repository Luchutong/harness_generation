#include "api.h"
#include <stdlib.h>
#include <string.h>
struct BxDecoder {size_t maximum;unsigned mode;unsigned magic;};
BxDecoder *bx_open(const BxConfig *config,unsigned *status){if(status)*status=1;if(!config||config->mode>3)return NULL;BxDecoder*p=malloc(sizeof(*p));if(!p)return NULL;p->maximum=config->maximum?config->maximum:4096;p->mode=config->mode;p->magic=43;if(status)*status=0;return p;}
int bx_decode(BxDecoder *decoder,const unsigned char *bytes,size_t count){if(!decoder||decoder->magic!=43)return -2;if(count>decoder->maximum)return -1;unsigned n=decoder->mode;for(size_t i=0;i<count;i++)n+=bytes[i];return (int)(n&255);}
void bx_close(BxDecoder *decoder){free(decoder);}
