#include "api.h"
#include <stdlib.h>
#include <string.h>
struct RoParser {RoRegistration handler;unsigned ready;};
RoParser *ro_create(void){RoParser*p=malloc(sizeof(*p));if(p){memset(p,0,sizeof(*p));p->ready=7;}return p;}
void ro_register(RoParser *parser,const RoRegistration *registration){if(parser&&registration)parser->handler=*registration;}
int ro_parse(RoParser *parser,const unsigned char *data,size_t size){if(!parser||parser->ready!=7||!parser->handler.on_byte)return -1;for(size_t i=0;i<size;i++)parser->handler.on_byte(parser->handler.cookie,data[i]);return 0;}
void ro_destroy(RoParser *parser){free(parser);}
