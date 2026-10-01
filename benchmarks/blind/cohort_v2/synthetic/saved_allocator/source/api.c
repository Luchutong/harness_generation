#include "api.h"
#include <stdlib.h>
#include <string.h>
struct SaParser {SaAllocator allocator;unsigned tag;};
SaParser *sa_open(const SaAllocator *allocator){if(!allocator||!allocator->allocate||!allocator->release)return NULL;SaParser*p=allocator->allocate(allocator->cookie,sizeof(*p));if(p){p->allocator=*allocator;p->tag=19;}return p;}
int sa_parse(SaParser *parser,const unsigned char *data,size_t length){if(!parser||parser->tag!=19)return -1;unsigned v=0;for(size_t i=0;i<length;i++)v+=data[i];return (int)(v&255);}
void sa_close(SaParser *parser){if(parser){SaAllocator a=parser->allocator;a.release(a.cookie,parser);}}
