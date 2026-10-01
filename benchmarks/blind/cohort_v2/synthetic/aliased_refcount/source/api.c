#include "api.h"
#include <stdlib.h>
#include <string.h>
struct ArObject {unsigned references;unsigned value;};
ArObject *ar_new(void){ArObject*p=malloc(sizeof(*p));if(p){p->references=1;p->value=0;}return p;}
ArObject *ar_retain(ArObject *object){if(object)object->references++;return object;}
ArObject *ar_decode(ArObject *object,const unsigned char *bytes,size_t count){if(!object)return NULL;for(size_t i=0;i<count;i++)object->value+=bytes[i];return ar_retain(object);}
void ar_unref(ArObject *object){if(object&&!--object->references)free(object);}
