#include "api.h"
#include <stdlib.h>
#include <string.h>
struct OhHandle {size_t capacity;unsigned tag;};
int oh_acquire(OhHandle **output,size_t capacity){if(!output)return -1;*output=NULL;if(capacity>4096)return -1;OhHandle*h=malloc(sizeof(*h));if(!h)return -1;h->capacity=capacity?capacity:4096;h->tag=9;*output=h;return 0;}
int oh_ingest(OhHandle *handle,const void *payload,size_t bytes){if(!handle||handle->tag!=9)return -2;if(bytes>handle->capacity)return -1;const unsigned char*p=payload;unsigned n=0;for(size_t i=0;i<bytes;i++)n^=p[i];return (int)n;}
void oh_release(OhHandle *handle){free(handle);}
