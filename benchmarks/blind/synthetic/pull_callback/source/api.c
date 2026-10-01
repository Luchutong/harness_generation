#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef size_t (*PlRead)(void *opaque,unsigned char *out,size_t capacity);
typedef struct PlParser { PlRead read; void *opaque; } PlParser;
typedef struct PlCursor { const unsigned char *data; size_t size; size_t position; } PlCursor;
PlParser *pl_open(PlRead read,void *opaque) { if(!read) return NULL;PlParser *p=malloc(sizeof(*p));if(p){p->read=read;p->opaque=opaque;}return p; }
int pl_parse(PlParser *p) { unsigned char out[8];unsigned sum=0;size_t n;while((n=p->read(p->opaque,out,sizeof(out)))!=0){if(n>sizeof(out))return -1;for(size_t i=0;i<n;i++)sum+=out[i];}return sum&255; }
void pl_close(PlParser *p) { free(p); }
size_t pl_memory_read(void *opaque,unsigned char *out,size_t capacity) { PlCursor *c=opaque;size_t n=c->size-c->position;if(n>capacity)n=capacity;if(n)memcpy(out,c->data+c->position,n);c->position+=n;return n; }
void pl_example(const unsigned char *d,size_t n) { PlCursor c={d,n,0};PlParser *p=pl_open(pl_memory_read,&c);if(p){pl_parse(p);pl_close(p);} }
