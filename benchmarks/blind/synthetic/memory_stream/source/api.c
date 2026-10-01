#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct SvStream { const unsigned char *data;size_t size;size_t position; } SvStream;
SvStream *sv_open_memory(const unsigned char *data,size_t size) { SvStream *s=malloc(sizeof(*s));if(s){s->data=data;s->size=size;s->position=0;}return s; }
size_t sv_read(SvStream *s,unsigned char *out,size_t capacity) { size_t n=s->size-s->position;if(n>capacity)n=capacity;if(n)memcpy(out,s->data+s->position,n);s->position+=n;return n; }
int sv_parse_stream(SvStream *s) { unsigned char buf[4];unsigned sum=0;size_t n;while((n=sv_read(s,buf,sizeof(buf))))for(size_t i=0;i<n;i++)sum+=buf[i];return sum&255; }
void sv_close(SvStream *s) { free(s); }
void sv_example(const unsigned char *d,size_t n) { SvStream *s=sv_open_memory(d,n);if(s){sv_parse_stream(s);sv_close(s);} }
