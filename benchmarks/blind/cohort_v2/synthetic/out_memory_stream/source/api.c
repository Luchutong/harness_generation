#include "api.h"
#include <stdlib.h>
#include <string.h>
struct MsStream {const unsigned char *bytes;size_t length,position;unsigned ready;};
int ms_create(MsStream **output){if(!output)return -1;*output=calloc(1,sizeof(MsStream));return *output?0:-1;}
void ms_bind(MsStream *stream,const unsigned char *bytes,size_t length){stream->bytes=bytes;stream->length=length;stream->position=0;stream->ready=1;}
size_t ms_read(MsStream *stream,unsigned char *destination,size_t capacity){size_t n=stream->length-stream->position;if(n>capacity)n=capacity;if(n)memcpy(destination,stream->bytes+stream->position,n);stream->position+=n;return n;}
int ms_parse(MsStream *stream){if(!stream||!stream->ready)return -1;unsigned char b[11];size_t n;unsigned sum=0;while((n=ms_read(stream,b,sizeof(b))))for(size_t i=0;i<n;i++)sum+=b[i];return (int)(sum&255);}
void ms_destroy(MsStream *stream){free(stream);}
