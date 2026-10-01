#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct MsStream MsStream;
int ms_create(MsStream **output);
void ms_bind(MsStream *stream,const unsigned char *bytes,size_t length);
size_t ms_read(MsStream *stream,unsigned char *destination,size_t capacity);
int ms_parse(MsStream *stream);
void ms_destroy(MsStream *stream);
#ifdef __cplusplus
}
#endif
#endif
