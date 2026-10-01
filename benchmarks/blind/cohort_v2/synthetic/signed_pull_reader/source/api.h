#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct SrReader SrReader;
typedef ptrdiff_t (*SrRead)(void *state,unsigned char *destination,size_t capacity);
SrReader *sr_open(SrRead read,void *state);
int sr_parse(SrReader *reader);
void sr_close(SrReader *reader);
#ifdef __cplusplus
}
#endif
#endif
