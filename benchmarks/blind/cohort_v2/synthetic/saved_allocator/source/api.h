#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct SaParser SaParser;
typedef struct SaAllocator {void *(*allocate)(void *cookie,size_t size);void (*release)(void *cookie,void *memory);void *cookie;} SaAllocator;
SaParser *sa_open(const SaAllocator *allocator);
int sa_parse(SaParser *parser,const unsigned char *data,size_t length);
void sa_close(SaParser *parser);
#ifdef __cplusplus
}
#endif
#endif
