#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct RoParser RoParser;
typedef struct RoRegistration {void (*on_byte)(void *cookie,unsigned byte);void *cookie;} RoRegistration;
RoParser *ro_create(void);
void ro_register(RoParser *parser,const RoRegistration *registration);
int ro_parse(RoParser *parser,const unsigned char *data,size_t size);
void ro_destroy(RoParser *parser);
#ifdef __cplusplus
}
#endif
#endif
