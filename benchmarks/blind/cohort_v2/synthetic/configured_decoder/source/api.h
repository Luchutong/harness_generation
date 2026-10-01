#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct BxDecoder BxDecoder;
typedef struct BxConfig { size_t maximum; unsigned mode; } BxConfig;
/* Decoder objects must originate from bx_open; config storage is borrowed. */
BxDecoder *bx_open(const BxConfig *config,unsigned *status);
int bx_decode(BxDecoder *decoder,const unsigned char *bytes,size_t count);
void bx_close(BxDecoder *decoder);
#ifdef __cplusplus
}
#endif
#endif
