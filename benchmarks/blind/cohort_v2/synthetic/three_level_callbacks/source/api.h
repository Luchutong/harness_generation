#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct TcCallbacks {struct Transport {struct Receiver {void (*consume)(void *state,unsigned byte);void *state;} receiver;} transport;} TcCallbacks;
int tc_decode(const TcCallbacks *callbacks,const unsigned char *bytes,size_t size);
#ifdef __cplusplus
}
#endif
#endif
