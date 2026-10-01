#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct PsSession PsSession;
PsSession *ps_start(const char *name);
int ps_decode(PsSession *session,const unsigned char *data,size_t size);
void ps_stop(PsSession *session);
#ifdef __cplusplus
}
#endif
#endif
