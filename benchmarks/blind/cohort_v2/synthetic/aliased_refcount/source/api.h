#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct ArObject ArObject;
ArObject *ar_new(void);
ArObject *ar_retain(ArObject *object);
ArObject *ar_decode(ArObject *object,const unsigned char *bytes,size_t count);
void ar_unref(ArObject *object);
#ifdef __cplusplus
}
#endif
#endif
