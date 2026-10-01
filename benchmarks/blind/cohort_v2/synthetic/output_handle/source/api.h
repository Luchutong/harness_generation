#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct OhHandle OhHandle;
int oh_acquire(OhHandle **output,size_t capacity);
int oh_ingest(OhHandle *handle,const void *payload,size_t bytes);
void oh_release(OhHandle *handle);
#ifdef __cplusplus
}
#endif
#endif
