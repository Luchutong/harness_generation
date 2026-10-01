#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct TfTransaction TfTransaction;
TfTransaction *tf_begin(void);
int tf_feed(TfTransaction *transaction,const unsigned char *bytes,size_t size);
int tf_commit(TfTransaction *transaction);
void tf_end(TfTransaction *transaction);
#ifdef __cplusplus
}
#endif
#endif
