#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct SpSnapshot SpSnapshot;
SpSnapshot *sp_new(unsigned seed);
void sp_feed(SpSnapshot *snapshot,const unsigned char *bytes,size_t count);
int sp_compare(const SpSnapshot *left,const SpSnapshot *right);
void sp_delete(SpSnapshot *snapshot);
#ifdef __cplusplus
}
#endif
#endif
