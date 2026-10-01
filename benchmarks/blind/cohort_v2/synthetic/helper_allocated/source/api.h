#ifndef BLIND_API_H
#define BLIND_API_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct HaState HaState;
HaState *ha_construct(void);
int ha_append(HaState *state,const unsigned char *data,size_t size);
int ha_finish(HaState *state);
void ha_destruct(HaState *state);
#ifdef __cplusplus
}
#endif
#endif
