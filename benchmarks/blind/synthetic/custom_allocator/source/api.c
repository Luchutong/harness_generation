#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct Arena { void *(*allocate)(void *cookie,size_t n); void (*release)(void *cookie,void *p); void *cookie; } Arena;
typedef struct AlParser { const Arena *arena; unsigned value; } AlParser;
AlParser *al_create(const Arena *arena) {
    if(!arena || !arena->allocate || !arena->release) return NULL;
    AlParser *p=arena->allocate(arena->cookie,sizeof(*p)); if(!p) return NULL;
    p->arena=arena; p->value=0; return p;
}
int al_decode(AlParser *p,const unsigned char *data,size_t n) { if(n) p->value=data[0]; return p->value; }
void al_destroy(AlParser *p,const Arena *arena) { if(p && arena==p->arena) arena->release(arena->cookie,p); }
static void *al_heap(void *cookie,size_t n) { (void)cookie; return malloc(n); }
static void al_free(void *cookie,void *p) { (void)cookie; free(p); }
void al_example(const unsigned char *d,size_t n) {
    Arena arena={al_heap,al_free,NULL}; AlParser *p=al_create(&arena); if(!p) return;
    al_decode(p,d,n); al_destroy(p,&arena);
}
