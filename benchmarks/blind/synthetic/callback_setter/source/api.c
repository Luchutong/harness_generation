#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef int (*ScNotify)(void *user,unsigned byte);
typedef struct ScParser { ScNotify notify; void *user; } ScParser;
ScParser *sc_create(void) { ScParser *p=malloc(sizeof(*p)); if(p) {p->notify=NULL;p->user=NULL;} return p; }
void sc_set_reader(ScParser *p,ScNotify notify,void *user) { p->notify=notify;p->user=user; }
int sc_parse(ScParser *p,const unsigned char *data,size_t size) {
    if(!p->notify) return -1; if(size) return p->notify(p->user,data[0]); return 0;
}
void sc_destroy(ScParser *p) { free(p); }
static int sc_sink(void *u,unsigned b) { (void)u;(void)b;return 0; }
void sc_example(const unsigned char *d,size_t n) { ScParser *p=sc_create(); if(!p)return;sc_set_reader(p,sc_sink,NULL);sc_parse(p,d,n);sc_destroy(p); }
