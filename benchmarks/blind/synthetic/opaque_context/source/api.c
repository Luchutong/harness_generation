#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "opaque.h"
struct HiddenParser { unsigned mode; };
HiddenParser *hidden_create(unsigned mode) { HiddenParser *p=malloc(sizeof(*p)); if(p) p->mode=mode; return p; }
int hidden_decode(HiddenParser *p,const unsigned char *bytes,size_t length) { return length ? (bytes[0]^p->mode)&255 : 0; }
void hidden_destroy(HiddenParser *p) { free(p); }
void hidden_example(const unsigned char *d,size_t n) { HiddenParser *p=hidden_create(0); if(p) {hidden_decode(p,d,n);hidden_destroy(p);} }
