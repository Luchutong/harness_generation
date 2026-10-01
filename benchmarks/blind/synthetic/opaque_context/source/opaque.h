#include <stddef.h>
typedef struct HiddenParser HiddenParser;
HiddenParser *hidden_create(unsigned mode);
int hidden_decode(HiddenParser *p,const unsigned char *bytes,size_t length);
void hidden_destroy(HiddenParser *p);
