#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef int (*DeepRead)(void *u,const unsigned char *p,size_t n);
typedef long (*DeepSeek)(void *u,long offset);
struct DeepReader { DeepRead read; DeepSeek seek; };
typedef struct DeepIO { struct DeepReader reader; void *userdata; } DeepIO;
int deep_parse(DeepIO *io,const unsigned char *bytes,size_t size) {
    if(!io->reader.read || !io->reader.seek) return -1;
    if(io->reader.seek(io->userdata,0)<0) return -2;
    return io->reader.read(io->userdata,bytes,size);
}
