#include "api.h"
#include <stdlib.h>
#include <string.h>
int tc_decode(const TcCallbacks *callbacks,const unsigned char *bytes,size_t size){if(!callbacks||!callbacks->transport.receiver.consume)return -1;for(size_t i=0;i<size;i++)callbacks->transport.receiver.consume(callbacks->transport.receiver.state,bytes[i]);return 0;}
