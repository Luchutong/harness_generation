#include "api.h"
#include <stdlib.h>
#include <string.h>
struct TfTransaction {unsigned phase;unsigned sum;};
TfTransaction *tf_begin(void){TfTransaction*t=malloc(sizeof(*t));if(t){t->phase=0;t->sum=0;}return t;}
int tf_feed(TfTransaction *transaction,const unsigned char *bytes,size_t size){if(!transaction||transaction->phase>=3)return -1;for(size_t i=0;i<size;i++)transaction->sum+=bytes[i];transaction->phase++;return 0;}
int tf_commit(TfTransaction *transaction){if(!transaction||transaction->phase!=3)return -1;return (int)(transaction->sum&255);}
void tf_end(TfTransaction *transaction){free(transaction);}
