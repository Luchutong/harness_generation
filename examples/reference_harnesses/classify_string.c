#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "target.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size > 4096) return 0;
    char *text = malloc(Size + 1);
    if (text == NULL) return 0;
    if (Size != 0) memcpy(text, Data, Size);
    text[Size] = '\0';
    volatile int result = classify_string(text);
    (void)result;
    free(text);
    return 0;
}
