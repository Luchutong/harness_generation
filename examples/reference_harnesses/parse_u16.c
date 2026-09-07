#include <stdint.h>
#include <stddef.h>
#include "target.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uint16_t out = 0;
    volatile int result = parse_u16(Data, Size, &out);
    volatile uint16_t observed_out = out;
    (void)result;
    (void)observed_out;
    return 0;
}
