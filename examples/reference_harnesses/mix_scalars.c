#include <stdint.h>
#include <stddef.h>
#include "target.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 7) return 0;
    uint32_t value = (uint32_t)Data[0] | ((uint32_t)Data[1] << 8)
                   | ((uint32_t)Data[2] << 16) | ((uint32_t)Data[3] << 24);
    uint16_t salt = (uint16_t)((uint16_t)Data[4] | ((uint16_t)Data[5] << 8));
    volatile uint32_t result = mix_scalars(value, salt, Data[6]);
    (void)result;
    return 0;
}
