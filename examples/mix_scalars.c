#include <stdint.h>

/* All values are accepted; unsigned arithmetic deliberately wraps. */
static uint32_t mix_scalars(uint32_t value, uint16_t salt, uint8_t mode) {
    switch (mode & 3u) {
        case 0: return value + salt;
        case 1: return value ^ ((uint32_t)salt << 16);
        case 2: return value * ((uint32_t)salt + 1u);
        default: return value >> (salt & 31u);
    }
}
