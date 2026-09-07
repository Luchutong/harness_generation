#include <stddef.h>
#include <stdint.h>

/* Read a little-endian integer. out must point to writable uint16_t storage. */
static int parse_u16(const uint8_t *data, size_t size, uint16_t *out) {
    if (size < 2) return -1;
    *out = (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
    return *out == 0xCAFE ? 1 : 0;
}
