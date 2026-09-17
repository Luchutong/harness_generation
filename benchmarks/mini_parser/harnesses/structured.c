#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "target.c"

static size_t hg_min_size(size_t left, size_t right) {
    return left < right ? left : right;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    mp_context ctx;
    mp_init(&ctx);

    size_t pos = 0;
    for (unsigned step = 0; step < 32 && Size - pos >= 2; ++step) {
        uint8_t op = (uint8_t)(1u + (Data[pos++] % 7u));
        size_t requested = (size_t)(Data[pos++] % (MP_MAX_PAYLOAD + 1u));
        size_t len = hg_min_size(requested, Size - pos);

        uint8_t frame[MP_HEADER_SIZE + MP_MAX_PAYLOAD] = {'M', 'P', 1, op};
        frame[4] = (uint8_t)len;
        frame[5] = (uint8_t)(len >> 8);
        if (len) memcpy(frame + MP_HEADER_SIZE, Data + pos, len);

        uint16_t sum = mp_checksum(frame + MP_HEADER_SIZE, len);
        frame[6] = (uint8_t)sum;
        frame[7] = (uint8_t)(sum >> 8);

        volatile int result = mp_parse(&ctx, frame, MP_HEADER_SIZE + len);
        volatile uint32_t observation = ctx.observation;
        (void)result;
        (void)observation;
        pos += len;
    }

    mp_destroy(&ctx);
    return 0;
}
