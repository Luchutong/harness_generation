#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern "C" {

typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

void mp_init(mp_context *ctx);
void mp_destroy(mp_context *ctx);
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);

}

#ifndef MP_HEADER_SIZE
#define MP_HEADER_SIZE 8
#endif

#ifndef MP_MAX_PAYLOAD
#define MP_MAX_PAYLOAD 64
#endif

static uint16_t mp_checksum(const uint8_t *data, size_t size) {
    uint16_t sum = 0;
    for (size_t i = 0; i < size; ++i) {
        sum = (uint16_t)(sum + data[i]);
    }
    return sum;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mp_context ctx;
    mp_init(&ctx);

    size_t offset = 0;
    int steps = 0;
    const int max_steps = 32;

    while (steps < max_steps && offset + MP_HEADER_SIZE <= size) {
        uint8_t frame_buf[MP_HEADER_SIZE + MP_MAX_PAYLOAD];

        frame_buf[0] = 'M';
        frame_buf[1] = 'P';
        frame_buf[2] = 1;
        frame_buf[3] = data[offset + 3];

        size_t remaining = size - (offset + MP_HEADER_SIZE);
        size_t payload_len = remaining;
        if (payload_len > MP_MAX_PAYLOAD) {
            payload_len = MP_MAX_PAYLOAD;
        }

        if (payload_len > 0) {
            memcpy(frame_buf + MP_HEADER_SIZE, data + offset + MP_HEADER_SIZE, payload_len);
        }

        frame_buf[4] = (uint8_t)(payload_len & 0xFF);
        frame_buf[5] = (uint8_t)((payload_len >> 8) & 0xFF);

        uint16_t csum = mp_checksum(frame_buf + MP_HEADER_SIZE, payload_len);
        frame_buf[6] = (uint8_t)(csum & 0xFF);
        frame_buf[7] = (uint8_t)((csum >> 8) & 0xFF);

        size_t frame_len = MP_HEADER_SIZE + payload_len;

        mp_parse(&ctx, frame_buf, frame_len);

        offset += frame_len;
        steps++;
    }

    mp_destroy(&ctx);
    return 0;
}
