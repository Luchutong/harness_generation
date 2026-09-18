#include <stddef.h>
#include <stdint.h>

extern "C" {

typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

void mp_destroy(mp_context *ctx);
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);

}

#ifndef MP_HEADER_SIZE
#define MP_HEADER_SIZE 8
#endif

#ifndef MP_MAX_PAYLOAD
#define MP_MAX_PAYLOAD 64
#endif

static uint16_t mp_checksum(const uint8_t *data, size_t len) {
    uint16_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum = (uint16_t)(sum + data[i]);
    }
    return sum;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mp_context ctx;
    ctx.saved = nullptr;
    ctx.saved_len = 0;
    ctx.owns_saved = 0;
    ctx.observation = 0;

    const size_t header_size = MP_HEADER_SIZE;
    const size_t max_payload = MP_MAX_PAYLOAD;
    const size_t max_steps = 32;

    size_t offset = 0;
    size_t steps = 0;

    while (steps < max_steps && offset + header_size <= size) {
        const uint8_t *frame_in = data + offset;
        size_t remaining = size - offset;

        uint8_t opcode = frame_in[3];

        size_t avail_payload = remaining - header_size;
        size_t payload_len = avail_payload;
        if (payload_len > max_payload) {
            payload_len = max_payload;
        }

        uint8_t frame_buf[MP_HEADER_SIZE + MP_MAX_PAYLOAD];
        frame_buf[0] = 'M';
        frame_buf[1] = 'P';
        frame_buf[2] = 1;
        frame_buf[3] = opcode;
        frame_buf[4] = (uint8_t)(payload_len & 0xFF);
        frame_buf[5] = (uint8_t)((payload_len >> 8) & 0xFF);

        const uint8_t *payload_src = frame_in + header_size;
        for (size_t i = 0; i < payload_len; ++i) {
            frame_buf[header_size + i] = payload_src[i];
        }

        uint16_t csum = mp_checksum(frame_buf + header_size, payload_len);
        frame_buf[6] = (uint8_t)(csum & 0xFF);
        frame_buf[7] = (uint8_t)((csum >> 8) & 0xFF);

        size_t frame_len = header_size + payload_len;

        mp_parse(&ctx, frame_buf, frame_len);

        offset += frame_len;
        steps++;
    }

    mp_destroy(&ctx);
    return 0;
}
