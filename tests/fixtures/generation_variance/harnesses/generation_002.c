#include <stddef.h>
#include <stdint.h>

extern "C" {
typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

void mp_destroy(mp_context *ctx);
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);
void mp_init(mp_context *ctx);
}

#ifndef MP_HEADER_SIZE
#define MP_HEADER_SIZE 8u
#endif
#ifndef MP_MAX_PAYLOAD
#define MP_MAX_PAYLOAD 64u
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mp_context ctx;
    mp_init(&ctx);

    uint8_t frame_buf[MP_HEADER_SIZE + MP_MAX_PAYLOAD];

    size_t pos = 0;
    const size_t bounded_steps = 32;

    for (size_t step = 0; step < bounded_steps; ++step) {
        if (pos >= size) {
            break;
        }

        uint8_t opcode = data[pos++];

        uint8_t len_byte = 0;
        if (pos < size) {
            len_byte = data[pos++];
        }
        size_t payload_length = (size_t)(len_byte % (MP_MAX_PAYLOAD + 1u));

        size_t available = size - pos;
        if (payload_length > available) {
            payload_length = available;
        }

        frame_buf[0] = (uint8_t)'M';
        frame_buf[1] = (uint8_t)'P';
        frame_buf[2] = (uint8_t)1;
        frame_buf[3] = opcode;
        frame_buf[4] = (uint8_t)(payload_length & 0xFFu);
        frame_buf[5] = (uint8_t)((payload_length >> 8) & 0xFFu);

        for (size_t i = 0; i < payload_length; ++i) {
            frame_buf[MP_HEADER_SIZE + i] = data[pos + i];
        }
        pos += payload_length;

        uint16_t checksum = 0;
        for (size_t i = 0; i < payload_length; ++i) {
            checksum = (uint16_t)(checksum + frame_buf[MP_HEADER_SIZE + i]);
        }
        frame_buf[6] = (uint8_t)(checksum & 0xFFu);
        frame_buf[7] = (uint8_t)((checksum >> 8) & 0xFFu);

        size_t frame_len = MP_HEADER_SIZE + payload_length;
        mp_parse(&ctx, frame_buf, frame_len);
    }

    mp_destroy(&ctx);
    return 0;
}
