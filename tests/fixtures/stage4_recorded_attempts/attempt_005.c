#include <stddef.h>
#include <stdint.h>

extern "C" {
typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

void mp_init(mp_context *ctx);
void mp_destroy(mp_context *ctx);
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);
uint16_t mp_checksum(const uint8_t *data, size_t size);
}

#ifndef MP_HEADER_SIZE
#define MP_HEADER_SIZE 8
#endif

#ifndef MP_MAX_PAYLOAD
#define MP_MAX_PAYLOAD 64
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mp_context ctx;
    mp_init(&ctx);

    size_t offset = 0;
    const size_t max_steps = 32;

    for (size_t step = 0; step < max_steps && offset < size; ++step) {
        uint8_t opcode = data[offset];
        ++offset;

        size_t remaining = size - offset;
        size_t payload_len = remaining;
        if (payload_len > MP_MAX_PAYLOAD) {
            payload_len = MP_MAX_PAYLOAD;
        }

        uint8_t frame[MP_HEADER_SIZE + MP_MAX_PAYLOAD];
        frame[0] = 'M';
        frame[1] = 'P';
        frame[2] = 1;
        frame[3] = opcode;
        frame[4] = (uint8_t)(payload_len & 0xFF);
        frame[5] = (uint8_t)((payload_len >> 8) & 0xFF);

        for (size_t i = 0; i < payload_len; ++i) {
            frame[MP_HEADER_SIZE + i] = data[offset + i];
        }
        offset += payload_len;

        uint16_t checksum = mp_checksum(frame + MP_HEADER_SIZE, payload_len);
        frame[6] = (uint8_t)(checksum & 0xFF);
        frame[7] = (uint8_t)((checksum >> 8) & 0xFF);

        mp_parse(&ctx, frame, MP_HEADER_SIZE + payload_len);
    }

    mp_destroy(&ctx);
    return 0;
}
