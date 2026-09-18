#include <stddef.h>
#include <stdint.h>

extern "C" {

typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

void mp_init(mp_context *ctx);
void mp_destroy(mp_context *ctx);
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);
uint16_t le16(const uint8_t *p);
uint16_t mp_checksum(const uint8_t *data, size_t size);

}

#ifndef MP_MAX_PAYLOAD
#define MP_MAX_PAYLOAD 64
#endif

#ifndef MP_HEADER_SIZE
#define MP_HEADER_SIZE 8
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mp_context ctx;
    mp_init(&ctx);

    uint8_t frame_buf[MP_HEADER_SIZE + MP_MAX_PAYLOAD];

    size_t offset = 0;
    const size_t max_steps = 32;

    for (size_t step = 0; step < max_steps; ++step) {
        if (size - offset < MP_HEADER_SIZE) {
            break;
        }

        size_t remaining = size - offset - MP_HEADER_SIZE;
        size_t payload_length = remaining;
        if (payload_length > MP_MAX_PAYLOAD) {
            payload_length = MP_MAX_PAYLOAD;
        }

        frame_buf[0] = 'M';
        frame_buf[1] = 'P';
        frame_buf[2] = 1;
        frame_buf[3] = data[offset + 3];

        frame_buf[4] = (uint8_t)(payload_length & 0xFF);
        frame_buf[5] = (uint8_t)((payload_length >> 8) & 0xFF);

        for (size_t i = 0; i < payload_length; ++i) {
            frame_buf[MP_HEADER_SIZE + i] = data[offset + MP_HEADER_SIZE + i];
        }

        uint16_t checksum = mp_checksum(frame_buf + MP_HEADER_SIZE, payload_length);
        frame_buf[6] = (uint8_t)(checksum & 0xFF);
        frame_buf[7] = (uint8_t)((checksum >> 8) & 0xFF);

        size_t frame_len = MP_HEADER_SIZE + payload_length;
        mp_parse(&ctx, frame_buf, frame_len);

        offset += frame_len;
    }

    mp_destroy(&ctx);
    return 0;
}
