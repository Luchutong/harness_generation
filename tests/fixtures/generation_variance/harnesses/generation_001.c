#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern "C" {

typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

void mp_init(mp_context *ctx);
void mp_destroy(mp_context *ctx);
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);
uint16_t mp_checksum(const uint8_t *data, size_t size);

}

#ifndef MP_HEADER_SIZE
#define MP_HEADER_SIZE 8u
#endif

#ifndef MP_MAX_PAYLOAD
#define MP_MAX_PAYLOAD 64u
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mp_context ctx;
    mp_init(&ctx);

    size_t pos = 0;
    const size_t max_steps = 32;

    for (size_t step = 0; step < max_steps; ++step) {
        if (pos >= size) {
            break;
        }

        uint8_t opcode = data[pos++];

        size_t payload_len = 0;
        if (pos < size) {
            payload_len = (size_t)(data[pos++] % (MP_MAX_PAYLOAD + 1u));
        }

        size_t available = size - pos;
        if (payload_len > available) {
            payload_len = available;
        }

        uint8_t frame_buf[MP_HEADER_SIZE + MP_MAX_PAYLOAD];
        frame_buf[0] = (uint8_t)'M';
        frame_buf[1] = (uint8_t)'P';
        frame_buf[2] = (uint8_t)1;
        frame_buf[3] = opcode;

        uint16_t plen = (uint16_t)payload_len;
        frame_buf[4] = (uint8_t)(plen & 0xFFu);
        frame_buf[5] = (uint8_t)((plen >> 8) & 0xFFu);

        if (payload_len > 0) {
            memcpy(frame_buf + MP_HEADER_SIZE, data + pos, payload_len);
            pos += payload_len;
        }

        uint16_t csum = mp_checksum(frame_buf + MP_HEADER_SIZE, payload_len);
        frame_buf[6] = (uint8_t)(csum & 0xFFu);
        frame_buf[7] = (uint8_t)((csum >> 8) & 0xFFu);

        size_t frame_len = MP_HEADER_SIZE + payload_len;
        if (frame_len < MP_HEADER_SIZE) {
            break;
        }
        if (frame_len > MP_HEADER_SIZE + MP_MAX_PAYLOAD) {
            break;
        }

        mp_parse(&ctx, frame_buf, frame_len);
    }

    mp_destroy(&ctx);
    return 0;
}
