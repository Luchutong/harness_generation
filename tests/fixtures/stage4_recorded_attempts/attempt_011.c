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
#define MP_HEADER_SIZE 8
#endif

#ifndef MP_MAX_PAYLOAD
#define MP_MAX_PAYLOAD 64
#endif

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void store_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mp_context ctx;
    mp_init(&ctx);

    size_t offset = 0;
    const size_t max_steps = 32;

    for (size_t step = 0; step < max_steps; ++step) {
        if (offset + MP_HEADER_SIZE > size) {
            break;
        }

        size_t remaining = size - offset;
        size_t avail_payload = remaining - MP_HEADER_SIZE;
        size_t payload_len = avail_payload;
        if (payload_len > (size_t)MP_MAX_PAYLOAD) {
            payload_len = (size_t)MP_MAX_PAYLOAD;
        }

        uint8_t frame[MP_HEADER_SIZE + MP_MAX_PAYLOAD];
        frame[0] = (uint8_t)'M';
        frame[1] = (uint8_t)'P';
        frame[2] = (uint8_t)1;
        frame[3] = data[offset + 3];

        if (payload_len > 0) {
            memcpy(frame + MP_HEADER_SIZE, data + offset + MP_HEADER_SIZE, payload_len);
        }

        store_le16(frame + 4, (uint16_t)payload_len);
        uint16_t csum = mp_checksum(frame + MP_HEADER_SIZE, payload_len);
        store_le16(frame + 6, csum);

        size_t frame_len = MP_HEADER_SIZE + payload_len;
        mp_parse(&ctx, frame, frame_len);

        offset += frame_len;
    }

    mp_destroy(&ctx);
    return 0;
}
