#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern "C" {

typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

void mp_init(mp_context *ctx);
void mp_destroy(mp_context *ctx);
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);
uint16_t le16(const uint8_t *p);
uint16_t mp_checksum(const uint8_t *data, size_t len);

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

    uint8_t frame_buf[MP_HEADER_SIZE + MP_MAX_PAYLOAD];

    size_t offset = 0;
    int steps = 0;

    while (offset < size && steps < 32) {
        size_t remaining = size - offset;

        size_t payload_len = remaining;
        if (payload_len > MP_MAX_PAYLOAD) {
            payload_len = MP_MAX_PAYLOAD;
        }

        frame_buf[0] = (uint8_t)'M';
        frame_buf[1] = (uint8_t)'P';
        frame_buf[2] = (uint8_t)1;
        frame_buf[3] = data[offset];

        frame_buf[4] = (uint8_t)(payload_len & 0xFF);
        frame_buf[5] = (uint8_t)((payload_len >> 8) & 0xFF);

        size_t payload_src = offset + 1;
        size_t payload_avail = (payload_src < size) ? (size - payload_src) : 0;
        if (payload_avail < payload_len) {
            payload_len = payload_avail;
            frame_buf[4] = (uint8_t)(payload_len & 0xFF);
            frame_buf[5] = (uint8_t)((payload_len >> 8) & 0xFF);
        }

        if (payload_len > 0) {
            memcpy(frame_buf + MP_HEADER_SIZE, data + payload_src, payload_len);
        }

        uint16_t cksum = mp_checksum(frame_buf + MP_HEADER_SIZE, payload_len);
        frame_buf[6] = (uint8_t)(cksum & 0xFF);
        frame_buf[7] = (uint8_t)((cksum >> 8) & 0xFF);

        size_t frame_len = MP_HEADER_SIZE + payload_len;

        mp_parse(&ctx, frame_buf, frame_len);

        offset = payload_src + payload_len;
        steps++;
    }

    mp_destroy(&ctx);
    return 0;
}
