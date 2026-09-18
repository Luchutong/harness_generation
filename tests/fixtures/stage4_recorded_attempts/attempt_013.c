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
    for (int step = 0; step < 32; ++step) {
        if (offset + MP_HEADER_SIZE > size) {
            break;
        }

        const uint8_t *hdr = data + offset;

        uint8_t opcode = hdr[3];

        uint16_t raw_len = le16(hdr + 4);
        size_t payload_len = (size_t)raw_len;
        if (payload_len > MP_MAX_PAYLOAD) {
            payload_len = MP_MAX_PAYLOAD;
        }

        size_t avail = size - (offset + MP_HEADER_SIZE);
        if (payload_len > avail) {
            payload_len = avail;
        }

        frame_buf[0] = 'M';
        frame_buf[1] = 'P';
        frame_buf[2] = 1;
        frame_buf[3] = opcode;
        frame_buf[4] = (uint8_t)(payload_len & 0xFF);
        frame_buf[5] = (uint8_t)((payload_len >> 8) & 0xFF);

        if (payload_len > 0) {
            memcpy(frame_buf + MP_HEADER_SIZE, data + offset + MP_HEADER_SIZE, payload_len);
        }

        uint16_t csum = mp_checksum(frame_buf + MP_HEADER_SIZE, payload_len);
        frame_buf[6] = (uint8_t)(csum & 0xFF);
        frame_buf[7] = (uint8_t)((csum >> 8) & 0xFF);

        size_t frame_len = MP_HEADER_SIZE + payload_len;
        if (frame_len >= MP_HEADER_SIZE && frame_len <= MP_HEADER_SIZE + MP_MAX_PAYLOAD) {
            mp_parse(&ctx, frame_buf, frame_len);
        }

        offset += MP_HEADER_SIZE + payload_len;
    }

    mp_destroy(&ctx);
    return 0;
}
