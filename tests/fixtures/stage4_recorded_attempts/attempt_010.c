#include <stddef.h>
#include <stdint.h>

#include <vector>
#include <cstring>

extern "C" {

typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

void mp_init(mp_context *ctx);
void mp_destroy(mp_context *ctx);
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);
uint16_t mp_checksum(const uint8_t *data, size_t size);
uint16_t le16(const uint8_t *p);

}

#ifndef MP_MAX_PAYLOAD
#define MP_MAX_PAYLOAD 64
#endif

#ifndef MP_HEADER_SIZE
#define MP_HEADER_SIZE 8
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mp_context ctx;
    mp_init(&ctx);

    size_t offset = 0;
    const size_t max_steps = 32;

    for (size_t step = 0; step < max_steps; ++step) {
        if (size - offset < MP_HEADER_SIZE) {
            break;
        }

        const uint8_t *header = data + offset;

        uint8_t opcode = header[3];

        size_t remaining = size - offset - MP_HEADER_SIZE;
        size_t payload_len = remaining;
        if (payload_len > MP_MAX_PAYLOAD) {
            payload_len = MP_MAX_PAYLOAD;
        }

        std::vector<uint8_t> frame(MP_HEADER_SIZE + payload_len);

        frame[0] = (uint8_t)'M';
        frame[1] = (uint8_t)'P';
        frame[2] = (uint8_t)1;
        frame[3] = opcode;

        uint16_t plen = (uint16_t)payload_len;
        frame[4] = (uint8_t)(plen & 0xFF);
        frame[5] = (uint8_t)((plen >> 8) & 0xFF);

        if (payload_len > 0) {
            std::memcpy(frame.data() + MP_HEADER_SIZE, data + offset + MP_HEADER_SIZE, payload_len);
        }

        uint16_t csum = mp_checksum(frame.data() + MP_HEADER_SIZE, payload_len);
        frame[6] = (uint8_t)(csum & 0xFF);
        frame[7] = (uint8_t)((csum >> 8) & 0xFF);

        mp_parse(&ctx, frame.data(), frame.size());

        offset += MP_HEADER_SIZE + payload_len;
    }

    mp_destroy(&ctx);
    return 0;
}
