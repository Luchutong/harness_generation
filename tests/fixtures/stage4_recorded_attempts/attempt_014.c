#include <stddef.h>
#include <stdint.h>

#include <vector>
#include <cstring>

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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mp_context ctx;
    mp_init(&ctx);

    const size_t header_size = 8;
    const size_t max_payload = (size_t)MP_MAX_PAYLOAD;
    const size_t max_steps = 32;

    size_t offset = 0;
    for (size_t step = 0; step < max_steps; ++step) {
        if (size - offset < header_size) {
            break;
        }

        size_t remaining = size - offset;
        size_t avail_payload = remaining - header_size;
        if (avail_payload == 0) {
            break;
        }

        size_t payload_len = avail_payload;
        if (payload_len > max_payload) {
            payload_len = max_payload;
        }

        std::vector<uint8_t> frame(header_size + payload_len);
        frame[0] = (uint8_t)'M';
        frame[1] = (uint8_t)'P';
        frame[2] = (uint8_t)1;
        frame[3] = data[offset + 3];

        const uint8_t *payload_src = data + offset + header_size;
        if (payload_len > 0) {
            std::memcpy(frame.data() + header_size, payload_src, payload_len);
        }

        uint16_t plen = (uint16_t)payload_len;
        frame[4] = (uint8_t)(plen & 0xFF);
        frame[5] = (uint8_t)((plen >> 8) & 0xFF);

        uint16_t csum = mp_checksum(frame.data() + header_size, payload_len);
        frame[6] = (uint8_t)(csum & 0xFF);
        frame[7] = (uint8_t)((csum >> 8) & 0xFF);

        mp_parse(&ctx, frame.data(), frame.size());

        offset += header_size + payload_len;
    }

    mp_destroy(&ctx);
    return 0;
}
