#include <stddef.h>
#include <stdint.h>

extern "C" {
typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

void mp_init(mp_context *ctx);
void mp_destroy(mp_context *ctx);
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);
uint16_t mp_checksum(const uint8_t *data, size_t size);
}

#ifndef MP_MAX_PAYLOAD
#define MP_MAX_PAYLOAD 64u
#endif

#ifndef MP_HEADER_SIZE
#define MP_HEADER_SIZE 8u
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mp_context ctx;
    mp_init(&ctx);

    size_t pos = 0;
    unsigned frames_processed = 0;

    while (pos < size && frames_processed < 32u) {
        uint8_t opcode = data[pos++];

        size_t payload_len = 0;
        if (pos < size) {
            payload_len = (size_t)(data[pos++] % (MP_MAX_PAYLOAD + 1u));
        }

        size_t available = size - pos;
        if (payload_len > available) {
            payload_len = available;
        }

        uint8_t frame[MP_HEADER_SIZE + MP_MAX_PAYLOAD];
        frame[0] = (uint8_t)'M';
        frame[1] = (uint8_t)'P';
        frame[2] = (uint8_t)1;
        frame[3] = opcode;
        frame[4] = (uint8_t)(payload_len & 0xFFu);
        frame[5] = (uint8_t)((payload_len >> 8) & 0xFFu);

        for (size_t i = 0; i < payload_len; i++) {
            frame[MP_HEADER_SIZE + i] = data[pos + i];
        }

        uint16_t checksum = mp_checksum(frame + MP_HEADER_SIZE, payload_len);
        frame[6] = (uint8_t)(checksum & 0xFFu);
        frame[7] = (uint8_t)((checksum >> 8) & 0xFFu);

        size_t frame_len = MP_HEADER_SIZE + payload_len;
        mp_parse(&ctx, frame, frame_len);

        pos += payload_len;
        frames_processed++;
    }

    mp_destroy(&ctx);
    return 0;
}
