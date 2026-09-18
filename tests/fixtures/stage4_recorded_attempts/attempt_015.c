#include <stddef.h>
#include <stdint.h>

extern "C" {

typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

void mp_init(mp_context *ctx);
void mp_destroy(mp_context *ctx);
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);

}

namespace {

constexpr size_t kHeaderSize = 8;
constexpr size_t kMaxPayload = 64;
constexpr size_t kMaxSteps = 32;

uint16_t le16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint16_t mp_checksum(const uint8_t *data, size_t size) {
    uint16_t sum = 0;
    for (size_t i = 0; i < size; ++i) {
        sum = static_cast<uint16_t>(sum + data[i]);
    }
    return sum;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mp_context ctx;
    mp_init(&ctx);

    size_t offset = 0;
    for (size_t step = 0; step < kMaxSteps; ++step) {
        if (offset + kHeaderSize > size) {
            break;
        }

        const uint8_t *header = data + offset;
        uint8_t opcode = header[3];

        size_t remaining = size - (offset + kHeaderSize);
        size_t payload_len = remaining < kMaxPayload ? remaining : kMaxPayload;

        uint8_t frame_buf[kHeaderSize + kMaxPayload];
        frame_buf[0] = 'M';
        frame_buf[1] = 'P';
        frame_buf[2] = 1;
        frame_buf[3] = opcode;
        frame_buf[4] = static_cast<uint8_t>(payload_len & 0xFF);
        frame_buf[5] = static_cast<uint8_t>((payload_len >> 8) & 0xFF);

        for (size_t i = 0; i < payload_len; ++i) {
            frame_buf[kHeaderSize + i] = data[offset + kHeaderSize + i];
        }

        uint16_t checksum = mp_checksum(frame_buf + kHeaderSize, payload_len);
        frame_buf[6] = static_cast<uint8_t>(checksum & 0xFF);
        frame_buf[7] = static_cast<uint8_t>((checksum >> 8) & 0xFF);

        size_t frame_len = kHeaderSize + payload_len;
        mp_parse(&ctx, frame_buf, frame_len);

        offset += kHeaderSize + payload_len;
    }

    mp_destroy(&ctx);
    return 0;
}
