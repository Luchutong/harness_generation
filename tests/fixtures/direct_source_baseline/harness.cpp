#include "parser.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < MP_HEADER_SIZE) return 0;

    mp_context ctx;
    mp_init(&ctx);

    /* Feed the whole input as one frame first. */
    mp_parse(&ctx, data, size);

    /* Also exercise stateful sequences: split the input into multiple
       frames so MP_STORE / MP_RELEASE / MP_USE interactions are covered.
       Use a small bounded number of frames to keep work bounded. */
    const size_t max_frames = 8;
    size_t offset = 0;
    size_t frames = 0;
    while (offset + MP_HEADER_SIZE <= size && frames < max_frames) {
        /* Derive frame length from the header's length field if it looks
           plausible; otherwise consume the rest. */
        size_t remaining = size - offset;
        size_t frame_len = remaining;
        if (remaining >= MP_HEADER_SIZE) {
            const uint8_t *h = data + offset;
            if (h[0] == 'M' && h[1] == 'P' && h[2] == 1) {
                size_t declared = (size_t)h[4] | ((size_t)h[5] << 8);
                if (declared <= MP_MAX_PAYLOAD &&
                    declared + MP_HEADER_SIZE <= remaining) {
                    frame_len = declared + MP_HEADER_SIZE;
                }
            }
        }
        if (frame_len == 0) break;
        mp_parse(&ctx, data + offset, frame_len);
        offset += frame_len;
        ++frames;
    }

    mp_destroy(&ctx);
    return 0;
}
