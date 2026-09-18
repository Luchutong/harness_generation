#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct { uint8_t *saved; size_t saved_len; int owns_saved; volatile uint32_t observation; } mp_context;

extern "C" void mp_destroy(mp_context *ctx);
extern "C" int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mp_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    mp_parse(&ctx, data, size);
    mp_destroy(&ctx);
    return 0;
}
