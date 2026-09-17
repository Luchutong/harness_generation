#include <stddef.h>
#include <stdint.h>
#include "target.c"

/*
 * Deliberately minimal baseline for feedback-loop experiments.  It passes the
 * raw byte stream to the parser once, so the structured reference harness is
 * never supplied to the model as a generation prompt.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    mp_context ctx;
    mp_init(&ctx);
    volatile int result = mp_parse(&ctx, Data, Size);
    (void)result;
    mp_destroy(&ctx);
    return 0;
}
