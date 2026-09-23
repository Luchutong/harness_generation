#include <stddef.h>
#include <stdint.h>
#include "common.h"

size_t parseUTF8(const char *inbufptr, u32 inbuflen, u32 parser_flags,
                 OutputFlags outflags, const char **outptr,
                 JSTextFilterFun onCodeBlock);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > UINT32_MAX) return 0;
  const char *output = NULL;
  size_t output_size = parseUTF8((const char *)data, (u32)size, 0,
                                 OutputFlagHTML, &output, NULL);
  if (output_size && output == NULL) __builtin_trap();
  return 0;
}
