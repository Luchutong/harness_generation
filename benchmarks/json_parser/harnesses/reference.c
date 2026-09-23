/* Hand-written reference harness for json-parser.
 *
 * This is the natural harness shape for a text parser: the fuzzer bytes ARE
 * the JSON document, so no framing layer is needed.  It is used only as a
 * coverage/quality baseline and is never handed to the model.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern "C" {
#include "json.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   json_settings settings;
   char error[json_error_max];
   json_value *value;

   memset(&settings, 0, sizeof(settings));
   error[0] = '\0';

   value = json_parse_ex(&settings, (const char *) data, size, error);
   if (value != 0)
   {
      json_value_free(value);
   }

   return 0;
}
