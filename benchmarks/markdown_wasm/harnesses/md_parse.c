#include <stddef.h>
#include <stdint.h>
#include "md4c.h"

static int enter_block(MD_BLOCKTYPE type, void *detail, void *userdata) {
  (void)type; (void)detail; (void)userdata;
  return 0;
}
static int leave_block(MD_BLOCKTYPE type, void *detail, void *userdata) {
  (void)type; (void)detail; (void)userdata;
  return 0;
}
static int enter_span(MD_SPANTYPE type, void *detail, void *userdata) {
  (void)type; (void)detail; (void)userdata;
  return 0;
}
static int leave_span(MD_SPANTYPE type, void *detail, void *userdata) {
  (void)type; (void)detail; (void)userdata;
  return 0;
}
static int text(MD_TEXTTYPE type, const MD_CHAR *value, MD_SIZE size, void *userdata) {
  (void)type; (void)value; (void)size; (void)userdata;
  return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > UINT32_MAX) return 0;
  MD_PARSER parser = {0};
  parser.abi_version = 0;
  parser.flags = MD_DIALECT_GITHUB;
  parser.enter_block = enter_block;
  parser.leave_block = leave_block;
  parser.enter_span = enter_span;
  parser.leave_span = leave_span;
  parser.text = text;
  (void)md_parse((const MD_CHAR *)data, (MD_SIZE)size, &parser, NULL);
  return 0;
}
