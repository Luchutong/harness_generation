#include <stddef.h>
#include <stdint.h>

struct Parser;
struct Node;

int parser_from_memory(struct Parser *parser, const unsigned char *data, unsigned long size);
struct Node parser_next(struct Parser *parser);
void node_process(struct Node *node);
void parser_free(struct Parser *parser);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct Parser parser;
    int rc = parser_from_memory(&parser, (const unsigned char *)data, (unsigned long)size);
    if (rc != 0) {
        return 0;
    }
    struct Node node = parser_next(&parser);
    node_process(&node);
    parser_free(&parser);
    return 0;
}
