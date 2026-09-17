#include <stddef.h>

struct Parser;
struct Node;

int parser_from_memory(struct Parser *parser, const unsigned char *data, unsigned long size);
struct Node parser_next(struct Parser *parser);
void node_process(struct Node *node);
void parser_free(struct Parser *parser);

int main(void) {
    struct Parser parser;
    const unsigned char data[] = {0x01};
    int rc = parser_from_memory(&parser, data, sizeof(data));
    if (rc != 0) {
        return 0;
    }
    struct Node node = parser_next(&parser);
    node_process(&node);
    parser_free(&parser);
    return 0;
}
