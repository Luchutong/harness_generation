#include <stddef.h>

typedef struct Parser Parser;
typedef struct Node Node;

int parser_from_memory(Parser *parser, const unsigned char *data, unsigned long size);
Node parser_next(Parser *parser);
void node_process(Node *node);
void parser_free(Parser *parser);

int main(void) {
    Parser parser;
    const unsigned char input[] = {0x01, 0x02, 0x03};
    int rc = parser_from_memory(&parser, input, sizeof(input));
    if (rc != 0) {
        return 0;
    }

    Node node = parser_next(&parser);
    node_process(&node);

    parser_free(&parser);
    return 0;
}
