#include <stddef.h>

typedef struct Parser Parser;

typedef struct Node {
    int value;
} Node;

int parser_from_memory(Parser *parser, const unsigned char *data, unsigned long size);
Node parser_next(Parser *parser);
void node_process(Node *node);
void parser_free(Parser *parser);

int main(void) {
    Parser parser;
    const unsigned char data[] = { 0x01 };
    unsigned long size = sizeof(data);

    if (parser_from_memory(&parser, data, size) != 0) {
        return 1;
    }

    Node node = parser_next(&parser);
    node_process(&node);

    parser_free(&parser);

    return 0;
}
