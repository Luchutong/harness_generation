#include "../include/parser.h"

int parser_from_memory(
    Parser *parser,
    const unsigned char *data,
    unsigned long size)
{
    if (size == 0) return -1;
    parser->state = data[0];
    return 0;
}

Node parser_next(Parser *parser)
{
    Node n;
    n.value = parser->state;
    return n;
}

void node_process(Node *node)
{
    node->value++;
}

void parser_free(Parser *parser)
{
    (void)parser;
}
