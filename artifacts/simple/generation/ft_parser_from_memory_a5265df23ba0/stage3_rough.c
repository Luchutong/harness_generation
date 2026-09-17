#include "parser.h"
void rough_sequence(Parser *parser, const unsigned char *data, unsigned long size)
{
    parser_from_memory(parser, data, size);
    Node node = parser_next(parser);
    node_process(&node);
    parser_free(parser);
}
