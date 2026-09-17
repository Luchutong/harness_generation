#include "parser.h"

int main(void) {
    Parser parser;
    const unsigned char data[] = {0x01, 0x02, 0x03};
    int rc = parser_from_memory(&parser, data, sizeof(data));
    if (rc != 0) {
        return 0;
    }

    Node node = parser_next(&parser);
    node_process(&node);

    parser_free(&parser);
    return 0;
}
