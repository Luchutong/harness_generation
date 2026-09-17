typedef struct {
    int state;
} Parser;

typedef struct {
    int value;
} Node;

int parser_from_memory(Parser *parser, const unsigned char *data, unsigned long size);
Node parser_next(Parser *parser);
void node_process(Node *node);
void parser_free(Parser *parser);
