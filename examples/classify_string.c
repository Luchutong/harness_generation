#include <string.h>

/* text must be a non-null, NUL-terminated C string. */
static int classify_string(const char *text) {
    size_t length = strlen(text);
    if (length == 0) return 0;
    if (strcmp(text, "hello") == 0) return 1;
    if (length >= 4 && strncmp(text, "GET ", 4) == 0) return 2;
    return 3;
}
