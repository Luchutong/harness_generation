"""Shared validation policies for generated harnesses."""

from __future__ import annotations


FORBIDDEN_LOGGING_FUNCTIONS = frozenset({
    "fprintf", "perror", "printf", "putchar", "puts", "vfprintf", "vprintf",
})

DEFAULT_ALLOWED_FUNCTIONS = frozenset({
    "abort", "assert", "calloc", "free", "malloc", "memcmp", "memcpy",
    "memmove", "memset", "realloc", "strchr", "strcmp", "strlen",
    "strncmp", "strnlen", "strrchr",
})

FORBIDDEN_IO_FUNCTIONS = frozenset({
    "fclose", "fdopen", "fgetpos", "fopen", "fread", "freopen", "fseek",
    "fsetpos", "ftell", "fwrite", "rewind", "tmpfile",
})
