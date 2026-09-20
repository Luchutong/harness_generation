"""Shared validation policies for generated harnesses."""

from __future__ import annotations


FORBIDDEN_LOGGING_FUNCTIONS = frozenset({
    "fprintf", "perror", "printf", "putchar", "puts", "vfprintf", "vprintf",
})
