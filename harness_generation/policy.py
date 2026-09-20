"""The single authority for the function-name sets validation is built on.

Each of these was written down twice -- once in :mod:`validation`, once in
:mod:`stage4` -- and the two copies were free to drift.  They did: the logging
set was seven names in one file and two in the other, so ``puts`` in a generated
harness was a refusal in one audit and invisible in the next.  Which set a
harness met depended on which audit happened to look at it, and nothing in the
repository said which was meant.

So there is one copy now, here, and the audits import it.  The names are the
ones the validators already used, because a second vocabulary for the same set
is the same disease in a different place.

Changing a set here changes every audit at once.  That is the point, and it is
why ``tests/test_policy.py`` pins the contents item by item: a set that can
change silently is the problem this module exists to remove.
"""

#: Calls that write to a log.  A libFuzzer harness's only output is a crash, so
#: these are demo scaffolding that survived the transform.
FORBIDDEN_LOGGING_FUNCTIONS = frozenset({
    "fprintf", "perror", "printf", "putchar", "puts", "vfprintf", "vprintf",
})

#: Calls that open, read or seek a file.  The input comes from ``data`` and
#: ``size``; a harness that reaches the filesystem is not fuzzing its argument.
FORBIDDEN_IO_FUNCTIONS = frozenset({
    "fclose", "fdopen", "fgetpos", "fopen", "fread", "freopen", "fseek",
    "fsetpos", "ftell", "fwrite", "rewind", "tmpfile",
})

#: The standard C functions a harness may call without the project having to
#: declare them.  Everything outside this set and outside the project's own
#: functions is an invented API.
DEFAULT_ALLOWED_FUNCTIONS = frozenset({
    "abort", "assert", "calloc", "free", "malloc", "memcmp", "memcpy",
    "memmove", "memset", "realloc", "strchr", "strcmp", "strlen",
    "strncmp", "strnlen", "strrchr",
})
