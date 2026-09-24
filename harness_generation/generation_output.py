"""Conservative normalization for generated source-code responses."""

from __future__ import annotations

import re


# A transport delimiter the model echoed back, such as a stray ``</stdin>``
# line. No C or C++ translation unit ends with a bare tag, so one is always an
# artifact of the response envelope rather than generated code.
_WRAPPER_TAG = re.compile(r"(?:</?[^<>\n]+>)+")


def normalize_c_response(content: str) -> str:
    """Remove one complete outer Markdown source fence while preserving raw output.

    Prose outside the fence, nested fences, and partial fences are deliberately
    left untouched so the existing syntax validators still reject them.
    """
    stripped = _strip_wrapper_tags(content.strip())
    lines = stripped.splitlines()
    if len(lines) < 3:
        return stripped
    opening = lines[0].strip().lower()
    if opening not in {"```", "```c", "```cpp", "```c++"} or lines[-1].strip() != "```":
        return stripped
    inner = "\n".join(lines[1:-1]).strip()
    if "```" in inner:
        return stripped
    return inner


def _strip_wrapper_tags(content: str) -> str:
    """Drop trailing echoed transport delimiters, keeping the code itself."""
    lines = content.splitlines()
    end = len(lines)
    while end > 1 and _WRAPPER_TAG.fullmatch(lines[end - 1].strip()):
        end -= 1
    return content if end == len(lines) else "\n".join(lines[:end])
