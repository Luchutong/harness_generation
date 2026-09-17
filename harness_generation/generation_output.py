"""Conservative normalization for generated source-code responses."""

from __future__ import annotations


def normalize_c_response(content: str) -> str:
    """Remove one complete outer Markdown source fence while preserving raw output.

    Prose outside the fence, nested fences, and partial fences are deliberately
    left untouched so the existing syntax validators still reject them.
    """
    stripped = content.strip()
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
