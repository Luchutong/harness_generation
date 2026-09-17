"""Atomic JSON records shared by candidates and experiments."""

import json
from pathlib import Path


def write_json(path: Path, data: object, *, sort_keys: bool = False,
               allow_nan: bool = True) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            sort_keys=sort_keys,
            allow_nan=allow_nan,
        ) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
