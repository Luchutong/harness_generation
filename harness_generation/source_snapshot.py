"""Authenticate raw file identity and compare the same C view used by Phase 1."""
import hashlib
import re

from sfg_builder.parser import _c_view

VERSION = "authenticated-c-source-view-v1"


def authenticated_c_source(artifacts, filename, data):
    """Legacy artifacts keep declaration checks; new ones also bind ALL raw bytes.

    C++ regions are ignored only for declaration matching, never for identity.
    This projection does not evaluate arbitrary build macros or select branches.
    """
    expected = artifacts.source_hashes.get(filename)
    if expected is not None and hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("live source differs from the frozen raw source snapshot")
    text = _c_view(data).decode("utf-8")
    normalized = re.sub(r"\s+", "", text)
    for function in artifacts.functions:
        if function["file"] == filename and function.get("defined") and (
                function.get("body", "") not in text or
                re.sub(r"\s+", "", function["signature"].rstrip(";")) not in normalized):
            raise ValueError("live source differs from the frozen function snapshot")
    for declaration in (*artifacts.structs, *artifacts.callback_typedefs):
        if declaration["file"] == filename and re.sub(r"\s+", "", declaration["declaration"]) not in normalized:
            raise ValueError("live source differs from the frozen type snapshot")
    return text
