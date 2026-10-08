"""Shared source coverage; only exact, version-consistent bytes close a body."""
from collections import defaultdict


def complete_bodies(functions, records, source_hashes=None):
    """Accept full records or consistent, gap-free fragments of the indexed body.

    Range fragments are checked at their exact lines against the snapshot, and
    never joined across raw-file hashes. Truncated prefixes prove only the bytes
    actually supplied; a truncated range's last incomplete line proves nothing.
    The analysis still uses the indexed AST and its existing conservative rules.
    """
    result = defaultdict(set)
    fragments = defaultdict(list)
    for eid, record in records.items():
        if record.get("tool") not in {
                "get_function", "read_source_range", "find_resource_flows", "find_function_argument_usages"}:
            continue
        ids = {record.get("function_id"), record.get("caller_id")}
        if record.get("tool") == "read_source_range":
            ids.update(fid for fid, f in functions.items() if f["file"] == record.get("source")
                and f["start_line"] <= record.get("line_end", 0) and f["end_line"] >= record.get("line_start", 0))
        for fid in ids:
            function = functions.get(fid)
            if not function or not function.get("defined") or not function.get("body"):
                continue
            # Old complete-body fixtures/records identify the source by exact
            # function ID. Range fragments always require explicit coordinates.
            if (record.get("source") is not None and record["source"] != function["file"]) or (
                    record.get("tool") == "read_source_range" and record.get("source") != function["file"]):
                continue
            expected_hash = (source_hashes or {}).get(function["file"])
            sha = record.get("source_sha256")
            if expected_hash and sha and sha != expected_hash:
                continue
            body, content = function["body"], record.get("content", "")
            if not record.get("truncated") and body in content:
                result[fid].add(eid)
            if record.get("tool") != "read_source_range":
                if content and body.startswith(content):
                    fragments[fid].append((sha, 0, len(content), eid))
                continue
            if not sha or record.get("origin") != "owned_live_source":
                continue
            lines = body.splitlines(keepends=True)
            first_line = function["end_line"] - body.count("\n")
            supplied = content.splitlines(keepends=True)
            if record.get("truncated") and supplied and not supplied[-1].endswith("\n"):
                supplied.pop()
            offset = 0
            pieces = []
            valid = True
            for number, line in enumerate(lines):
                coordinate = first_line + number
                if record.get("line_start", 0) <= coordinate <= record.get("line_end", 0):
                    index = coordinate - record["line_start"]
                    if index >= len(supplied):
                        continue
                    actual = supplied[index]
                    # Definition boundary lines can also contain the signature
                    # or trailing newline; interior lines must match exactly.
                    match = (line.rstrip("\r\n") in actual.rstrip("\r\n") if number in {0, len(lines)-1}
                             else line == actual)
                    if not match:
                        valid = False
                        break
                    pieces.append((sha, offset, offset + len(line), eid))
                offset += len(line)
            if valid:
                fragments[fid].extend(pieces)
    for fid, pieces in fragments.items():
        versions = {sha for sha, *_ in pieces if sha}
        for version in versions or {None}:
            selected = sorted((start, end, eid) for sha, start, end, eid in pieces if sha in {None, version})
            covered, used = 0, set()
            for start, end, eid in selected:
                if start > covered:
                    break
                covered = max(covered, end)
                used.add(eid)
            if covered == len(functions[fid]["body"]):
                result[fid].update(used)
    return result
