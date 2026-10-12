"""Source-completeness feedback and bounded fragment recovery.

Coverage means exact issued bytes, not a saved get_function/truncated label.
Structural recursion/loop observations explain missing rules and grant no proof.
"""
from ..semantic_discovery.models import digest
from ..semantic_discovery.tools import ToolBudgetExceeded, _walk, _text
from ..source_evidence import complete_bodies


def authenticated_records(snapshot, evidence):
    records = evidence.get("records", []) if isinstance(evidence, dict) and "records" in evidence else evidence
    records = records if isinstance(records, dict) else {r.get("evidence_id"): r for r in records if isinstance(r, dict)}
    accepted = {}
    for eid, record in records.items():
        if not isinstance(record, dict) or not isinstance(eid, str):
            continue
        raw = {key: value for key, value in record.items() if key != "evidence_id"}
        expected_hash = snapshot.artifacts.source_hashes.get(record.get("source"))
        try:
            expected = "ev_" + digest({"snapshot": snapshot.source_fingerprint, "record": raw})[:32]
        except (TypeError, ValueError):
            continue
        if record.get("evidence_id") == expected == eid and expected_hash == record.get("source_sha256") and expected_hash:
            accepted[eid] = record
    return accepted


def source_coverage(snapshot, evidence, authorized_ids):
    complete = complete_bodies(snapshot.functions, authenticated_records(snapshot, evidence), snapshot.artifacts.source_hashes)
    return sorted(set(complete) & set(authorized_ids))


def validate_source_query(query, snapshot, authorized_ids):
    """A recovery fragment may not expand the frozen function authorization."""
    allowed = set(authorized_ids)
    name, arguments = query.get("tool"), query.get("arguments", {})
    if name == "get_function":
        if set(arguments) != {"function"} or arguments["function"] not in allowed:
            raise ValueError("recovery query attempted to authorize an undiscovered API")
        return
    if name != "read_source_range" or set(arguments) != {"file", "line_start", "line_end"}:
        raise ValueError("invalid recovery source query")
    start, end = arguments["line_start"], arguments["line_end"]
    if (type(start) is not int or type(end) is not int or start < 1 or end < start or not any(
            function.get("defined") and function.get("body") and function["file"] == arguments["file"]
            and function["end_line"] - function["body"].count("\n") <= start <= end <= function["end_line"]
            for fid, function in snapshot.functions.items() if fid in allowed)):
        raise ValueError("recovery fragment outside authorized function body")


def structural_summary_gaps(snapshot, evidence, authorized_ids, function_id, *, maximum=64):
    """Inspect issued complete bodies, including calls nested inside loops.

    This syntactic diagnostic does not certify a call target, allocator, release,
    ownership, or path. Incomplete/unauthorized bodies are never traversed.
    """
    from ..harness_context.value_flow import body_tree, unique_callee
    complete = set(source_coverage(snapshot, evidence, authorized_ids))
    graph, loops, pending = {}, set(), [function_id]
    while pending and len(graph) < maximum:
        fid = pending.pop()
        if fid in graph or fid not in complete:
            continue
        function = snapshot.functions[fid]
        source, body = body_tree(function)
        if body is None or body.has_error:
            continue
        targets = set()
        for node in _walk(body):
            if node.type in {"for_statement", "while_statement", "do_statement"}:
                loops.add(fid)
            if node.type != "call_expression":
                continue
            callee = node.child_by_field_name("function")
            if callee is None or callee.type != "identifier":
                continue
            target = unique_callee(snapshot, _text(callee, source), function)
            if target and target["id"] in complete:
                targets.add(target["id"])
        graph[fid] = sorted(targets)
        pending.extend(targets - set(graph))
    recursive, done = set(), set()
    def visit(fid, active):
        if fid in active:
            recursive.update(active[active.index(fid):])
            return
        if fid in done:
            return
        for callee in graph.get(fid, ()):
            visit(callee, (*active, fid))
        done.add(fid)
    for fid in graph:
        visit(fid, ())
    reasons = []
    if recursive:
        reasons.append("requires_recursive_summary")
    if loops:
        reasons.append("requires_loop_summary")
    return {"reason_codes": reasons, "recursive_function_ids": sorted(recursive), "loop_function_ids": sorted(loops),
        "scanned_function_ids": sorted(graph), "scan_truncated": bool(pending),
        "observation_class": "syntactic_diagnostic_only", "generation_authority": False}


def enrich_diagnosis(diagnosis, result, *, snapshot=None, evidence=None, authorized_ids=()):
    """Expose the underlying summary gaps without treating them as proof."""
    summaries = result.get("effect_bundle", {}).get("function_summaries", [])
    summary = next((row for row in summaries if row.get("function_id") == diagnosis.get("function_id")), None)
    if summary is None:
        return diagnosis
    reasons = [r[:512] for r in summary.get("unresolved", []) if isinstance(r, str)][:32]
    missing = sorted({reason.split(":", 1)[1] for reason in reasons
        if reason.startswith("incomplete_function_body:")})
    if missing:
        allowed = set(authorized_ids)
        blocked = sorted(set(missing) - allowed) if snapshot is not None else []
        diagnosis.update(missing_function_ids=missing, blocked_function_ids=blocked)
        if diagnosis.get("root_cause") in {"unsupported_effect", "missing_source"}:
            diagnosis["root_cause"] = "upstream_scope_blocked" if blocked else "missing_source"
    if reasons:
        diagnosis["summary_reason_codes"] = reasons
    if snapshot is not None and evidence is not None and diagnosis.get("function_id"):
        structural = structural_summary_gaps(snapshot, evidence, authorized_ids, diagnosis["function_id"])
        if structural["reason_codes"]:
            diagnosis["structural_summary_gaps"] = structural
            if diagnosis.get("kind") in {"cleanup_same_object", "resource_lifecycle_complete"}:
                diagnosis["release_scope_gap"] = "owned_graph_scope_unverified"
    return diagnosis


def collect_missing_source(tools, snapshot, evidence, authorized_ids, *, prioritized=(), attempts=None):
    """Read exact finite fragments after get_function is too large.

    Partial progress survives budget exhaustion. Each query uses the existing
    repository scope, max lines/record/chars/tool calls, and stale-source checks.
    """
    attempts = [] if attempts is None else attempts
    records = authenticated_records(snapshot, evidence)
    before = source_coverage(snapshot, records, authorized_ids)
    missing = set(authorized_ids) - set(before)
    ordered = [fid for fid in dict.fromkeys(prioritized) if fid in missing]
    ordered.extend(sorted(missing - set(ordered)))
    queries, failures = [], []
    def execute(name, arguments):
        if len(attempts) >= tools.budget.max_tool_calls:
            raise ToolBudgetExceeded("max_tool_calls")
        validate_source_query({"tool": name, "arguments": arguments}, snapshot, authorized_ids)
        attempts.append({"tool": name, "arguments": arguments})
        result = tools.execute(name, arguments)
        queries.append({"tool": name, "arguments": arguments, "result": result})
        records.update(tools.evidence)
        return result
    try:
        for fid in ordered:
            function = snapshot.functions[fid]
            if not function.get("defined") or not function.get("body"):
                failures.append({"function_id": fid, "reason": "source_definition_unavailable"})
                continue
            result = execute("get_function", {"function": fid})
            if fid in source_coverage(snapshot, records, authorized_ids):
                continue
            if result.get("error"):
                failures.append({"function_id": fid, "reason": result["error"]})
                continue
            first = function["end_line"] - function["body"].count("\n")
            cursor = first
            while cursor <= function["end_line"] and fid not in source_coverage(snapshot, records, authorized_ids):
                end = min(function["end_line"], cursor + tools.budget.max_lines_per_read - 1)
                response = execute("read_source_range", {"file": function["file"], "line_start": cursor, "line_end": end})
                pages = [row for row in response.get("evidence", []) if row.get("origin") == "owned_live_source"]
                if not pages:
                    failures.append({"function_id": fid, "reason": response.get("error", "source_range_unavailable")})
                    break
                page = pages[0]
                # A truncated final line supplies no complete coverage. Re-read
                # it next time rather than stepping past unobserved bytes.
                next_line = page["line_start"] + page.get("content", "").count("\n") if page.get("truncated") else page["line_end"] + 1
                if next_line <= cursor:
                    failures.append({"function_id": fid, "reason": "source_line_exceeds_record_budget"})
                    break
                cursor = next_line
    except ToolBudgetExceeded as error:
        failures.append({"reason": "source_recovery_budget_exhausted", "detail": str(error)})
    after = source_coverage(snapshot, records, authorized_ids)
    return {"queries": queries, "coverage_before": before, "coverage_after": after,
        "missing_after": sorted(set(authorized_ids) - set(after)), "failures": failures,
        "source_completeness_is_not_semantic_proof": True}
