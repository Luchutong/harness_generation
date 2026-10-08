"""Generic source-view identity and fragmented-proof counterexamples."""
from copy import deepcopy
from dataclasses import replace
import hashlib

import pytest

from harness_generation.context_generation.persistence import load_frozen_inputs
from harness_generation.harness_context.value_flow import complete_bodies
from harness_generation.semantic_discovery.tools import RepositoryTools
from harness_generation.source_snapshot import authenticated_c_source
from test_context_generation import ready
from test_harness_context import CONTEXT, setup


@pytest.mark.parametrize("condition", ["defined(__cplusplus)", "defined __cplusplus", "__cplusplus",
    "(defined(__cplusplus))", "(OTHER) && (defined(__cplusplus))"])
def test_cpp_projection_recognizes_balanced_positive_conditions(condition):
    from sfg_builder.parser import _c_view
    source = ("#if " + condition + "\nint cpp_only;\n#else\nint c_only;\n#endif\n").encode()
    projected = _c_view(source)
    assert b"cpp_only" not in projected and b"c_only" in projected
    assert len(projected) == len(source) and projected.count(b"\n") == source.count(b"\n")


@pytest.mark.parametrize("condition", ["!defined(__cplusplus)", "defined(__cplusplus) == 0", "defined(__cplusplus) || OTHER"])
def test_cpp_projection_does_not_erase_c_or_unknown_conditions(condition):
    from sfg_builder.parser import _c_view
    source = ("#if " + condition + "\nint can_be_c;\n#endif\n").encode()
    assert b"can_be_c" in _c_view(source)


def test_preparation_completes_long_wrapper_dependency_inside_budget(tmp_path):
    from harness_generation.harness_context.construction import prepare_local_evidence
    from harness_generation.harness_context.models import ContextBudget
    from harness_generation.harness_context.requirements import HarnessRequirementBuilder
    source = ("int engine(const unsigned char *p, unsigned long n) {\n int k = 0;\n" +
        " k += n ? p[0] : 0;\n" * 90 + " return k;\n}\n" +
        "int parse(const unsigned char *p, unsigned long n) { return engine(p, n); }\n")
    prepared = setup(tmp_path, source=source, budget=ContextBudget(
        max_chars_per_record=1500, max_lines_per_read=12, max_preparation_tool_calls=16))
    tools = prepared[5]
    req = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"][0]
    tools.activate(req)
    tools.bootstrap()
    before = prepared[4].tool_calls
    events = prepare_local_evidence(tools)
    engine = prepared[0][-1]["engine"]
    assert engine in complete_bodies(prepared[3], prepared[4].evidence)
    assert any(e.get("tool") == "read_source_range" for e in events)
    charged = sum(e.get("kind") == "tool_call" and e.get("tool_executed") is True for e in events)
    assert prepared[4].tool_calls - before == charged <= prepared[4].budget.max_preparation_tool_calls
    assert prepared[4].budget.max_tool_calls == 64
    assert prepared[4].tool_calls <= prepared[4].budget.max_tool_calls
    assert prepared[4].source_chars <= prepared[4].budget.max_source_chars


def test_source_completion_keeps_missing_proof_when_budget_is_small(tmp_path):
    from harness_generation.harness_context.construction import prepare_local_evidence
    from harness_generation.harness_context.models import ContextBudget
    from harness_generation.harness_context.requirements import HarnessRequirementBuilder
    source = "int parse(const unsigned char *p, unsigned long n) {\n int k=0;\n" + " k += n ? p[0] : 0;\n" * 90 + " return k;\n}\n"
    prepared = setup(tmp_path, source=source, budget=ContextBudget(max_tool_calls=3, max_chars_per_record=1500, max_lines_per_read=4))
    tools = prepared[5]
    req = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"][0]
    tools.activate(req)
    tools.bootstrap()
    prepare_local_evidence(tools)
    fid = prepared[0][-1]["parse"]
    assert fid not in complete_bodies(prepared[3], prepared[4].evidence)
    assert prepared[4].tool_calls == 2
    # The preparation cap leaves the final query available to the Agent. A
    # further real source fragment costs that query without proving a gap-free
    # body: the unread middle of this long function still matters.
    function = prepared[3].functions[fid]
    extra = tools.execute("read_source_range", {"file": function["file"],
        "line_start": function["end_line"] - 3, "line_end": function["end_line"]})
    assert not extra.get("error") and extra["evidence_ids"]
    assert prepared[4].tool_calls == prepared[4].budget.max_tool_calls == 3
    assert fid not in complete_bodies(prepared[3], prepared[4].evidence)


def test_projected_cpp_declaration_authenticates_raw_identity(tmp_path):
    source = "#include <stdlib.h>\n" + CONTEXT.replace(
        "int ready; int calls;", "int ready; int calls;\n#ifdef __cplusplus\n int value() const { return calls; }\n#endif\n")
    store, frozen, plan = ready(tmp_path, "context", source_override=source)
    index = frozen[-1]
    path = index.owned_path("api.c")
    assert plan["resources"]
    assert authenticated_c_source(frozen[3].artifacts, "api.c", path.read_bytes())
    tools = RepositoryTools(frozen[3].artifacts, index.catalog, index=index)
    result = tools.execute("read_source_range", {"file": "api.c", "line_start": 1, "line_end": 9})
    assert not result.get("error") and result["evidence"][0]["source_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    # The erased C++ branch changes no projected C declarations. Raw identity
    # must still reject it, including through the actual frozen-generation gate.
    path.write_text(source.replace("return calls;", "return calls + 1;"))
    with pytest.raises(ValueError, match="raw source snapshot"):
        load_frozen_inputs(store, frozen[0]["ft_id"])
    assert tools.execute("read_source_range", {"file": "api.c", "line_start": 1, "line_end": 9})["error"]


def fragments(tmp_path):
    source = "int parse(const unsigned char *data, unsigned long size) {\n int value = 0;\n" + (
        " value += size ? data[0] : 0;\n" * 24) + " return value;\n}\n"
    prepared = setup(tmp_path, source=source)
    snapshot = prepared[3]
    function = snapshot.functions[prepared[0][-1]["parse"]]
    lines = source.splitlines(keepends=True)
    sha = hashlib.sha256(source.encode()).hexdigest()
    records = {}
    for start in range(1, len(lines) + 1, 6):
        end = min(start + 5, len(lines))
        eid = "piece_" + str(start)
        records[eid] = {"tool": "read_source_range", "source": "api.c", "origin": "owned_live_source",
            "source_sha256": sha, "line_start": start, "line_end": end,
            "content": "".join(lines[start-1:end]), "truncated": False}
    return snapshot, function, records


def test_gap_free_ranges_close_a_long_body(tmp_path):
    snapshot, function, records = fragments(tmp_path)
    assert complete_bodies(snapshot, records)[function["id"]] == set(records)
    # Repeated interior lines are matched at declared coordinates, rather than
    # requiring unique text matches or guessing by a parameter/function name.
    assert len(records) > 1


@pytest.mark.parametrize("damage", ["gap", "wrong_content", "wrong_file", "mixed_hash", "partial_final_line"])
def test_inconsistent_fragments_do_not_prove_a_body(tmp_path, damage):
    snapshot, function, records = fragments(tmp_path)
    records = deepcopy(records)
    middle = sorted(records, key=lambda eid: records[eid]["line_start"])[1]
    if damage == "gap":
        records.pop(middle)
    elif damage == "wrong_content":
        records[middle]["content"] = records[middle]["content"].replace("data[0]", "data[1]")
    elif damage == "wrong_file":
        records[middle]["source"] = "another.c"
    elif damage == "mixed_hash":
        records[middle]["source_sha256"] = "0" * 64
    else:
        last = max(records, key=lambda eid: records[eid]["line_end"])
        records[last]["content"] = records[last]["content"].rstrip()[:-1]
        records[last]["truncated"] = True
    assert function["id"] not in complete_bodies(snapshot, records)


def test_legacy_partial_prefix_and_same_version_ranges_can_join(tmp_path):
    snapshot, function, records = fragments(tmp_path)
    first = min(records, key=lambda eid: records[eid]["line_start"])
    end = records[first]["line_end"]
    body_lines = function["body"].splitlines(keepends=True)
    records[first] = {"tool": "get_function", "source": "api.c", "function_id": function["id"],
        "content": "".join(body_lines[:end]), "truncated": True}
    assert function["id"] in complete_bodies(snapshot, records)


def test_raw_hash_participates_in_phase1_identity(tmp_path):
    snapshot, function, records = fragments(tmp_path)
    changed = replace(snapshot.artifacts, source_hashes={"api.c": "0" * 64})
    from harness_generation.minimal_ft.models import ProjectSnapshot
    updated = ProjectSnapshot.from_artifacts(changed)
    assert updated.source_fingerprint != snapshot.source_fingerprint
    assert updated.functions_fingerprint != snapshot.functions_fingerprint
    assert not complete_bodies(updated, records)


@pytest.mark.parametrize("release,consumer,helper", [("z_close", "a_display", "discard_impl"),
    ("a_close", "z_display", "unrelated_spelling")])
def test_scheduling_uses_effect_and_type_hints_not_api_spelling(tmp_path, release, consumer, helper):
    from harness_generation.harness_context.loop import investigation_priority
    source = ("typedef struct Product { int v; } Product;\n"
        "typedef struct Settings { void (*drop)(void*); } Settings;\n"
        "Product *parse(const unsigned char *p, unsigned long n) { return malloc(sizeof(Product)); }\n"
        "static void " + helper + "(void *p) { free(p); }\n"
        "void " + release + "(Product *p) { Settings s={0}; s.drop=" + helper + "; s.drop(p); }\n"
        "void " + consumer + "(Product *p) { if(p) puts(\"value\"); }\n")
    prepared = setup(tmp_path, source=source)
    ids, snapshot = prepared[0][-1], prepared[3]
    report = {"semantic_obligation_graph": {"frontier": [], "nodes": []}}
    def row(name):
        return {"requirement_id": name, "subject_function_id": ids[name], "mandatory": False,
                "required_by": [ids["parse"]]}
    assert investigation_priority(row(release), snapshot, report) < investigation_priority(row(consumer), snapshot, report)
    assert investigation_priority(row(helper), snapshot, report) > investigation_priority(row(release), snapshot, report)
    # A ranking hint does not issue an API choice or claim a local proof.
    assert not prepared[4].evidence and not prepared[4].model_calls
