"""Narrow source queries, callback-reference scope and non-proof boundaries."""
import pytest

from harness_generation.harness_context.models import ContextBudget
from harness_generation.harness_context.requirements import HarnessRequirementBuilder
from harness_generation.harness_context.value_flow import complete_bodies
from harness_generation.semantic_discovery.tools import ToolBudgetExceeded
from test_harness_context import setup


SOURCE = """typedef unsigned long size_t;
typedef struct Object { int value; } Object;
typedef struct Options { void (*drop)(void *, void *); void *user; } Options;
static void discard(void *p, void *user) { free(p); }
static void other(void *p, void *user) { (void)p; }
void dispatch(Options *opts, Object *p) {
 if (!p) return;
 while (p) {
  Object *alias=p;
  p=0;
  opts->drop(alias, opts->user);
 }
}
Object *parse(const unsigned char *data, size_t size) {
 Options a={0}, b={0};
 a.drop=discard;
 if (size) b.drop=other;
 else b.drop=discard;
 dispatch(&a, (Object*)data);
 return 0;
}
"""


def active(tmp_path, source=SOURCE, budget=None):
    prepared = setup(tmp_path, source=source, budget=budget)
    tools = prepared[5]
    requirement = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"][0]
    tools.activate(requirement)
    return prepared, tools, prepared[0][-1]


def test_field_writes_preserve_receivers_conditions_and_discover_reference(tmp_path):
    prepared, tools, ids = active(tmp_path)
    result = tools.execute("find_field_writes", {"function": ids["parse"], "field": "drop"})
    rows = result["evidence"]
    assert [(r["receiver_expression"], r["assigned_expression"]) for r in rows] == [
        ("a", "discard"), ("b", "other"), ("b", "discard")]
    assert not rows[0]["control_context"]
    assert rows[1]["control_context"][0]["branch"] == "then"
    assert rows[2]["control_context"][0]["branch"] == "else"
    assert ids["discard"] in rows[0]["possible_callee_ids"]
    assert ids["discard"] in tools.scope_ids
    assert all(r["syntactic_only"] and r["source_sha256"] for r in rows)
    assert tools.execute("get_function", {"function": ids["discard"]})["evidence_ids"]
    # A function-reference discovery issues neither a cleanup choice nor proof.
    assert not any(r["reason"] == "cleanup" for r in result["signed_proposal_registry"]["support_candidates"])


def test_call_sites_keep_actual_arguments_and_loop_context(tmp_path):
    prepared, tools, ids = active(tmp_path)
    tools.execute("find_callees", {"function": ids["parse"]})
    result = tools.execute("get_call_sites", {"function": ids["dispatch"], "callee": "drop"})
    row, = result["evidence"]
    assert row["callee_expression"] == "opts->drop"
    assert row["argument_expressions"] == ["alias", "opts->user"]
    assert row["dispatch_kind"] == "indirect_syntax" and not row["possible_callee_ids"]
    assert row["control_context"] == [{"kind": "while", "condition": "(p)", "line": 8}]
    assert row["line_start"] == 11
    # Calls through a member are not resolved by a matching field spelling.
    assert ids["discard"] not in tools.scope_ids


def test_control_context_uses_absolute_line_and_rejects_outside_body(tmp_path):
    _, tools, ids = active(tmp_path)
    row, = tools.execute("get_control_context", {"function": ids["parse"], "line": 18})["evidence"]
    assert row["content"] == "b.drop=discard;"
    assert row["line_start"] == row["line_end"] == 18
    assert row["control_context"][0]["branch"] == "else"
    assert tools.execute("get_control_context", {"function": ids["parse"], "line": 2})["error"]


def test_designated_callback_initializer_is_a_reference_not_resolved_target(tmp_path):
    _, tools, ids = active(tmp_path, SOURCE.replace("Options a={0}, b={0};\n a.drop=discard;",
        "Options a={.drop=&discard}, b={0};"))
    rows = tools.execute("find_field_writes", {"function": ids["parse"], "field": "drop"})["evidence"]
    first = rows[0]
    assert first["operator"] == "designated_initializer" and first["receiver_expression"] == "a"
    assert first["possible_callee_ids"] == [ids["discard"]]


def test_shadowed_function_address_is_not_discovered(tmp_path):
    source = SOURCE.replace("Options a={0}, b={0};", "void (*discard)(void*,void*)=0;\n Options a={0}, b={0};")
    _, tools, ids = active(tmp_path, source)
    row = tools.execute("find_field_writes", {"function": ids["parse"], "field": "a.drop"})["evidence"][0]
    assert not row["possible_callee_ids"] and ids["discard"] not in tools.scope_ids


@pytest.mark.parametrize("tool,extra", [
    ("find_field_writes", {"field": "drop"}), ("get_call_sites", {"callee": "*"}),
    ("get_control_context", {"line": 4})])
def test_detail_queries_cannot_read_undiscovered_functions(tmp_path, tool, extra):
    _, tools, ids = active(tmp_path)
    result = tools.execute(tool, {"function": ids["discard"], **extra})
    assert result["error"] == "outside_requirement_scope_use_discovery_tool" and not result["evidence_ids"]


def test_function_reference_obeys_discovery_budget(tmp_path):
    _, tools, ids = active(tmp_path, budget=ContextBudget(max_discovered_functions=0))
    result = tools.execute("find_field_writes", {"function": ids["parse"], "field": "a.drop"})
    assert result["evidence"] and ids["discard"] not in tools.scope_ids
    assert {b["reason"] for b in result["blocked_discoveries"]} == {"discovery_or_depth_budget"}


def test_detail_evidence_is_bounded_cached_and_not_a_complete_body(tmp_path):
    prepared, tools, ids = active(tmp_path, budget=ContextBudget(max_references_per_query=1))
    result = tools.execute("find_field_writes", {"function": ids["parse"], "field": "drop"})
    assert len(result["evidence"]) == 1 and result["total_matches"] == 3 and result["query_truncated"]
    chars = prepared[4].source_chars
    cached = tools.execute("find_field_writes", {"function": ids["parse"], "field": "drop"})
    assert result["evidence_ids"] == cached["evidence_ids"] and prepared[4].source_chars == chars
    assert prepared[4].tool_calls == 2 and prepared[4].evidence_cache_hits == 1
    assert not complete_bodies(prepared[3], prepared[4].evidence)


def test_detail_source_budget_failure_rolls_back_evidence(tmp_path):
    prepared, tools, ids = active(tmp_path, budget=ContextBudget(max_source_chars=100))
    with pytest.raises(ToolBudgetExceeded):
        tools.execute("find_field_writes", {"function": ids["parse"], "field": "drop"})
    assert not prepared[4].evidence and not tools.visible_ids and prepared[4].source_chars == 0


def test_call_query_preserves_short_circuit_guard(tmp_path):
    _, tools, ids = active(tmp_path, SOURCE.replace("dispatch(&a, (Object*)data);", "size && (discard((void*)data, 0), 1);"))
    row, = tools.execute("get_call_sites", {"function": ids["parse"], "callee": "discard"})["evidence"]
    assert row["control_context"][0]["kind"] == "short_circuit"
    assert row["control_context"][0]["condition"] == "size"


def test_detail_query_excludes_comment_and_string_names(tmp_path):
    source=SOURCE.replace("a.drop=discard;", '/* a.drop=other; */\n puts("a.drop=other;");\n a.drop=discard;')
    _, tools, ids = active(tmp_path, source)
    assert len(tools.execute("find_field_writes", {"function": ids["parse"], "field": "drop"})["evidence"]) == 3


def test_query_cannot_turn_a_callback_reference_into_signed_cleanup(tmp_path):
    from harness_generation.harness_context.proposals import registry
    prepared, tools, ids = active(tmp_path)
    tools.bootstrap()
    tools.execute("find_field_writes", {"function": ids["parse"], "field": "drop"})
    tools.execute("get_function", {"function": ids["discard"]})
    tools.execute("find_callees", {"function": ids["parse"]})
    tools.execute("get_function", {"function": ids["dispatch"]})
    assert not any(c["function_id"] in {ids["discard"], ids["dispatch"]} and c["reason"] == "cleanup"
                   for c in registry(tools)["support_candidates"])


def test_detail_query_is_reused_on_the_same_requirement(tmp_path):
    prepared, tools, ids = active(tmp_path)
    result = tools.execute("find_field_writes", {"function": ids["parse"], "field": "a.drop"})
    requirement = tools.requirement
    charged = prepared[4].source_chars
    tools.activate(requirement)
    assert set(result["evidence_ids"]) <= tools.visible_ids
    assert prepared[4].source_chars == charged


def test_agenda_recommends_narrow_detail_without_issuing_proof(tmp_path):
    from harness_generation.harness_context.agent import HarnessContextAgent
    from harness_generation.semantic_discovery import FakeAgentModel, AgentModelResponse, AgentToolCall
    from harness_generation.semantic_discovery.models import canonical
    # Exercise parameter ownership's generic detail agenda. A scalar result
    # creates no returned-resource cleanup priority, and disabling preparation
    # keeps the exact helper undiscovered until a real query is executed.
    source = SOURCE.replace("Object *parse(", "int parse(")
    prepared, tools, ids = active(tmp_path, source=source,
        budget=ContextBudget(max_preparation_tool_calls=0))
    req = next(r for r in HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"]
               if r["kind"] == "ownership")
    result = {"requirement_id": req["requirement_id"], "status": "unresolved", "facts": [],
              "discovered_api_dependencies": [], "open_questions": ["Callback resource release is not proved."]}
    model = FakeAgentModel([AgentModelResponse(tool_calls=(AgentToolCall("end", "submit_requirement_resolution", canonical(result)),))])
    run = HarnessContextAgent(model, prepared[4]).investigate(req, tools)
    options = run.metadata["proof_agenda"]["slots"][0]["query_options"]
    issued = run.metadata["proof_agenda"]["issued_evidence_inventory"]
    assert any(q["tool"] == "find_field_writes" and q["arguments"] == {"function": ids["parse"], "field": "drop"}
               for q in options)
    assert any(q["tool"] == "get_call_sites" and q["arguments"] == {"function": ids["parse"], "callee": "dispatch"}
               for q in options)
    assert not any(r["tool"] in {"find_field_writes", "get_call_sites"} for r in issued)
    assert ids["dispatch"] not in tools.scope_ids
    assert run.result["status"] == "unresolved" and not run.result["facts"]
