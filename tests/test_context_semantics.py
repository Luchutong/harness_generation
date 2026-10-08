"""Offline Slice→FT→Context→closure→Gate→Plan, plus adversarial semantics.

All contracts are explicit fixtures. No model provider is invoked by pytest.
"""
from copy import deepcopy
import json

import pytest

from harness_generation.context_generation import HarnessPlanBuilder, PlanError
from harness_generation.harness_context import HarnessRequirementBuilder
from harness_generation.harness_context.callbacks import callback_declarations
from harness_generation.harness_context.evidence import build_context
from harness_generation.harness_context.models import resolution_schema, obj, arr
from harness_generation.harness_context.terminal import terminal_schema, expand_submission, compact_submission
from harness_generation.harness_context.value_flow import resource_flows
from harness_generation.harness_context.reconciliation import VERSION as RECONCILER_VERSION
from harness_generation.semantic_discovery.models import canonical
from test_harness_context import (setup, mine, assert_gate, direct_specs, context_specs,
    argument, owner, lifecycle_value, order, OWNED, BORROWED, NUL, CALLBACK, CONTEXT)
from test_context_generation import ready
from test_semantic_slicing import fixture, run as slice_run, queries, terminal, tool

SHARED = '''#include <stdlib.h>
#include <stddef.h>
typedef struct Context { const unsigned char *data; size_t size; } Context;
Context *create(void) { return calloc(1,sizeof(Context)); }
void destroy(Context *ctx) { free(ctx); }
void feed(Context *ctx, const unsigned char *data, size_t size) { ctx->data=data; ctx->size=size; }
int parse(Context *ctx) { return ctx->size ? ctx->data[0] : 0; }
void usage(const unsigned char *data, size_t size) { Context *a=create(); Context *b=a; feed(b,data,size); parse(a); destroy(b); }
'''

REGISTERED = '''#include <stdlib.h>
#include <stddef.h>
typedef int (*ReadCallback)(void *user, const unsigned char *buf, size_t size);
typedef struct Table { ReadCallback read; } Table;
typedef struct Context { ReadCallback read; void *user; } Context;
Context *create(void) { return calloc(1,sizeof(Context)); }
void destroy(Context *ctx) { free(ctx); }
void register_table(Context *ctx, const Table *table, void *userdata) { ctx->read=table->read; ctx->user=userdata; }
int parse(Context *ctx, const unsigned char *data, size_t size) { return ctx->read(ctx->user,data,size); }
void usage(const unsigned char *data, size_t size) { Context *ctx=create(); Table table={0}; register_table(ctx,&table,0); parse(ctx,data,size); destroy(ctx); }
'''


def issued_flow(prepared, subject="parse"):
    req = next(r for r in HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"] if r["subject_function_id"] == prepared[0][-1][subject])
    prepared[5].activate(req)
    return prepared[5].execute("find_resource_flows", {"function": prepared[0][-1][subject]})


def indirect(parameter, via):
    return {"parameter": parameter, "source": "context", "transform": "field", "size_parameter": None,
        "size_relation": "none", "nul_terminated": False, "binary_zero_allowed": None, "mutable": False,
        "alignment": "none", "via_function_id": via}


def shared_ready(tmp_path, *, source=SHARED, cleanup_ownership=None, feed_initialization=False, extra_core=None):
    roles = {"parse": ("core", "accepted_anchor"), "feed": ("core", "external_input_injection"),
        "create": ("support", "resource_creation"), "destroy": ("support", "resource_cleanup")}
    if extra_core:
        roles[extra_core] = ("core", "core_processing")
    prepared = setup(tmp_path, source, roles=roles, discover_callers=bool(extra_core))
    ids = prepared[0][-1]
    parse, feed, create, destroy = [ids[n] for n in ("parse", "feed", "create", "destroy")]
    specs = {k: v for k, v in context_specs(ids).items() if k[0] != parse}
    specs.update(direct_specs(feed))
    # feed stores fuzz bytes until parse/destroy, beyond feed's return.
    specs[(feed, "ownership")]["value"]["entries"][0]["lifetime"] = "until_context_cleanup"
    for fid in (feed, parse):
        rid = "resource_model_" + ("feed" if fid == feed else "parse")
        specs[(fid, "lifecycle")] = {"value": lifecycle_value(fid, rid, "Context", "ctx", create, destroy),
            "dependencies": [{"function_id": create, "necessity": "required", "reason": "creation"},
                             {"function_id": destroy, "necessity": "required", "reason": "cleanup"}]}
        specs[(fid, "state")] = {"value": {"preconditions": [{"parameter": "ctx", "kind": "initialized" if fid == feed else "input_fed", "api": create if fid == feed else feed}]}}
        # Deliberately contradictory SOFT preferences do not corrupt the DAG.
        specs[(fid, "call_order")] = {"value": {"constraints": [order(parse, feed), order(feed, parse)]}}
    specs[(feed, "argument_construction")]["value"]["arguments"].insert(0, argument("ctx", "derived", resource="resource_model_feed"))
    specs[(feed, "ownership")]["value"]["entries"].append(owner("ctx", resource="resource_model_feed"))
    specs[(parse, "argument_construction")] = {"value": {"arguments": [argument("ctx", "derived", resource="resource_model_parse")]}}
    specs[(parse, "input_binding")] = {"value": {"bindings": [indirect("ctx", feed)]}}
    specs[(parse, "ownership")] = {"value": {"entries": [owner("ctx", resource="resource_model_parse")]}}
    specs[(parse, "return_semantics")] = {"value": {"success": "always", "nullable": None, "owned": None, "error_cleanup": False}}
    if extra_core:
        specs.update(direct_specs(ids[extra_core]))
        specs[(ids[extra_core], "call_order")] = {"value": {"constraints": []}}
    if cleanup_ownership:
        specs[(destroy, "ownership")] = {"value": {"entries": [owner("ctx", ownership=cleanup_ownership)]}}
    if feed_initialization:
        specs[(parse, "lifecycle")]["value"]["resources"][0]["initialization"] = {"mandatory": True, "api": feed}
    issued_flow(prepared)
    run, model = mine(prepared, specs, persist=True)
    return prepared, run, model


def registered_ready(tmp_path):
    prepared = setup(tmp_path, REGISTERED, roles={"parse": ("core", "accepted_anchor"),
        "create": ("support", "resource_creation"), "destroy": ("support", "resource_cleanup"),
        "register_table": ("support", "callback_registration")})
    ids = prepared[0][-1]; fid, register = ids["parse"], ids["register_table"]
    specs = context_specs(ids)
    specs[(fid, "state")] = {"value": {"preconditions": [{"parameter": "ctx", "kind": "initialized", "api": register}]}}
    sig = "int (*read)(void *user, const unsigned char *buf, size_t size)"
    def cb(parameter, setup=None, userdata=None):
        return dict(parameter=parameter, signature=sig, mandatory=True, setup_api=setup,
                    userdata=userdata, lifetime="per_context", null_allowed=False)
    dep = {"function_id": register, "necessity": "required", "reason": "callback"}
    specs[(fid, "callback")] = {"value": {"callbacks": [cb("ctx.read", register, "ctx.user")]}, "dependencies": [dep]}
    specs[(register, "support_decision")] = {"value": {"decision": "required", "reason": "callback", "required_by": [fid]},
        "dependencies": [{**dep, "required_by": fid}]}
    specs[(register, "argument_construction")] = {"value": {"arguments": [argument("ctx", "derived"), argument("table", "zero_init"), argument("userdata", "zero_init")]}}
    specs[(register, "ownership")] = {"value": {"entries": [owner("ctx"), owner("table"), owner("userdata")]}}
    specs[(register, "ownership")]["value"]["entries"][2]["lifetime"] = "until_context_cleanup"
    specs[(register, "buffer_length")] = {"status": "not_applicable", "value": {"applicable": False, "links": []}}
    specs[(register, "callback")] = {"value": {"callbacks": [cb("ctx.read", userdata="userdata"), cb("table.read")]}}
    issued_flow(prepared)
    run, model = mine(prepared, specs, persist=True)
    return prepared, run, model


def owned_consumer_ready(tmp_path, *, missing_cleanup_argument=False):
    source = "#include <stdlib.h>\n" + OWNED + '''void consume(Node *node) { node->value ^= 1; }
void usage(const unsigned char *data, size_t size) { Node *n=parse(data,size); consume(n); node_free(n); }
'''
    prepared = setup(tmp_path, source, roles={"parse": ("core", "accepted_anchor"), "consume": ("core", "core_data_dependency"), "node_free": ("support", "resource_cleanup")})
    ids = prepared[0][-1]; fid, consumer, cleanup = [ids[n] for n in ("parse", "consume", "node_free")]
    specs = direct_specs(fid)
    specs[(fid, "return_semantics")]["value"] = dict(success="nonnull", nullable=True, owned=True, error_cleanup=False)
    specs[(fid, "ownership")]["value"]["entries"].append(owner(returned=True, ownership="owned", release=cleanup, resource="resource_producer"))
    for api, name, rid in ((fid, None, "resource_producer"), (consumer, "node", "resource_consumer")):
        specs[(api, "lifecycle")] = {"value": lifecycle_value(api, rid, "Node", name, fid, cleanup),
            "dependencies": [{"function_id": cleanup, "necessity": "required", "reason": "cleanup"}]}
        specs[(api, "call_order")] = {"value": {"constraints": []}}
    specs[(consumer, "input_binding")] = {"value": {"bindings": [indirect("node", fid)]}}
    specs[(consumer, "argument_construction")] = {"value": {"arguments": [argument("node", "derived", resource="resource_consumer")]}}
    specs[(consumer, "ownership")] = {"value": {"entries": [owner("node", resource="resource_consumer")]}}
    specs[(consumer, "state")] = {"value": {"preconditions": [{"parameter": "node", "kind": "none", "api": None}]}}
    specs[(cleanup, "argument_construction")] = {"value": {"arguments": [argument("node", "derived")]}}
    if missing_cleanup_argument:
        del specs[(cleanup, "argument_construction")]
    specs[(cleanup, "ownership")] = {"value": {"entries": [owner("node", ownership="transferred")]}}
    specs[(cleanup, "support_decision")] = {"value": {"decision": "required", "reason": "cleanup", "required_by": [fid, consumer]},
        "dependencies": [{"function_id": cleanup, "required_by": fid, "necessity": "required", "reason": "cleanup"}]}
    issued_flow(prepared)
    run, model = mine(prepared, specs, persist=True)
    return prepared, run, model


@pytest.mark.parametrize("case", ["direct", "nul", "shared", "owned_consume", "registered_callback"])
def test_five_api_models_slice_to_frozen_plan(tmp_path, case):
    if case in {"direct", "nul"}:
        store, frozen, plan = ready(tmp_path, case)
        assert frozen[4]["generation_allowed"] and frozen[1]["frozen"]
        if case == "nul":
            assert plan["contracts"]["input_contract"]["bindings"][0]["input_kind"] == "nul_terminated_string"
            assert plan["input_transforms"][0]["max_allocation_bytes"] == plan["input_policy"]["max_bytes"] + 1
            assert plan["input_transforms"][0]["allocation"] == "heap"
    else:
        prepared, run, _ = {"shared": shared_ready, "owned_consume": owned_consumer_ready, "registered_callback": registered_ready}[case](tmp_path)
        assert_gate(run)
        plan = HarnessPlanBuilder().build(prepared[1], run.context, run.closure, prepared[3], run.completeness)
        assert len(plan["resources"]) == 1
        if case == "shared":
            assert {r["reason"] for r in run.context["resource_identity"]["bindings"]} == {"source_value_flow"}
            assert any(e["reason"] == "input_state_write_before_read" for e in plan["ordering_provenance"]["edges"])
            assert run.completeness["soft_unknowns"]
        if case == "registered_callback":
            cb = next(c for c in plan["contracts"]["callback_contract"]["callbacks"] if c["function_id"] == prepared[0][-1]["parse"])
            assert cb["declaration_identity"]["owner_type"] == "Context"
            assert cb["userdata_binding"]["source_verified"] and cb["userdata_binding"]["until"] == "context_cleanup"
            assert cb["registration"]["api"] == prepared[0][-1]["register_table"]
            assert plan["type_declarations"][0].startswith("typedef int (*ReadCallback)")


@pytest.mark.parametrize("variant", ["owned", "borrowed", "nullable", "wrapper", "two_cleanup", "stored_field"])
def test_owned_return_slice_preserves_cleanup_frontier_without_final_ownership(tmp_path, variant):
    source = BORROWED if variant == "borrowed" else OWNED
    roles = {"parse": ("core", "accepted_anchor"), "node_free": ("support", "resource_cleanup")}
    if variant == "nullable":
        source = source.replace("Node *node = malloc", "if (!size) return 0; Node *node = malloc")
    if variant == "wrapper":
        source += "void release_wrapper(Node *node) { node_free(node); }\n"
        roles["release_wrapper"] = ("support", "resource_cleanup")
    if variant == "two_cleanup":
        source += "void release_other(Node *node) { free(node); }\n"
        roles["release_other"] = ("support", "resource_cleanup")
    if variant == "stored_field":
        source += "typedef struct Store { Node *node; } Store;\nvoid store(Store *ctx, const unsigned char *data, size_t size) { ctx->node=parse(data,size); }\n"
    sample = fixture(tmp_path, source)
    ids = sample[-1]
    mapping = {ids[n]: r for n, r in roles.items()}
    run, _, tools = slice_run(sample, [queries(*(tool("get_function", "body_" + n, function=ids[n]) for n in roles)), terminal(mapping)])
    assert run.result["run_status"] in {"completed", "completed_with_unresolved"}
    assert run.result["core_functions"] == [ids["parse"]]
    assert set(run.result["support_functions"]) == {ids[n] for n in roles if n != "parse"}
    assert any(r["kind"] == "producer_return_consumer_candidate" for r in tools.frontier.rows[ids["node_free"]]["weak_relations"])


@pytest.mark.parametrize("usage", [
    "Context *a=create(); Context *b=create(); feed(a,data,size); parse(b); destroy(a); destroy(b);",
    "Context *a=create(); Context *b=a; b=create(); feed(a,data,size); parse(b);",
    "Context *a=create(); if(size) { feed(a,data,size); } parse(a);",
])
def test_resource_same_type_reassignment_and_control_flow_never_force_merge(tmp_path, usage):
    source = SHARED[:SHARED.index("void usage")] + "void usage(const unsigned char *data, size_t size) {" + usage + "}\n"
    prepared, run, _ = shared_ready(tmp_path, source=source)
    assert_gate(run, "incomplete")
    if 'if(size)' in usage:
        assert not run.context['construction_contract']['local_chains']
        assert any(g['kind'] in {'state', 'argument_construction'} for g in run.completeness['hard_missing'])
    else:
        assert any(g["code"] in {"shared_resource_identity_unresolved", "resource_identity_multiple_origins"} for g in run.completeness["hard_missing"])


def test_nul_without_length_link_is_derived_only_from_issued_string_evidence(tmp_path):
    prepared = setup(tmp_path, NUL); fid = prepared[0][-1]["parse"]
    specs = direct_specs(fid, data="text", size=None, nul=True)
    specs[(fid, "input_binding")]["value"]["bindings"][0]["size_relation"] = "none"
    specs[(fid, "buffer_length")] = {"status": "not_applicable", "value": {"applicable": False, "links": []}}
    run, _ = mine(prepared, specs)
    assert_gate(run)
    from harness_generation.harness_context.input_contracts import VERSION
    assert run.context["buffer_length_contract"]["links"][0]["derived_by"] == VERSION
    assert run.context["facts"] != []  # raw fact remains not_applicable, projection is replayable


def test_char_pointer_without_nul_source_proof_stays_hard_missing(tmp_path):
    prepared = setup(tmp_path, "int parse(const char *text) { return text[0]; }\n")
    specs = direct_specs(prepared[0][-1]["parse"], data="text", size=None, nul=True)
    run, _ = mine(prepared, specs)
    assert_gate(run, "incomplete")
    assert any(g["code"] == "nul_string_semantics_unproven" for g in run.completeness["hard_missing"])


def test_hard_cycle_keeps_all_provenance_and_blocks_plan(tmp_path):
    prepared, run, _ = shared_ready(tmp_path)
    context = deepcopy(run.context)
    # A mandatory initializer declared to be the cleanup API contradicts the
    # independently required use-before-cleanup resource dependency.
    resource = next(r for r in context["lifecycle_contract"]["resources"] if r["function_id"] == prepared[0][-1]["parse"])
    resource["initialization"] = {"api": prepared[0][-1]["destroy"], "mandatory": True}
    from harness_generation.harness_context.ordering import ordering_graph
    graph = ordering_graph(context, prepared[3], prepared[4].evidence)
    assert graph["hard_cycles"] and all(e["evidence_ids"] for e in graph["hard_cycles"])
    context["ordering_graph"] = graph
    with pytest.raises(PlanError, match="hard ordering cycle"):
        HarnessPlanBuilder().build(prepared[1], context, run.closure, prepared[3], run.completeness)


def test_compact_terminal_schema_reduces_size_and_preserves_identity_validation(tmp_path):
    prepared = setup(tmp_path)
    reqs = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"]
    old = obj({"resolutions": arr({"anyOf": [resolution_schema(r["kind"], requirement=r) for r in reqs]}, len(reqs))})
    compact = terminal_schema(reqs)
    assert len(canonical(compact)) < len(canonical(old)) * .8
    assert "anyOf" not in canonical(compact) and "requirement_id" not in canonical(compact)
    values = [{"requirement_id": r["requirement_id"], "status": "unresolved", "facts": [], "discovered_api_dependencies": [], "open_questions": ["unknown"]} for r in reqs]
    wire = compact_submission(values, reqs)
    assert expand_submission(wire, reqs)["resolutions"] == values
    wire["resolutions"]["r0"]["requirement_id"] = "forged"
    with pytest.raises(ValueError):
        expand_submission(wire, reqs)


@pytest.mark.parametrize("usage,origin_kind", [
    ("Context *a=create(); Context *b=a; feed(b,data,size); parse(a); destroy(b);", "return"),
    ("Context *a; output(&a); Context *b=a; feed(b,data,size); parse(a); destroy(b);", "out_parameter"),
    ("struct Box { Context *item; } box; box.item=create(); feed(box.item,data,size); parse(box.item); destroy(box.item);", "return"),
])
def test_issued_return_out_alias_and_field_value_flow(tmp_path, usage, origin_kind):
    source = SHARED[:SHARED.index("void usage")] + "void output(Context **out) { *out=calloc(1,sizeof(Context)); }\n"
    source += "void usage(const unsigned char *data, size_t size) { " + usage + " }\n"
    prepared = setup(tmp_path, source)
    issued_flow(prepared)
    req = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"][0]
    prepared[5].activate(req)
    prepared[5].execute("find_initializers", {"type": "Context"})
    prepared[5].execute("get_function", {"function": prepared[0][-1]["output"]})
    flow = resource_flows(prepared[3], prepared[4].evidence)
    consumers = [r for r in flow["observations"] if r["function_id"] in {prepared[0][-1][n] for n in ("feed", "parse", "destroy")}]
    assert len({r["resource_id"] for r in consumers}) == 1
    assert all(r["origin"]["kind"] == origin_kind and r["evidence_ids"] for r in consumers)


def test_value_flow_rejects_same_base_type_with_different_pointer_depth(tmp_path):
    # Malformed indexed usage is not sufficient evidence to merge Context*
    # and Context**. The static resolver must reject it before code generation.
    source = SHARED[:SHARED.index("void usage")]
    source += "void indirect(Context **slot) { (void)slot; }\n"
    source += "void usage(void) { Context *a=create(); indirect(a); parse(a); }\n"
    prepared = setup(tmp_path, source)
    issued_flow(prepared)
    flow = resource_flows(prepared[3], prepared[4].evidence)
    indirect_id = prepared[0][-1]["indirect"]
    assert not any(r["function_id"] == indirect_id for r in flow["observations"])
    assert any(r["function_id"] == indirect_id and r["reason"] == "value_flow_type_mismatch"
               for r in flow["unresolved"])


@pytest.mark.parametrize("body", ["return strlen(text);", "return strcmp(text,\"x\");", "return strchr(text,'x') != 0;", "int i=0; while(text[i]) i++; return i;"])
def test_nul_consumption_has_exact_source_proof(tmp_path, body):
    prepared = setup(tmp_path, "int parse(const char *text) { " + body + " }\n")
    from harness_generation.harness_context.input_contracts import nul_evidence
    assert nul_evidence(prepared[3].functions[prepared[0][-1]["parse"]], "text", prepared[3])


def test_binary_char_buffer_with_length_is_not_reinterpreted(tmp_path):
    prepared = setup(tmp_path, "typedef unsigned long size_t; int parse(const char *data, size_t size) { return size ? data[size-1] : 0; }\n")
    run, _ = mine(prepared, direct_specs(prepared[0][-1]["parse"]))
    assert_gate(run)
    assert run.context["input_contract"]["bindings"][0]["input_kind"] == "explicit_length_buffer"
    assert not run.context["input_contract"]["bindings"][0]["nul_terminated"]


def test_typedef_and_nested_callback_field_exact_identity(tmp_path):
    source = REGISTERED.replace("typedef struct Context { ReadCallback read; void *user; } Context;", "typedef struct Context { Table callbacks; } Context;")
    prepared = setup(tmp_path, source)
    declarations = callback_declarations(prepared[3].functions[prepared[0][-1]["parse"]], prepared[3])
    row = next(r for r in declarations if r.get("field_path") == "callbacks.read")
    assert row["owner_type"] == "Table" and row["owner_path"] == "ctx.callbacks"
    assert row["parameter_types"] == ["void *", "const unsigned char *", "size_t"]


def test_callback_same_abi_multiple_fields_needs_exact_field_identity(tmp_path):
    source = CALLBACK.replace("void *userdata;", "int (*other)(void *userdata, const unsigned char *data, size_t size); void *userdata;")
    from harness_generation.harness_context.callbacks import callback_matches
    prepared = setup(tmp_path, source)
    declarations = callback_declarations(prepared[3].functions[prepared[0][-1]["parse"]], prepared[3])
    assert len(callback_matches({"parameter": "ctx"}, declarations)) == 2
    assert len(callback_matches({"parameter": "ctx.consume"}, declarations)) == 1


def test_callback_macro_abi_is_not_guessed(tmp_path):
    from harness_generation.harness_context.callbacks import exact_signature
    assert exact_signature("int UNKNOWN_ABI (*cb)(void *user)", ()) is None


def test_field_initialization_discharges_only_proven_callback_state(tmp_path):
    # Original real failure: initialized with no API, but public callback fields
    # and userdata are the only reads. No unrelated initialization is assumed.
    _, frozen, _ = ready(tmp_path, "callback")
    from harness_generation.harness_context.callbacks import field_initialization_complete
    context, snapshot = frozen[1], frozen[3]
    row = {"function_id": frozen[0]["anchor_function_id"], "parameter": "ctx", "kind": "initialized", "api": None}
    assert field_initialization_complete(context, row, snapshot)
    bad = deepcopy(context);bad["callback_contract"]["callbacks"][0]["userdata_binding"]["source_verified"] = False
    assert not field_initialization_complete(bad, row, snapshot)


def test_reserved_terminal_round_does_not_increase_model_budget(tmp_path):
    from harness_generation.semantic_discovery import FakeAgentModel, AgentModelResponse, AgentToolCall, ValidationBudget
    from harness_generation.semantic_discovery.loop import BoundedAgentLoop
    from harness_generation.semantic_discovery.tools import _schema
    prepared = setup(tmp_path)
    req = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"][0]
    tools = prepared[5];tools.activate(req)
    def submit(messages, schemas):
        assert [s["function"]["name"] for s in schemas] == ["done"]
        return AgentModelResponse(tool_calls=(AgentToolCall("done-1", "done", '{}'),))
    model = FakeAgentModel([submit])
    loop = BoundedAgentLoop(model, ValidationBudget(max_rounds=1), _schema("done", "done", {}, []), json.loads, reserve_terminal_round=True)
    result = loop.run([], tools)
    assert result.model_calls == 1 and result.tool_calls == 0 and result.termination == "final_decision"


def test_owned_cleanup_identity_is_framework_bound_without_reinvestigation(tmp_path):
    prepared = setup(tmp_path, OWNED)
    ids = prepared[0][-1];fid, cleanup = ids["parse"], ids["node_free"]
    specs = direct_specs(fid)
    specs[(fid, "return_semantics")]["value"] = dict(success="nonnull", nullable=True, owned=True, error_cleanup=False)
    specs[(fid, "ownership")]["value"]["entries"].append(owner(returned=True, ownership="owned", release=cleanup, resource="resource_result"))
    specs[(fid, "lifecycle")] = {"value": lifecycle_value(fid, "resource_result", "Node", None, fid, cleanup),
        "dependencies": [{"function_id": cleanup, "necessity": "required", "reason": "cleanup"}]}
    specs[(fid, "call_order")] = {"value": {"constraints": []}}
    specs[(cleanup, "argument_construction")] = {"value": {"arguments": [argument("node", "creator_api", fid, "resource_other")]}}
    specs[(cleanup, "ownership")] = {"value": {"entries": [owner("node", ownership="transferred")]}}
    run, _ = mine(prepared, specs, query_type="Node")
    assert_gate(run)
    # Canonical cleanup binding can discharge this requirement before a
    # redundant model proposal. Any submitted raw fact must remain grounded.
    raw = [f for f in run.context['facts'] if f['function_id'] == cleanup and f['predicate'] == 'argument_construction']
    assert all(f['value']['arguments'][0]['resource_id'] != 'resource_other' for f in raw)
    projected = next(a for a in run.context["argument_contract"]["arguments"] if a["function_id"] == cleanup)
    assert projected["construction"] == "derived" and projected["api"] is None
    assert projected["resource_id"] == run.context["lifecycle_contract"]["resources"][0]["resource_id"]


def test_reuse_scopes_intersect_only_with_allocated_local_release_proof(tmp_path):
    prepared, run, _ = shared_ready(tmp_path)
    facts = deepcopy(run.context["facts"])
    create = prepared[0][-1]["create"]
    for fact in facts:
        if fact["function_id"] == create and fact["predicate"] == "lifecycle":
            fact["value"]["resources"][0]["reuse"] = "per_context"
    context = build_context(prepared[1], run.requirements["requirements"], facts, prepared[3], prepared[4].evidence)
    assert context["resource_identity"]["reuse_projections"]
    assert {r["reuse"] for r in context["lifecycle_contract"]["resources"]} == {"per_input"}
    for fact in facts:
        if fact["function_id"] == create and fact["predicate"] == "lifecycle":
            fact["value"]["resources"][0]["reuse"] = "unknown"
    context = build_context(prepared[1], run.requirements["requirements"], facts, prepared[3], prepared[4].evidence)
    assert not context["resource_identity"]["reuse_projections"]
    assert "unknown" in {r["reuse"] for r in context["lifecycle_contract"]["resources"]}


def test_soft_unknown_resume_stays_unknown_and_needs_zero_model_calls(tmp_path):
    prepared = setup(tmp_path, CONTEXT, roles={"parse": ("core", "accepted_anchor"), "create": ("support", "resource_creation"),
        "destroy": ("support", "resource_cleanup"), "set_logger": ("support", "minimal_configuration")})
    specs = context_specs(prepared[0][-1])
    # A closed Gate leaves unrelated optional exploration open; an existing
    # unresolved investigation remains unknown as well. Neither needs a call.
    run, model = mine(prepared, specs, query_type="Context", persist=True)
    assert_gate(run)
    previous = {r["requirement_id"]: r["status"] for r in run.requirements["requirements"]
                if r["status"] in {"open", "unresolved"}}
    assert previous
    logger = prepared[0][-1]["set_logger"]
    assert not any(json.loads(next(m["content"] for m in call["messages"] if m["role"] == "user"))["requirement"]["subject_function_id"] == logger
                   for call in model.calls)
    # Reuse the same FT and snapshot; only budgets/counters reset.
    from harness_generation.harness_context.models import MiningState
    from harness_generation.harness_context.tools import HarnessContextTools
    state = MiningState(prepared[4].budget)
    tools = HarnessContextTools(prepared[3], prepared[5].index.catalog, prepared[1], state, index=prepared[5].index)
    again = (*prepared[:4], state, tools)
    resumed, model = mine(again, specs, query_type="Context", persist=True, resume=True)
    assert_gate(resumed)
    assert not model.calls and resumed.metadata["metrics"]["model_calls"] == 0
    assert {r["requirement_id"]: r["status"] for r in resumed.requirements["requirements"]
            if r["status"] in {"open", "unresolved"}} == previous


def test_callback_external_context_claim_without_fuzz_binding_remains_blocked(tmp_path):
    _, frozen, _ = ready(tmp_path, "callback")
    context = deepcopy(frozen[1])
    row = next(a for a in context["argument_contract"]["arguments"] if a["parameter"] == "ctx")
    row["construction"] = "input"
    from harness_generation.harness_context.callbacks import field_initialization_complete
    assert not field_initialization_complete(context, {"function_id": frozen[0]["anchor_function_id"], "parameter": "ctx"}, frozen[3])


def test_conflicting_typedef_abis_stay_unknown():
    from harness_generation.harness_context.callbacks import exact_signature
    typedefs = [{"name": "Handler", "declaration": "typedef int (*Handler)(void *);"},
                {"name": "Handler", "declaration": "typedef void (*Handler)(void *);"}]
    assert exact_signature("Handler cb", typedefs) is None


@pytest.mark.parametrize("stores", ["other->user=userdata;", "ctx->user=userdata; ctx->other=userdata;"])
def test_callback_userdata_setter_requires_unique_exact_owner(tmp_path, stores):
    from harness_generation.harness_context.callbacks import enrich_callbacks
    source = '''typedef int (*Handler)(void *);
typedef struct Context { Handler cb; void *user; void *other; } Context;
void parse(Context *ctx, Context *other, Handler cb, void *userdata) {
    ctx->cb=cb; ''' + stores + " }\n"
    prepared = setup(tmp_path, source)
    callback = dict(function_id=prepared[0][-1]["parse"], parameter="ctx.cb", userdata="userdata",
                    setup_api=None, lifetime="per_context", mandatory=True, null_allowed=False, signature=None)
    context = {"callback_contract": {"callbacks": [callback]}}
    enrich_callbacks(context, prepared[3])
    assert callback["declaration_identity"]
    assert not callback["userdata_binding"]["source_verified"]
    assert callback["userdata_binding"]["target"] is None


def callback_external_ready(tmp_path, source=CALLBACK, *, mandatory_init=False, explicit_init=False):
    prepared = setup(tmp_path, source)
    fid = prepared[0][-1]["parse"]
    specs = direct_specs(fid)
    specs[(fid, "argument_construction")]["value"]["arguments"].insert(0, argument("ctx", "zero_init", resource="resource_external"))
    specs[(fid, "ownership")]["value"]["entries"].append(owner("ctx", resource="resource_external"))
    specs[(fid, "lifecycle")] = {"value": {"resources": [{"resource_id": "resource_external", "type": "Context",
        "subject_parameter": "ctx", "return_value": False, "creation": {"kind": "stack", "api": None},
        "initialization": {"api": fid if explicit_init else None, "mandatory": mandatory_init},
        "cleanup": {"api": None, "mandatory": False}, "reuse": "per_context"}]}}
    specs[(fid, "state")] = {"value": {"preconditions": [{"parameter": "ctx", "kind": "initialized", "api": None}]}}
    specs[(fid, "callback")] = {"value": {"callbacks": [{"parameter": "ctx.consume",
        "signature": "int (*consume)(void *userdata, const unsigned char *data, size_t size)",
        "mandatory": True, "setup_api": None, "userdata": "ctx.userdata", "lifetime": "during_call", "null_allowed": False}]}}
    run, _ = mine(prepared, specs, persist=True)
    return prepared, run


def test_external_callback_has_verified_harness_construction_and_unchanged_model_facts(tmp_path):
    prepared, run = callback_external_ready(tmp_path)
    assert_gate(run)
    proof = run.context["construction_contract"]["sources"][0]
    assert proof["kind"] == "public_callback_object" and proof["escape_analysis"]
    assert {a["field"] for a in proof["assignments"]} == {"consume", "userdata"}
    raw = next(f for f in run.context["facts"] if f["predicate"] == "argument_construction"
        and any(a['parameter']=='ctx' for a in f['value']['arguments']))
    assert next(a for a in raw["value"]["arguments"] if a["parameter"] == "ctx")["construction"] == "zero_init"
    arg = next(a for a in run.context["argument_contract"]["arguments"] if a["parameter"] == "ctx")
    assert arg["construction"] == "zero_init" and arg["construction_source"] == proof["construction_id"]
    plan = HarnessPlanBuilder().build(prepared[1], run.context, run.closure, prepared[3], run.completeness)
    assert plan["construction_sources"]["sources"] == [proof]


@pytest.mark.parametrize("source", [
    CALLBACK.replace("void *userdata;", "void *userdata; int unproven_state;"),
    CALLBACK.replace("return ctx->consume", "escape(ctx); return ctx->consume"),
])
def test_external_callback_construction_rejects_extra_state_and_escape(tmp_path, source):
    _, run = callback_external_ready(tmp_path, source)
    assert_gate(run, "incomplete")
    assert not run.context["construction_contract"]["sources"]
    assert any(g["code"] == "state_precondition_unresolved" for g in run.completeness["hard_missing"])


def test_shared_context_source_proof_covers_only_local_lifecycle_and_order(tmp_path):
    prepared, run, _ = shared_ready(tmp_path)
    facts = [f for f in run.context["facts"] if not (f["function_id"] == prepared[0][-1]["parse"] and f["predicate"] in {"lifecycle", "call_order"})]
    rows = deepcopy(run.requirements["requirements"])
    for r in rows:
        if r["subject_function_id"] == prepared[0][-1]["parse"] and r["kind"] in {"lifecycle", "call_order"}:
            r.update(status="unresolved", evidence_ids=[])
    context = build_context(prepared[1], rows, facts, prepared[3], prepared[4].evidence)
    assert {r["predicate"] for r in context["framework_satisfied_requirements"]} == {"lifecycle", "call_order", "argument_construction", "state"}
    assert {r["predicate"] for r in context["framework_satisfied_requirements"] if r.get('proof_kind')!=RECONCILER_VERSION} == {"lifecycle", "call_order", "argument_construction", "state"}
    assert {r["status"] for r in rows if r["kind"] in {"lifecycle", "call_order"} and r["subject_function_id"] == prepared[0][-1]["parse"]} == {"unresolved"}
    proof = context["construction_contract"]["local_chains"][0]
    assert proof["state_transitions"] == [{"before": prepared[0][-1]["feed"], "after": prepared[0][-1]["parse"], "fields": ["data", "size"]}]
    assert len({r["resource_id"] for r in context["lifecycle_contract"]["resources"]}) == 1


def test_construction_certificate_tampering_is_rejected(tmp_path):
    from harness_generation.harness_context.evidence import HarnessContextValidator
    prepared, run = callback_external_ready(tmp_path)
    changed = deepcopy(run.context)
    changed["construction_contract"]["sources"][0]["storage"] = "arbitrary_external_object"
    errors = HarnessContextValidator().validate(changed, prepared[1], prepared[3], run.requirements["requirements"],
        prepared[4].evidence, prepared[5].initial_ids | set(prepared[4].discoveries))
    assert any(e["code"] == "context_changed_canonical_projection" for e in errors)


def test_local_state_transition_is_not_inferred_from_conditional_feed(tmp_path):
    from harness_generation.harness_context.construction import plain_fields
    prepared = setup(tmp_path, SHARED.replace("ctx->data=data; ctx->size=size;", "if(size) { ctx->data=data; ctx->size=size; }"))
    assert plain_fields(prepared[3].functions[prepared[0][-1]["feed"]], "ctx") is None


@pytest.mark.parametrize("explicit_init", [False, True])
def test_callback_field_recipe_satisfies_unknown_init_but_not_an_explicit_api(tmp_path, explicit_init):
    _, run = callback_external_ready(tmp_path, mandatory_init=True, explicit_init=explicit_init)
    assert_gate(run, "incomplete" if explicit_init else "complete")
    raw = next(f for f in run.context["facts"] if f["predicate"] == "lifecycle")
    assert raw["value"]["resources"][0]["initialization"]["mandatory"] is True
    if not explicit_init:
        assert run.context["lifecycle_contract"]["resources"][0]["initialization"] == {"mandatory": False, "api": None}


@pytest.mark.parametrize('ownership', ['unknown', 'transferred', 'owned'])
def test_cleanup_projection_preserves_explicit_ownership_claims(tmp_path, ownership):
    prepared, run, _ = shared_ready(tmp_path, cleanup_ownership=ownership)
    assert_gate(run, 'incomplete' if ownership == 'owned' else 'complete')
    fid = prepared[0][-1]["destroy"]
    raw = next(f for f in run.context["facts"] if f["function_id"] == fid and f["predicate"] == "ownership")
    assert raw["value"]["entries"][0]["ownership"] == ownership
    projected = next(o for o in run.context["ownership_contract"]["entries"] if o["function_id"] == fid)
    if ownership == 'owned':
        # An explicit owned claim with no release API must be repaired by the
        # Agent; source projection may fill unknowns but cannot silently erase it.
        assert projected['ownership'] == 'owned'
        assert any(g['code'] == 'mandatory_cleanup_unresolved' for g in run.completeness['hard_missing'])
    else:
        assert projected["ownership"] == "transferred" and projected["release_api"] is None
        assert any(s["kind"] == "cleanup_consumption" for s in run.context["construction_contract"]["sources"])


def test_nonexact_release_does_not_certify_cleanup_consumption(tmp_path):
    _, run, _ = shared_ready(tmp_path, source=SHARED.replace("free(ctx);", "if(ctx) free(ctx);"), cleanup_ownership="owned")
    assert_gate(run, "incomplete")
    assert not any(s["kind"] == "cleanup_consumption" for s in run.context["construction_contract"]["sources"])


def test_missing_cleanup_argument_is_bound_to_unique_owned_return(tmp_path):
    prepared, run, _ = owned_consumer_ready(tmp_path, missing_cleanup_argument=True)
    assert_gate(run)
    fid = prepared[0][-1]["node_free"]
    req = next(r for r in run.requirements["requirements"] if r["subject_function_id"] == fid and r["kind"] == "argument_construction")
    assert req["status"] in {"open", "unresolved"}
    assert req["requirement_id"] in run.completeness["framework_satisfied_requirements"]
    arg = next(a for a in run.context["argument_contract"]["arguments"] if a["function_id"] == fid)
    assert arg["construction"] == "derived" and arg["construction_source"]


def test_feed_is_a_state_transition_not_a_second_resource_initializer(tmp_path):
    prepared, run, _ = shared_ready(tmp_path, feed_initialization=True)
    assert_gate(run)
    fid = prepared[0][-1]["parse"]
    assert not any(f['function_id']==fid and f['predicate']=='lifecycle' for f in run.context['facts'])
    req=next(r for r in run.requirements['requirements'] if r['subject_function_id']==fid and r['kind']=='lifecycle')
    assert req['requirement_id'] in run.completeness['framework_satisfied_requirements']
    assert all(r["initialization"] == {"mandatory": False, "api": None} for r in run.context["lifecycle_contract"]["resources"])


def test_local_chain_rejects_an_unrecognized_resource_use(tmp_path):
    from harness_generation.harness_context.construction import local_chains
    source = SHARED.replace("parse(a); destroy(b);", "parse(a); escape(a); destroy(b);") + "void escape(Context *ctx) { keep(ctx); }\n"
    prepared, _, _ = shared_ready(tmp_path, source=source)
    assert not local_chains(prepared[3], prepared[4].evidence, set(prepared[3].functions))


def processing_helper_source():
    return SHARED.replace('int parse(', 'int zz_input(const unsigned char *data, size_t size);\nint parse(').replace(
        'return ctx->size ? ctx->data[0] : 0;',
        'return ctx->size ? ctx->data[0] + zz_input(ctx->data,ctx->size) : 0;') + '\nint zz_input(const unsigned char *data,size_t size) { return size ? data[0] ^ 1 : 0; }\n'


def test_plan_schedules_independent_core_before_cleanup_without_inventing_edges(tmp_path):
    source = processing_helper_source()
    prepared, run, _ = shared_ready(tmp_path, source=source, extra_core="zz_input")
    assert_gate(run)
    plan = HarnessPlanBuilder().build(prepared[1], run.context, run.closure, prepared[3], run.completeness)
    ids = prepared[0][-1]
    assert ids["zz_input"] in {r["function_id"] for r in plan["call_sequence"]}
    assert [r["function_id"] for r in plan["cleanup_sequence"]] == [ids["destroy"]]
    assert [ids["zz_input"], ids["destroy"]] not in plan["ordering_edges"]


def test_plan_still_rejects_hard_cleanup_before_active_use(tmp_path):
    source = processing_helper_source()
    prepared, run, _ = shared_ready(tmp_path, source=source, extra_core="zz_input")
    changed = deepcopy(run.context)
    ids = prepared[0][-1]
    changed["ordering_graph"]["edges"].append({"before": ids["destroy"], "after": ids["zz_input"], "strength": "hard"})
    with pytest.raises(PlanError, match="cleanup interleaved"):
        HarnessPlanBuilder().build(prepared[1], changed, run.closure, prepared[3], run.completeness)
