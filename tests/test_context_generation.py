"""Frozen artifact gates, exact plans, isolated translation and real local replay."""
from copy import deepcopy
import json
import shutil

import pytest

from harness_generation.cli import main as entrypoint
from harness_generation.context_generation import HarnessPlanBuilder, PlanError, ContextStage4Generator
from harness_generation.context_generation.cli import main
from harness_generation.context_generation.persistence import load_frozen_inputs
from harness_generation.context_generation.validation import validate_code
from harness_generation.harness_context.models import resource_id
from harness_generation.llm import FakeLLM
from test_harness_context import (setup, mine, assert_gate, direct_specs, context_specs, CONTEXT, OWNED, BORROWED,
    CALLBACK, NUL, argument, owner, order, lifecycle_value)

DIRECT_CODE = '''#include <stdint.h>
#include <stddef.h>
extern "C" int parse(const unsigned char *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 1048576) return 0;
    (void)parse(data, size);
    return 0;
}
'''


def ready(tmp_path, model="direct", *, source_override=None):
    source = {"direct": None, "context": "#include <stdlib.h>\n" + CONTEXT,
              "owned": "#include <stdlib.h>\n" + OWNED, "borrowed": "#include <stdlib.h>\n" + BORROWED, "callback": CALLBACK,
              "nul": "#include <string.h>\n" + NUL}[model]
    if source_override is not None:
        source = source_override
    prepared = setup(tmp_path, **({"source": source} if source else {}))
    ids, fid = prepared[0][-1], prepared[0][-1]["parse"]
    if model == "context":
        specs = context_specs(ids)
        rid = resource_id(fid, "ctx")
        for kind in ("lifecycle", "ownership"):
            entries = specs[(ids["create"], kind)]["value"]["resources" if kind == "lifecycle" else "entries"]
            entries[0]["resource_id"] = rid
        query = "Context"
    else:
        specs, query = direct_specs(fid), None
    if model in {"owned", "borrowed"}:
        borrowed = model == "borrowed"
        cleanup, rid = ids["node_free"], resource_id(fid)
        specs[(fid, "return_semantics")]["value"] = dict(success="always" if borrowed else "nonnull", nullable=not borrowed, owned=not borrowed, error_cleanup=False)
        specs[(fid, "ownership")]["value"]["entries"].append(owner(returned=True, ownership="static" if borrowed else "owned", release=None if borrowed else cleanup, resource=rid))
        specs[(fid, "lifecycle")] = {"value": lifecycle_value(fid, rid, "Node", None, fid, None if borrowed else cleanup, borrowed=borrowed)}
        if not borrowed:
            specs[(fid, "lifecycle")]["dependencies"] = [{"function_id": cleanup, "necessity": "required", "reason": "cleanup"}]
            specs[(fid, "call_order")] = {"value": {"constraints": [order(fid, cleanup)]}}
            specs[(cleanup, "argument_construction")] = {"value": {"arguments": [argument("node", "derived")]}}
            specs[(cleanup, "ownership")] = {"value": {"entries": [owner("node", ownership="transferred")]}}
        query = "Node"
    if model == "callback":
        rid = resource_id(fid, "ctx")
        specs[(fid, "argument_construction")]["value"]["arguments"].insert(0, argument("ctx", "zero_init", resource=rid))
        specs[(fid, "ownership")]["value"]["entries"].append(owner("ctx", resource=rid))
        specs[(fid, "lifecycle")] = {"value": {"resources": [{"resource_id": rid, "type": "Context",
            "subject_parameter": "ctx", "return_value": False, "creation": {"kind": "stack", "api": None},
            "initialization": {"api": None, "mandatory": False}, "cleanup": {"api": None, "mandatory": False}, "reuse": "per_input"}]}}
        specs[(fid, "state")] = {"value": {"preconditions": [{"parameter": "ctx", "kind": "none", "api": None}]}}
        specs[(fid, "callback")] = {"value": {"callbacks": [{"parameter": "ctx",
            "signature": "int (*consume)(void *userdata, const unsigned char *data, size_t size)",
            "mandatory": True, "setup_api": None, "userdata": "ctx.userdata", "lifetime": "during_call", "null_allowed": False}]}}
    if model == "nul":
        specs = direct_specs(fid, data="text", size=None, nul=True)
    run, _ = mine(prepared, specs, query_type=query, persist=True)
    assert_gate(run)
    store = prepared[0][0]
    frozen = load_frozen_inputs(store, prepared[1]["ft_id"])
    return store, frozen, HarnessPlanBuilder().build(*frozen[:5])


def test_plan_is_deterministic_complete_and_translation_only(tmp_path):
    store, frozen, plan = ready(tmp_path)
    assert plan == HarnessPlanBuilder().build(*frozen[:5])
    assert plan["core_apis"] == frozen[1]["core_apis"]
    assert plan["call_sequence"][0]["arguments"][1]["length_for"][0]["parameter"] == "data"
    prompt = ContextStage4Generator(FakeLLM([])).render(plan)
    assert prompt.parameters == {"harness_plan": plan}
    assert "source" not in prompt.parameters and "triplet" not in prompt.parameters
    assert "return size ? data[0]" not in prompt.content
    changed = deepcopy(plan)
    changed["input_policy"]["max_bytes"] += 1
    with pytest.raises(ValueError, match="immutable"):
        ContextStage4Generator(FakeLLM([])).render(changed)


@pytest.mark.parametrize("field", ["generation_allowed", "frozen", "identity"])
def test_builder_hard_gate(tmp_path, field):
    _, frozen, _ = ready(tmp_path)
    ft, context, closure, snapshot, report = frozen[:5]
    context, report = deepcopy(context), deepcopy(report)
    if field == "generation_allowed": report[field] = False
    elif field == "frozen": context[field] = False
    else: context["minimal_ft_digest"] = "wrong"
    with pytest.raises(PlanError):
        HarnessPlanBuilder().build(ft, context, closure, snapshot, report)


def test_shared_context_explicit_resource_and_order(tmp_path):
    _, _, plan = ready(tmp_path, "context")
    assert [r["role"] for r in plan["call_sequence"]] == ["create", "core"]
    create, core = plan["call_sequence"]
    assert create["return_resource"] == core["arguments"][0]["resource_id"]
    assert plan["cleanup_sequence"][0]["arguments"][0]["resource_id"] == create["return_resource"]
    assert len(plan["resources"]) == 1


def test_multiline_type_declarations_are_compared_with_snapshot_normalization(tmp_path):
    source = "#include <stdlib.h>\n" + CONTEXT.replace('typedef struct Context { int ready; int calls; } Context;',
        'typedef struct Context {\n int ready;\n int calls;\n} Context;')
    _, _, plan = ready(tmp_path, "context", source_override=source)
    assert plan["resources"][0]["type"] == "Context"


@pytest.mark.parametrize("model,code", [
    ("direct", DIRECT_CODE),
    ("context", '''#include <stddef.h>
#include <stdint.h>
typedef struct Context { int ready; int calls; } Context;
extern "C" Context *create(void);
extern "C" void destroy(Context *ctx);
extern "C" int parse(Context *ctx, const unsigned char *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 if(size > 1048576) return 0;
 Context *ctx = create();
 if(ctx) { (void)parse(ctx,data,size); destroy(ctx); }
 return 0;
}'''),
    ("owned", '''#include <stdint.h>
#include <stddef.h>
typedef struct Node { int value; } Node;
extern "C" Node *parse(const unsigned char *data, size_t size);
extern "C" void node_free(Node *node);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 if(size > 1048576) return 0;
 Node *node = parse(data,size);
 if(node) node_free(node);
 return 0;
}'''),
    ("borrowed", '''#include <stdint.h>
#include <stddef.h>
typedef struct Node { int value; } Node;
extern "C" Node *parse(const unsigned char *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 if(size > 1048576) return 0;
 Node *node = parse(data,size); (void)node; return 0;
}'''),
    ("callback", '''#include <stddef.h>
#include <stdint.h>
typedef struct Context { int (*consume)(void *userdata, const unsigned char *data, size_t size); void *userdata; } Context;
extern "C" int parse(Context *ctx, const unsigned char *data, size_t size);
static int consume(void *userdata, const unsigned char *data, size_t size) { return 0; }
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 if(size > 1048576) return 0;
 Context ctx = {}; ctx.consume = consume; ctx.userdata = NULL;
 (void)parse(&ctx,data,size); return 0;
}'''),
    ("nul", '''#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern "C" int parse(const char *text);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 if(size > 1048576) return 0;
 char *text = (char *)malloc(size+1);
 if(text) { memcpy(text,data,size); text[size]=0; (void)parse(text); free(text); }
 return 0;
}'''),
])
def test_api_models_translate_compile_replay_and_resume(tmp_path, model, code):
    if not shutil.which("clang") or not shutil.which("clang++"):
        pytest.skip("clang toolchain unavailable")
    store, _, plan = ready(tmp_path, model)
    before = {p: p.read_bytes() for p in store.root.rglob("*.json")}
    llm = FakeLLM([code])
    args = ["context-generate", "--artifacts", str(store.root), "--build", "--runtime"]
    assert entrypoint(args, llm=llm) == 0
    from harness_generation.context_generation.stage4 import PROMPT_VERSION
    assert len(llm.calls) == 1 and llm.calls[0]["prompt_version"] == PROMPT_VERSION
    marker = next((store.root / "context_generations").glob("*/*/*/metadata.json"))
    directory = marker.parent
    assert json.loads((directory / "build/build.json").read_text())["success"] is True
    replay = json.loads((directory / "build/runtime.json").read_text())
    assert replay["status"] == "passed" and len(replay["cases"]) == 6 and not replay["fuzz_executed"]
    saved = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.rglob("*") if p.is_file()}
    assert entrypoint(args + ["--resume"], llm=llm) == 0
    assert len(llm.calls) == 1
    assert all(saved[p] == (p.read_bytes(), p.stat().st_mtime_ns) for p in saved)
    assert all(p.read_bytes() == value for p, value in before.items())


@pytest.mark.parametrize("replace,error", [
    (("parse(data, size)", "parse(data)"), "api_call_arity_mismatch"),
    (("(void)parse(data, size);", "(void)parse(data, size); system(\"x\");"), "call_outside_plan"),
    (("(void)parse(data, size);", "while(size) { (void)parse(data, size); }"), "project_call_loop_not_in_plan"),
    (("const unsigned char *data, size_t size", "unsigned char *data, int size"), "api_declaration_abi_mismatch"),
    (("#include <stddef.h>", "#include <stdio.h>"), "include_outside_plan"),
])
def test_outside_plan_code_rejected(tmp_path, replace, error):
    _, _, plan = ready(tmp_path)
    check = validate_code(DIRECT_CODE.replace(*replace), plan)
    assert check["status"] == "invalid" and error in check["errors"]


def test_stale_context_blocks_before_provider(tmp_path):
    store, frozen, plan = ready(tmp_path)
    context = store.root / "harness_contexts" / plan["ft_id"] / "harness_context.json"
    doc = json.loads(context.read_text()); doc["frozen"] = False
    context.write_text(json.dumps(doc))
    llm = FakeLLM([DIRECT_CODE])
    assert main(["--artifacts", str(store.root)], llm=llm) == 1
    assert llm.calls == []
    assert not list((store.root / "context_generations").rglob("harness_plan.json"))


def test_plan_only_works_without_provider_and_legacy_files(tmp_path, monkeypatch):
    store, _, _ = ready(tmp_path)
    for path in (store.root / "triplets.json", store.root / "protocol_ir.json"):
        path.unlink(missing_ok=True)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    assert main(["--artifacts", str(store.root), "--plan-only"]) == 0


def test_live_source_change_blocks_before_provider(tmp_path):
    store, frozen, _ = ready(tmp_path)
    path = frozen[-1].owned_path("api.c")
    path.write_text(path.read_text().replace("return size ? data[0] : 0", "return -100"))
    llm = FakeLLM([DIRECT_CODE])
    assert main(["--artifacts", str(store.root)], llm=llm) == 1
    assert llm.calls == []


def test_tampered_code_invalidates_resume(tmp_path):
    store, _, _ = ready(tmp_path)
    llm = FakeLLM([DIRECT_CODE, DIRECT_CODE])
    args = ["--artifacts", str(store.root)]
    assert main(args, llm=llm) == 0
    code = next((store.root / "context_generations").rglob("harness.cpp"))
    code.write_text(code.read_text().replace("parse(data, size)", "parse(data)"))
    assert main(args + ["--resume"], llm=llm) == 0
    assert len(llm.calls) == 2


def test_failed_regeneration_cannot_reuse_previous_response_or_build(tmp_path):
    store, _, _ = ready(tmp_path)
    llm = FakeLLM([DIRECT_CODE])
    args = ["--artifacts", str(store.root)]
    assert main(args, llm=llm) == 0
    marker = next((store.root / "context_generations").glob("*/*/*/metadata.json"))
    (marker.parent / "harness.cpp").write_text("tampered")
    assert main(args + ["--resume"], llm=llm) == 1
    assert json.loads(marker.read_text())["status"] == "generation_failed"
    assert not (marker.parent / "response.json").exists()
    assert not (marker.parent / "harness.cpp").exists()
    assert list(marker.parent.parent.glob("history/*/attempt_*/response.json"))


def test_linkage_guards_validate_and_existing_real_source_can_be_replayed(tmp_path, monkeypatch):
    store, _, plan = ready(tmp_path)
    code = DIRECT_CODE.replace('extern "C" ', '')
    code = '#ifdef __cplusplus\nextern "C" {\n#endif\n' + code + '\n#ifdef __cplusplus\n}\n#endif\n'
    assert validate_code(code, plan)["status"] == "valid"
    source = tmp_path / "existing.cpp"
    source.write_text(code)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    assert main(["--artifacts", str(store.root), "--harness", str(source), "--build", "--runtime"]) == 0
    marker = next((store.root / "context_generations").glob("*/*/*/metadata.json"))
    assert json.loads(marker.read_text())["model_calls"] == 0
    assert not (marker.parent / "response.json").exists()


def test_unknown_preprocessor_condition_cannot_hide_required_calls(tmp_path):
    _, _, plan = ready(tmp_path)
    code = DIRECT_CODE.replace('(void)parse(data, size);', '#if 0\n (void)parse(data, size);\n#endif')
    assert "unsupported_preprocessor_condition" in validate_code(code, plan)["errors"]


def test_undefined_behavior_cannot_pass_runtime_with_zero_exit_recovery(tmp_path):
    store, _, _ = ready(tmp_path)
    code = DIRECT_CODE.replace('return 0;\n}', 'volatile int zero=0; volatile int value=1/zero; (void)value; return 0;\n}')
    assert main(["--artifacts", str(store.root), "--build", "--runtime"], llm=FakeLLM([code])) == 1
    marker = next((store.root / "context_generations").glob("*/*/*/metadata.json"))
    assert json.loads(marker.read_text())["status"] == "runtime_failed"
    runtime = json.loads((marker.parent / "build/runtime.json").read_text())
    assert runtime["status"] == "failed"
    assert all(case["success"] is False and case["return_code"] not in {None, 0} for case in runtime["cases"])


def test_c_language_plan_compiles_and_replays(tmp_path):
    store, _, _ = ready(tmp_path)
    code = DIRECT_CODE.replace('extern "C" ', '')
    assert main(["--artifacts", str(store.root), "--language", "c", "--build", "--runtime"], llm=FakeLLM([code])) == 0
    marker = next((store.root / "context_generations").glob("*/*/*/metadata.json"))
    assert (marker.parent / "harness.c").is_file()


def test_code_call_order_violation_rejected(tmp_path):
    _, _, plan = ready(tmp_path, "context")
    code = '''#include <stddef.h>
#include <stdint.h>
typedef struct Context { int ready; int calls; } Context;
extern "C" Context *create(void);
extern "C" void destroy(Context *ctx);
extern "C" int parse(Context *ctx, const unsigned char *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 Context *ctx = create(); if(ctx) { destroy(ctx); parse(ctx,data,size); } return 0;
}'''
    assert "required_call_order_violated" in validate_code(code, plan)["errors"]


def test_unknown_derived_scalar_cannot_become_an_invented_expression(tmp_path):
    _, frozen, _ = ready(tmp_path)
    ft, context, closure, snapshot, report = frozen[:5]
    changed = deepcopy(context)
    changed["input_contract"]["bindings"][0]["size_parameter"] = None
    with pytest.raises(PlanError, match="derived argument"):
        HarnessPlanBuilder().build(ft, changed, closure, snapshot, report)


def test_multi_core_feed_parse_share_resource_and_run_in_evidenced_order(tmp_path):
    source = '''#include <stdlib.h>
#include <stddef.h>
typedef struct Context { const unsigned char *data; size_t size; } Context;
Context *create(void) { return calloc(1, sizeof(Context)); }
void destroy(Context *ctx) { free(ctx); }
void feed(Context *ctx, const unsigned char *data, size_t size) { ctx->data=data; ctx->size=size; }
int parse(Context *ctx) { if(!ctx->data) abort(); return ctx->size ? ctx->data[0] : 0; }
void usage(const unsigned char *data, size_t size) { Context *ctx=create(); Context *alias=ctx; feed(alias,data,size); parse(ctx); destroy(alias); }
'''
    prepared = setup(tmp_path, source, roles={"parse": ("core", "accepted_anchor"), "feed": ("core", "external_input_injection"),
        "create": ("support", "resource_creation"), "destroy": ("support", "resource_cleanup")})
    ids = prepared[0][-1]
    parse, feed, create, destroy = (ids[name] for name in ("parse", "feed", "create", "destroy"))
    rid = resource_id(parse, "ctx")
    base = context_specs(ids)
    specs = {key: value for key, value in base.items() if key[0] != parse}
    specs[(create, "lifecycle")]["value"]["resources"][0]["resource_id"] = rid
    specs[(create, "ownership")]["value"]["entries"][0]["resource_id"] = rid
    specs.update(direct_specs(feed))
    specs[(feed, "ownership")]["value"]["entries"][0]["lifetime"] = "until_context_cleanup"
    specs[(feed, "argument_construction")]["value"]["arguments"].insert(0, argument("ctx", "derived", resource=rid))
    specs[(feed, "ownership")]["value"]["entries"].append(owner("ctx", resource=rid))
    for fid in (feed, parse):
        specs[(fid, "lifecycle")] = {"value": lifecycle_value(fid, rid, "Context", "ctx", create, destroy),
            "dependencies": [{"function_id": create, "necessity": "required", "reason": "creation"},
                             {"function_id": destroy, "necessity": "required", "reason": "cleanup"}]}
        specs[(fid, "call_order")] = {"value": {"constraints": [order(create, feed), order(feed, parse), order(parse, destroy)]}}
        specs[(fid, "state")] = {"value": {"preconditions": [{"parameter": "ctx", "kind": "initialized" if fid == feed else "input_fed", "api": create if fid == feed else feed}]}}
    specs[(parse, "input_binding")] = {"value": {"bindings": [{"parameter": "ctx", "source": "context", "transform": "field",
        "size_parameter": None, "size_relation": "none", "nul_terminated": False, "binary_zero_allowed": None,
        "mutable": False, "alignment": "none", "via_function_id": feed}]}}
    specs[(parse, "argument_construction")] = {"value": {"arguments": [argument("ctx", "derived", resource=rid)]}}
    specs[(parse, "ownership")] = {"value": {"entries": [owner("ctx", resource=rid)]}}
    specs[(parse, "return_semantics")] = {"value": {"success": "always", "nullable": None, "owned": None, "error_cleanup": False}}
    from harness_generation.harness_context import HarnessRequirementBuilder
    row = next(r for r in HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"] if r["subject_function_id"] == parse)
    prepared[5].activate(row)
    prepared[5].execute("find_resource_flows", {"function": parse})
    run, _ = mine(prepared, specs, persist=True)
    assert_gate(run)
    frozen = load_frozen_inputs(prepared[0][0], prepared[1]["ft_id"])
    plan = HarnessPlanBuilder().build(*frozen[:5])
    assert [r["symbol"] for r in plan["call_sequence"]] == ["create", "feed", "parse"]
    bad = deepcopy(run.context)
    for resource in bad["lifecycle_contract"]["resources"]:
        if resource["function_id"] == parse:
            resource["resource_id"] = "resource_other"
    with pytest.raises(PlanError, match="shared resource identity"):
        HarnessPlanBuilder().build(prepared[1], bad, run.closure, prepared[3], run.completeness)
    code = '''#include <stdint.h>
#include <stddef.h>
typedef struct Context { const unsigned char *data; size_t size; } Context;
extern "C" Context *create(void);
extern "C" void destroy(Context *ctx);
extern "C" void feed(Context *ctx, const unsigned char *data, size_t size);
extern "C" int parse(Context *ctx);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 if(size>1048576) return 0;
 Context *ctx=create(); if(ctx) { feed(ctx,data,size); parse(ctx); destroy(ctx); } return 0;
}'''
    assert main(["--artifacts", str(prepared[0][0].root), "--build", "--runtime"], llm=FakeLLM([code])) == 0
