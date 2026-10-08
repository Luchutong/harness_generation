"""Slice behavior and invariants; every model in this module is offline."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from harness_generation.artifacts import ArtifactStore
from harness_generation.entry_candidates import discover_candidates
from harness_generation.records import write_json
from harness_generation.semantic_discovery import (AgentModelResponse, AgentToolCall, CandidateValidationAgent,
    FakeAgentModel, RecordedAgentModel, RepositoryTools, ValidationBudget)
from harness_generation.semantic_discovery.models import candidate_id, canonical
from harness_generation.semantic_discovery.persistence import (run_configuration as validation_config,
    save_run as save_validation, write_validated_catalog)
from harness_generation.semantic_discovery.tools import RepositoryIndex
from harness_generation.semantic_discovery.tools import ToolBudgetExceeded
from harness_generation.semantic_slicing import SemanticSliceAgent, SemanticSliceTools, build_frontier, validate_submission
from harness_generation.semantic_slicing.cli import main
from harness_generation.semantic_slicing.persistence import (load_accepted_candidates, load_compatible_slice,
    run_configuration, save_run)
from harness_generation.sfg_adapter import load_sfg_artifacts
from sfg_builder.parser import CProjectParser, write_functions_json

HUB = """typedef unsigned long size_t;
typedef struct Context { const unsigned char *data; size_t size; int logger; int calls; } Context;
Context *create(void) { return calloc(1, sizeof(Context)); }
void destroy(Context *ctx) { free(ctx); }
void set_logger(Context *ctx) { ctx->logger = 1; }
int stats(Context *ctx) { return ctx->calls; }
void feed(Context *ctx, const void *data, size_t size) { ctx->data = data; ctx->size = size; }
int parse(Context *ctx) { ctx->calls++; return ctx->size ? ctx->data[0] : 0; }
int encode(Context *ctx, unsigned char *out) { out[0] = (unsigned char)ctx->calls; return 1; }
int unrelated(const unsigned char *data, size_t size) { return size ? data[size - 1] : 0; }
"""
DIRECT = """typedef unsigned long size_t;
int parse(const unsigned char *data, size_t size) { return size ? data[0] : 0; }
int wrapper(const unsigned char *data, size_t size) { return parse(data, size); }
int unrelated(void) { return 7; }
"""


def tool(name, call_id, **args):
    return AgentToolCall(call_id, name, canonical(args))


def queries(*calls):
    return AgentModelResponse(tool_calls=tuple(calls))


def tool_records(messages):
    return [record for message in messages if message["role"] == "tool"
            for record in json.loads(message["content"]).get("evidence", [])]


def terminal(mapping, *, mutate=None):
    """Rows use exact IDs and prefer the relevant function's source evidence."""
    def respond(messages, schemas):
        records = tool_records(messages)
        rows = []
        for fid, (role, reason) in mapping.items():
            proofs = [r for r in records if r.get("function_id") == fid]
            bodies = [r for r in proofs if r["tool"] == "get_function"]
            selected = bodies or proofs
            rows.append({"function_id": fid, "role": role, "reason_codes": [reason],
                "evidence_ids": [r["evidence_id"] for r in selected],
                "open_questions": ["Need more source evidence."] if role == "unresolved" else []})
        payload = {"classification": rows}
        if mutate:
            mutate(payload)
        return queries(tool("submit_semantic_slice", "terminal", **payload))
    return respond


def fixture(tmp_path, source=HUB, anchor="parse", *, oversized=False, relations=False):
    project = tmp_path / "project"
    project.mkdir()
    (project / "api.c").write_text(source)
    store = ArtifactStore(tmp_path / "phase1")
    write_functions_json(CProjectParser().parse(project), store.functions, project=project)
    write_json(store.annotations, {"schema_version": 1, "annotations": []})
    write_json(store.flows, {"schema_version": 1, "flows": []})
    write_json(store.sfg, {"schema_version": 1, "nodes": [], "edges": [], "functions": []})
    artifacts = load_sfg_artifacts(store.root)
    ids = {f["name"]: f["id"] for f in artifacts.functions}
    if relations:
        write_json(store.root / "ownership.json", {"schema_version": 1, "relations": [{
            "id": "ownership_context", "producer_function_id": ids["create"],
            "cleanup_function_id": ids["destroy"], "resource_type": "Context",
            "source": "fixture_contract", "confidence": 1.0, "evidence": ["owned Context allocation/release"]}]})
        write_json(store.root / "usage_patterns.json", {"schema_version": 1, "patterns": [{
            "id": "usage_context", "lifecycle_kind": "owned_resource", "resource_type": "Context",
            "producer_function_id": ids["create"], "producer_function": "create", "producer_binding": "return_value",
            "cleanup_function_id": ids["destroy"], "cleanup_function": "destroy", "cleanup_argument": "resource",
            "consumers": ["feed", "parse"], "consumer_function_ids": [ids["feed"], ids["parse"]],
            "consumer_argument_indices": [0, 0], "sequence": ["create", "feed", "parse", "destroy"],
            "conditions": [], "path_kind": "normal", "evidence": ["fixture explicit usage trace"],
            "support_by_source": {"test": 1}, "support_total": 1}]})
        artifacts = load_sfg_artifacts(store.root)
    catalog = discover_candidates(artifacts)
    if oversized:
        catalog = replace(catalog, candidates=tuple(replace(c, metadata={"construction": {
            "status": "oversized", "diagnostics": [{"anchor_function_id": c.function_id,
                "reason": "too_many_functions", "frontier": {"function_ids": list(ids.values()),
                    "relation_evidence": {"strong": []}}}]}}) if c.function == anchor else c
            for c in catalog.candidates))
    store.write_candidate_catalog(catalog)
    candidate = next(c for c in catalog.candidates if c.function == anchor)
    def accept(messages, schemas):
        eids = [r["evidence_id"] for r in tool_records(messages)]
        return queries(tool("submit_candidate_decision", "validation_terminal", verdict="accepted",
            input_mode="processor_api", reason_codes=["parser_decoder_consumer_api"], evidence_ids=eids,
            discovered_symbols=[], open_questions=[]))
    model = FakeAgentModel([queries(tool("get_function", "validation_source", function=candidate.function_id)), accept])
    budget = ValidationBudget()
    index = RepositoryIndex(artifacts, catalog, functions_path=store.functions)
    validation = CandidateValidationAgent(model, budget).validate(candidate, RepositoryTools(artifacts, catalog, index=index))
    assert validation.result["verdict"] == "accepted"
    save_validation(store, validation, validation_config(catalog, budget, model))
    write_validated_catalog(store, catalog, {candidate.function_id: validation.result}, {})
    return store, artifacts, catalog, candidate, validation.result, ids


def run(sample, responses, budget=None, *, discovery_limit=32):
    store, artifacts, catalog, candidate, validation, _ = sample
    budget = budget or ValidationBudget()
    frontier = build_frontier(store, artifacts, catalog, candidate, validation)
    index = RepositoryIndex(artifacts, catalog, functions_path=store.functions)
    tools = SemanticSliceTools(artifacts, catalog, frontier, budget, index=index,
                               max_discovered_functions=discovery_limit)
    model = FakeAgentModel(responses)
    return SemanticSliceAgent(model, budget).slice(tools), model, tools


def test_shared_context_hub_separates_core_support_and_unrelated(tmp_path):
    sample = fixture(tmp_path, relations=True)
    ids = sample[-1]
    mapping = {ids["parse"]: ("core", "accepted_anchor"), ids["feed"]: ("core", "external_input_injection"),
        ids["create"]: ("support", "required_initialization"), ids["destroy"]: ("support", "resource_cleanup"),
        ids["set_logger"]: ("exclude", "diagnostic_only"), ids["stats"]: ("exclude", "statistics_only")}
    result, _, _ = run(sample, [queries(*(tool("get_function", f"body_{name}", function=fid)
        for name, fid in ids.items() if fid in mapping)), terminal(mapping)])
    assert result.result["core_functions"] == sorted([ids["parse"], ids["feed"]])
    assert result.result["support_functions"] == sorted([ids["create"], ids["destroy"]])
    assert result.result["excluded_functions"] == sorted([ids["set_logger"], ids["stats"]])
    assert ids["encode"] in result.result["unresolved_frontier"]
    assert ids["unrelated"] not in result.result["unresolved_frontier"]


def test_direct_parser_does_not_force_expansion(tmp_path):
    sample = fixture(tmp_path, DIRECT)
    ids = sample[-1]
    result, model, _ = run(sample, [terminal({ids["parse"]: ("core", "accepted_anchor")})])
    assert result.result["core_functions"] == [ids["parse"]]
    assert result.result["unresolved_frontier"] == []
    assert result.result["budget"]["tool_calls"] == 1
    assert len(model.calls) == 1 and result.result["run_status"] == "completed"


def test_wrapper_discovers_real_delegate_through_call_evidence(tmp_path):
    sample = fixture(tmp_path, DIRECT, anchor="wrapper")
    ids = sample[-1]
    result, _, tools = run(sample, [queries(tool("find_callees", "callee", function=ids["wrapper"]),
        tool("get_function", "body_wrapper", function=ids["wrapper"])),
        queries(tool("get_function", "body_parse", function=ids["parse"])),
        terminal({ids["wrapper"]: ("core", "accepted_anchor"), ids["parse"]: ("core", "core_processing")})])
    assert result.result["core_functions"] == sorted([ids["wrapper"], ids["parse"]])
    assert tools.discovered == {ids["parse"]}
    assert result.metadata["discovery_evidence"][ids["parse"]] in tools.evidence


def test_unrelated_api_sharing_type_remains_unresolved(tmp_path):
    sample = fixture(tmp_path)
    ids = sample[-1]
    result, _, _ = run(sample, [terminal({ids["parse"]: ("core", "accepted_anchor")})])
    assert {ids["encode"], ids["set_logger"], ids["stats"]} <= set(result.result["unresolved_frontier"])
    assert result.result["excluded_functions"] == []


def test_oversized_frontier_is_paged_and_no_function_disappears(tmp_path):
    source = HUB + "\n".join(f"int query_{i}(Context *ctx) {{ return ctx->calls + {i}; }}" for i in range(80))
    sample = fixture(tmp_path, source, oversized=True)
    ids = sample[-1]
    result, model, tools = run(sample, [terminal({ids["parse"]: ("core", "accepted_anchor")})])
    assert len(result.result["core_functions"]) == 1
    assert len(result.result["unresolved_frontier"]) == len(ids) - 1
    seed = json.loads(model.calls[0]["messages"][-1]["content"])
    assert len(seed["evidence"]) == 1 and seed["next_offset"] == 1
    page = tools.execute("get_semantic_frontier", {"candidate_id": candidate_id(sample[3].function_id),
        "function_id": sample[3].function_id, "offset": 1})
    assert len(page["evidence"]) == 10 and page["total_matches"] == len(ids)
    assert all(json.loads(r["content"])["oversized_frontier"] for r in page["evidence"])


@pytest.mark.parametrize("budget", [ValidationBudget(max_tool_calls=1), ValidationBudget(max_rounds=1),
                                   ValidationBudget(max_source_chars=3300)])
def test_budget_exhaustion_keeps_anchor_and_unknowns(tmp_path, budget):
    sample = fixture(tmp_path)
    ids = sample[-1]
    # Repeat distinct calls until either repository or ordinary-round budget ends.
    responses = [queries(*(tool("get_function", f"read_{i}_{name}", function=fid)
                 for name, fid in ids.items() if name != "unrelated")) for i in range(6)]
    result, _, _ = run(sample, responses, budget)
    assert result.result["budget"]["exhausted"]
    assert result.result["run_status"] == "completed_with_unresolved"
    assert result.result["core_functions"] == [ids["parse"]]
    assert result.result["excluded_functions"] == []
    assert ids["stats"] in result.result["unresolved_frontier"]


def test_frontier_exposes_existing_strong_weak_and_provenance(tmp_path):
    sample = fixture(tmp_path, relations=True)
    store, artifacts, catalog, candidate, validation, ids = sample
    frontier = build_frontier(store, artifacts, catalog, candidate, validation)
    assert {r["kind"] for r in frontier.rows[ids["create"]]["strong_relations"]} == {"ownership", "explicit_usage_pattern"}
    assert frontier.rows[ids["stats"]]["strong_relations"] == []
    assert frontier.rows[ids["stats"]]["weak_relations"][0]["kind"] == "same_struct_type"
    result, _, tools = run(sample, [terminal({ids["parse"]: ("core", "accepted_anchor")})])
    output = tools.execute("get_semantic_frontier", {"candidate_id": candidate_id(candidate.function_id),
                                                    "function_id": candidate.function_id})
    create = next(json.loads(r["content"]) for r in output["evidence"] if r["function_id"] == ids["create"])
    assert create["shared_type_is_semantic_evidence"] is False
    assert "ownership.json" in create["provenance"]
    assert result.result["budget"]["source_chars"] <= result.result["budget"]["limits"]["max_source_chars"]


@pytest.mark.parametrize("mutation", ["anchor_excluded", "anchor_missing", "invented_function", "cross_run_evidence",
    "duplicate", "wrong_reason", "missing_evidence", "unknown_field", "bad_array", "name_instead_of_id"])
def test_strict_terminal_invariants_reject_invalid_rows(tmp_path, mutation):
    sample = fixture(tmp_path)
    fid = sample[3].function_id
    def mutate(payload):
        row = payload["classification"][0]
        if mutation == "anchor_excluded":
            row["role"], row["reason_codes"] = "exclude", ["unrelated_behavior"]
        elif mutation == "anchor_missing":
            payload["classification"] = []
        elif mutation == "invented_function":
            row["function_id"] = "api.c:99:invented"
        elif mutation == "cross_run_evidence":
            row["evidence_ids"] = ["ev_previous_run"]
        elif mutation == "duplicate":
            payload["classification"].append(deepcopy(row))
        elif mutation == "wrong_reason":
            row["reason_codes"] = ["shared_context_only"]
        elif mutation == "missing_evidence":
            row["evidence_ids"] = []
        elif mutation == "unknown_field":
            row["function"] = "parse"
        elif mutation == "bad_array":
            row["evidence_ids"] = "ev_bad"
        elif mutation == "name_instead_of_id":
            row["function_id"] = "parse"
    # Duplicate rows are shape-repairable under the registered last-round
    # extra. A second explicit duplicate payload must still be rejected; the
    # framework never removes a row or selects a role itself.
    first=terminal({fid: ("core", "accepted_anchor")}, mutate=mutate)
    responses=[first]
    if mutation == 'duplicate':
        def still_duplicate(messages,schemas):
            call=first(messages,schemas).tool_calls[0]
            return AgentModelResponse(tool_calls=(AgentToolCall('still_duplicate',call.name,call.arguments),))
        responses.append(still_duplicate)
    result, model, _ = run(sample, responses,
                       ValidationBudget(max_rounds=1))
    assert result.result["run_status"] == "invalid"
    assert result.metadata["canonical_is_fallback"]
    assert result.result["core_functions"] == [fid]
    assert result.result["excluded_functions"] == []
    assert result.metadata['extra_terminal_repair_attempts'] == int(mutation=='duplicate')
    assert len(model.calls) == 1+int(mutation=='duplicate')


@pytest.mark.parametrize("role,reason", [("core", "core_state_dependency"), ("support", "required_initialization"),
                                        ("exclude", "shared_context_only")])
def test_weak_frontier_alone_cannot_establish_decisive_role(tmp_path, role, reason):
    sample = fixture(tmp_path)
    ids = sample[-1]
    candidate = sample[3]
    result, _, _ = run(sample, [queries(tool("get_semantic_frontier", "frontier", candidate_id=candidate_id(candidate.function_id),
        function_id=candidate.function_id)), terminal({ids["parse"]: ("core", "accepted_anchor"), ids["stats"]: (role, reason)})])
    assert result.result["run_status"] == "invalid"
    assert ids["stats"] in result.result["unresolved_frontier"]


def test_evidence_about_another_function_cannot_classify_stats(tmp_path):
    sample = fixture(tmp_path)
    ids = sample[-1]
    def mutate(payload):
        payload["classification"].append({"function_id": ids["stats"], "role": "core",
            "reason_codes": ["core_state_dependency"], "evidence_ids": payload["classification"][0]["evidence_ids"],
            "open_questions": []})
    result, _, _ = run(sample, [terminal({ids["parse"]: ("core", "accepted_anchor")}, mutate=mutate)])
    assert result.result["run_status"] == "invalid"


def test_unresolved_requires_question_and_may_omit_evidence(tmp_path):
    sample = fixture(tmp_path)
    ids = sample[-1]
    result, _, _ = run(sample, [terminal({ids["parse"]: ("core", "accepted_anchor"),
                                         ids["stats"]: ("unresolved", "insufficient_evidence")})])
    assert result.result["run_status"] == "completed_with_unresolved"
    question = next(r for r in result.result["classification"] if r["function_id"] == ids["stats"])
    assert question["evidence_ids"] == [] and question["open_questions"]


def test_repository_scope_and_discovery_limit_are_enforced(tmp_path):
    sample = fixture(tmp_path, DIRECT, anchor="wrapper")
    _, _, tools = run(sample, [terminal({sample[3].function_id: ("core", "accepted_anchor")})], discovery_limit=0)
    ids = sample[-1]
    assert tools.execute("get_function", {"function": ids["unrelated"]})["error"] == "outside_semantic_frontier"
    assert tools.execute("find_symbol_references", {"symbol": "unrelated"})["error"] == "outside_semantic_frontier"
    assert tools.execute("read_source_range", {"file": "api.c", "line_start": 4, "line_end": 4})["error"] == "outside_semantic_frontier"
    output = tools.execute("find_callees", {"function": ids["wrapper"]})
    assert output["evidence_ids"] and output["discovery_limit_reached"]
    assert tools.discovered == set()
    assert tools.execute("get_function", {"function": ids["parse"]})["error"] == "outside_semantic_frontier"
    assert tools.execute("shell", {"command": "cat .env"})["error"] == "tool_not_allowed"


@pytest.mark.parametrize("mode", ["prose", "mixed"])
def test_slice_requires_sole_native_terminal_call(tmp_path, mode):
    sample = fixture(tmp_path)
    fid = sample[3].function_id
    valid = terminal({fid: ("core", "accepted_anchor")})
    def invalid(messages, schemas):
        response = valid(messages, schemas)
        if mode == "prose":
            return AgentModelResponse(content=response.tool_calls[0].arguments)
        return queries(*response.tool_calls, tool("get_function", "late_query", function=fid))
    # Plain prose has one bounded protocol recovery. Reject another prose
    # response rather than exhausting the fake transport on that repair call.
    result, _, _ = run(sample, [invalid, invalid] if mode == 'prose' else [invalid])
    assert result.result["run_status"] == "invalid" and result.result["budget"]["tool_calls"] == 1


def test_cli_processes_accepted_only_and_resume_needs_no_model_call(tmp_path):
    sample = fixture(tmp_path)
    store, _, _, candidate, _, ids = sample
    triplet_text = '{"schema_version":1,"triplets":[]}\n'
    (store.root / "triplets.json").write_text(triplet_text)
    discovery_before, validated_before = store.entry_candidates.read_bytes(), store.validated_candidates.read_bytes()
    model = FakeAgentModel([terminal({ids["parse"]: ("core", "accepted_anchor")})])
    args = ["--artifacts", str(store.root)]
    assert main(args, model=model) == 0
    directory = store.semantic_slice_run(candidate_id(candidate.function_id))
    assert {p.name for p in directory.iterdir()} == {"slice.json", "trace.json", "evidence.json", "metadata.json"}
    assert json.loads((directory / "slice.json").read_text())["anchor_function_id"] == candidate.function_id
    resumed = FakeAgentModel([])
    assert main(args + ["--resume"], model=resumed) == 0 and resumed.calls == []
    assert (store.root / "triplets.json").read_text() == triplet_text
    assert store.entry_candidates.read_bytes() == discovery_before
    assert store.validated_candidates.read_bytes() == validated_before
    assert main(args + ["--candidate", ids["stats"]], model=FakeAgentModel([])) == 1


def test_resume_rejects_tampered_trace_and_changed_budget(tmp_path):
    sample = fixture(tmp_path)
    store, artifacts, catalog, candidate, validation, ids = sample
    result, model, tools = run(sample, [terminal({ids["parse"]: ("core", "accepted_anchor")})])
    config = run_configuration(catalog, tools.frontier, tools.budget, model, 32)
    save_run(store, result, config)
    assert load_compatible_slice(store, tools.frontier, config, tools.index, tools.budget)
    changed = {**config, "budget": ValidationBudget(max_rounds=2).to_dict()}
    assert load_compatible_slice(store, tools.frontier, changed, tools.index, tools.budget) is None
    path = store.semantic_slice_run(candidate_id(candidate.function_id)) / "trace.json"
    doc = json.loads(path.read_text())
    doc["events"][0]["result_evidence_ids"] = []
    write_json(path, doc)
    assert load_compatible_slice(store, tools.frontier, config, tools.index, tools.budget) is None


def test_accepted_gate_rejects_stale_or_forged_validation(tmp_path):
    sample = fixture(tmp_path)
    store, artifacts, catalog, candidate, _, _ = sample
    index = RepositoryIndex(artifacts, catalog, functions_path=store.functions)
    assert len(load_accepted_candidates(store, catalog, index)) == 1
    doc = json.loads(store.validated_candidates.read_text())
    doc["candidates"][0]["status"] = "accepted"
    doc["candidates"][0]["validation"] = None
    write_json(store.validated_candidates, doc)
    with pytest.raises(ValueError):
        load_accepted_candidates(store, catalog, index)
    write_json(store.validated_candidates, [])
    with pytest.raises(ValueError):
        load_accepted_candidates(store, catalog, index)
    doc["candidates"][0]["status"] = {"malformed": True}
    write_json(store.validated_candidates, doc)
    with pytest.raises(ValueError):
        load_accepted_candidates(store, catalog, index)


def test_recorded_native_submission_replays_deterministically(tmp_path):
    sample = fixture(tmp_path, DIRECT)
    fid = sample[3].function_id
    result, model, tools = run(sample, [terminal({fid: ("core", "accepted_anchor")})])
    response = terminal({fid: ("core", "accepted_anchor")})(model.calls[0]["messages"], model.calls[0]["tools"])
    recording = tmp_path / "recorded.json"
    write_json(recording, [{"tool_calls": [{"id": c.id, "name": c.name, "arguments": c.arguments}
                                           for c in response.tool_calls]}])
    replay_tools = SemanticSliceTools(sample[1], sample[2], tools.frontier, index=tools.index)
    replay = SemanticSliceAgent(RecordedAgentModel.from_file(recording)).slice(replay_tools)
    assert replay.result["classification"] == result.result["classification"]
    assert replay.evidence == result.evidence


def test_too_small_budget_fails_without_invalid_canonical_slice(tmp_path):
    sample = fixture(tmp_path)
    with pytest.raises(ValueError, match="budget"):
        run(sample, [], ValidationBudget(max_source_chars=1))


def test_complete_live_range_supports_exclusion_and_real_discovery(tmp_path):
    sample = fixture(tmp_path)
    ids = sample[-1]
    def submit(messages, schemas):
        records = tool_records(messages)
        source = next(r for r in records if r["tool"] == "read_source_range")
        seed = next(r for r in records if r["tool"] == "get_semantic_frontier")
        return queries(tool("submit_semantic_slice", "terminal", classification=[
            {"function_id": ids["parse"], "role": "core", "reason_codes": ["accepted_anchor"],
             "evidence_ids": [seed["evidence_id"]], "open_questions": []},
            {"function_id": ids["stats"], "role": "exclude", "reason_codes": ["statistics_only"],
             "evidence_ids": [source["evidence_id"]], "open_questions": []}]))
    result, _, tools = run(sample, [queries(tool("read_source_range", "source", file="api.c", line_start=1, line_end=10)), submit])
    assert result.result["excluded_functions"] == [ids["stats"]]
    assert ids["unrelated"] in tools.discovered
    assert result.metadata["live_sources"]
    live_payload = next(json.loads(m["content"]) for m in result.trace["messages"]
                        if m["role"] == "tool" and json.loads(m["content"]).get("project_functions"))
    assert {r["function_id"] for r in live_payload["project_functions"]} == set(ids.values())
    assert all(r["evidence_id"] in tools.evidence for r in live_payload["project_functions"])


def test_partial_live_range_cannot_prove_exclusion(tmp_path):
    source = HUB.replace("int stats(Context *ctx) { return ctx->calls; }", "int stats(Context *ctx) {\n int n = ctx->calls;\n return n;\n}")
    sample = fixture(tmp_path, source)
    ids = sample[-1]
    def submit(messages, schemas):
        records = tool_records(messages)
        seed, live = records[0], next(r for r in records if r["tool"] == "read_source_range")
        return queries(tool("submit_semantic_slice", "terminal", classification=[
            {"function_id": ids["parse"], "role": "core", "reason_codes": ["accepted_anchor"],
             "evidence_ids": [seed["evidence_id"]], "open_questions": []},
            {"function_id": ids["stats"], "role": "exclude", "reason_codes": ["statistics_only"],
             "evidence_ids": [live["evidence_id"]], "open_questions": []}]))
    result, _, _ = run(sample, [queries(tool("read_source_range", "partial", file="api.c", line_start=6, line_end=7)), submit])
    assert result.result["run_status"] == "invalid"
    assert result.result["excluded_functions"] == []


def test_cleanup_wrapper_stays_support(tmp_path):
    source = HUB + "\nvoid release(Context *ctx) { destroy(ctx); }\n"
    sample = fixture(tmp_path, source)
    ids = sample[-1]
    result, _, _ = run(sample, [queries(tool("get_function", "release", function=ids["release"])),
        terminal({ids["parse"]: ("core", "accepted_anchor"), ids["release"]: ("support", "resource_cleanup")},
            mutate=lambda d: d["classification"][1]["reason_codes"].append("wrapper_delegation"))])
    assert result.result["support_functions"] == [ids["release"]]
    assert result.result["core_functions"] == [ids["parse"]]




def test_agent_api_requires_completed_accepted_validation(tmp_path):
    sample = fixture(tmp_path)
    changed = (*sample[:4], {**sample[4], "verdict": "rejected"}, sample[5])
    with pytest.raises(ValueError, match="accepted"):
        run(changed, [])


def test_source_identity_payload_budget_failure_rolls_back_query_and_discovery(tmp_path):
    sample = fixture(tmp_path)
    _, _, tools = run(sample, [terminal({sample[3].function_id: ("core", "accepted_anchor")})])
    arguments = {"file": "api.c", "line_start": 1, "line_end": 10}
    probe = RepositoryTools(sample[1], sample[2], index=tools.index)
    base_record = probe.execute("read_source_range", arguments)["evidence"][0]
    original_chars, original_evidence = tools.source_chars, dict(tools.evidence)
    original_symbols = set(tools.known_symbols)
    tools.budget = replace(tools.budget, max_source_chars=original_chars + len(canonical(base_record)) + 1)
    with pytest.raises(ToolBudgetExceeded, match="max_source_chars"):
        tools.execute("read_source_range", arguments)
    assert tools.source_chars == original_chars and tools.evidence == original_evidence
    assert tools.discovered == set() and tools.live_sources == {}
    assert tools.known_symbols == original_symbols


def test_slice_resume_checks_owned_live_source_hash(tmp_path):
    sample = fixture(tmp_path)
    fid = sample[3].function_id
    result, model, tools = run(sample, [queries(tool("read_source_range", "source", file="api.c", line_start=1, line_end=10)),
                                       terminal({fid: ("core", "accepted_anchor")})])
    config = run_configuration(sample[2], tools.frontier, tools.budget, model, 32)
    save_run(sample[0], result, config)
    assert load_compatible_slice(sample[0], tools.frontier, config, tools.index, tools.budget)
    source = tmp_path / "project/api.c"
    source.write_text(source.read_text() + "\n// changed after the run\n")
    assert load_compatible_slice(sample[0], tools.frontier, config, tools.index, tools.budget) is None
