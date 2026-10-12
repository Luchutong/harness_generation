"""Independent v0.5 test fixtures; offline models and bounded local C projects.

Fixtures do not import test modules or run the removed discovery/Slice/FT CLI.
v0.5 component tests receive an explicit FT-shaped shared-component input.
"""
from copy import deepcopy
import hashlib
import json
import sys

import pytest

from harness_generation.artifacts import ArtifactStore
from harness_generation.context_generation.build import SANITIZERS
from harness_generation.context_generation.executable_plan import ExecutablePlanBuilder
from harness_generation.effectiveness.validation import POLICY
from harness_generation.entry_candidates import CandidateCatalog
from harness_generation.harness_strategy.models import StrategyBudget
from harness_generation.harness_strategy.normalization import normalize_strategy
from harness_generation.harness_strategy.persistence import run_configuration
from harness_generation.harness_strategy.planner import StrategyPlanner
from harness_generation.harness_strategy.tools import StrategyTools
from harness_generation.lightweight_context import build_context
from harness_generation.minimal_ft.models import ProjectSnapshot
from harness_generation.orchestration.quality import capture_live_quality, execution_identity
from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, FakeAgentModel, canonical
from harness_generation.semantic_discovery.tools import RepositoryIndex, RepositoryTools
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.source_analysis import BuildAwareIndex
from sfg_builder.cli import main as parse_main


def block_legacy_proof_imports(monkeypatch):
    """Default generation must also work after these legacy modules are removed."""
    for name in ("harness_generation.semantic_effects.verifier",
                 "harness_generation.semantic_effects.summaries",
                 "harness_generation.strategy_context.gate"):
        monkeypatch.setitem(sys.modules, name, None)


COMPILE_HEADER = """#include <stdlib.h>
#define CJSON_CDECL
typedef struct Hooks { void (CJSON_CDECL *release)(void *); int state; } Hooks;
"""

COMPILE_SOURCE = """#include "api.h"
static int hidden(int value) { return value; }
int parse(Hooks *hooks) { return hooks->state; }
#if ENABLED
int conditional(void) { return 1; }
#endif
"""

def compile_fixture(tmp_path, *, source=COMPILE_SOURCE, header=COMPILE_HEADER, flags=None, extra_entries=()):
    project = tmp_path / "project"
    project.mkdir()
    (project / "api.h").write_text(header)
    (project / "api.c").write_text(source)
    commands = project / "compile_commands.json"
    flags = flags if flags is not None else ["-std=c11", "-DENABLED=0"]
    entries = [{"directory": str(project), "file": "api.c",
                "arguments": ["clang", *flags, "-c", "api.c", "-o", "output.o"]}, *extra_entries]
    commands.write_text(json.dumps(entries))
    artifacts = tmp_path / "artifacts"
    assert parse_main(["--project", str(project), "--output", str(artifacts), "--compile-commands", str(commands)]) == 0
    snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(artifacts))
    index = BuildAwareIndex.load(artifacts, snapshot)
    ids = {f["name"]: f["id"] for f in snapshot.functions.values()}
    return project, artifacts, commands, snapshot, index, ids

def step(kind, sid, eids, **values):
    return {"kind": kind, "step_id": sid, "evidence_ids": eids, "hypothesis_ids": [], **values}

def proposal(*steps, hypotheses=()):
    return {"steps": list(steps), "hypotheses": list(hypotheses), "open_questions": []}

ENTRY_HEADER = """#include <stddef.h>
#include <stdlib.h>
typedef struct State { int error; } State;
"""

ENTRY_SOURCE = """#include "api.h"
int completely_unrelated(State *state, const unsigned char *data, size_t size) {
  if (state == NULL) {
    if (state != NULL) state->error = 1;
    return -1;
  }
  if (size == 0) return 0;
  return data[0];
}
"""

def entry_fixture(tmp_path, source=ENTRY_SOURCE, *, header=ENTRY_HEADER, name="completely_unrelated", flags=None):
    project, artifacts, commands, snapshot, index, ids = compile_fixture(tmp_path,
        source=source, header=header, flags=flags or ["-std=c11"])
    ft = {"ft_id": "ft_entry_0123456789abcdef01234567", "anchor_function_id": ids[name],
        "core_functions": [{"function_id": ids[name], "role": "anchor"}],
        "support_candidates": [{"function_id": fid} for key, fid in ids.items() if key != name],
        "excluded_functions": []}
    tools = RepositoryTools(snapshot.artifacts, CandidateCatalog((), snapshot.source_fingerprint),
                            functions_path=artifacts / "functions.json")
    eids = {key: tools.execute("get_function", {"function": fid})["evidence_ids"] for key, fid in ids.items()}
    return ft, snapshot, ids, tools.evidence, eids, index, project, commands

EXECUTABLE_HEADER = """#include <stdlib.h>
#include <stddef.h>
typedef struct Obj { int value; const unsigned char *data; } Obj;
"""

EXECUTABLE_SOURCE = """#include "api.h"
Obj *create(const unsigned char *data, size_t size) {
 Obj *obj = malloc(sizeof(Obj));
 if (obj) { obj->value = size ? data[0] : 0; obj->data = NULL; }
 return obj;
}
int parse(Obj *obj) { return obj->value; }
void destroy(Obj *obj) {
 if (!obj) return;
 while (obj->value < -1) obj->value++;
 free(obj);
}
"""

def executable_fixture(tmp_path):
    # Build-aware authentication must describe the effective sanitizer recipe.
    project, artifacts, _, snapshot, analysis, ids = compile_fixture(tmp_path, source=EXECUTABLE_SOURCE,
        header=EXECUTABLE_HEADER + "Obj *create(const unsigned char *, size_t);\nint parse(Obj *);\nvoid destroy(Obj *);\n",
        flags=["-std=c11", *SANITIZERS])
    ft = {"ft_id": "ft_fixture_0123456789abcdef01234567", "anchor_function_id": ids["parse"],
          "core_functions": [{"function_id": ids["parse"], "role": "anchor"}],
          "support_candidates": [{"function_id": fid} for name, fid in ids.items() if name != "parse"],
          "excluded_functions": []}
    tools = RepositoryTools(snapshot.artifacts, CandidateCatalog((), snapshot.source_fingerprint),
                            functions_path=artifacts / "functions.json")
    eids = {name: tools.execute("get_function", {"function": fid})["evidence_ids"] for name, fid in ids.items()}
    proposed = proposal(
        step("call", "create_call", eids["create"], function_id=ids["create"],
             arguments={"data": {"kind": "fuzz_bytes"}, "size": {"kind": "fuzz_size"}}, guard_ids=[]),
        step("capture", "capture_obj", eids["create"], value_id="obj", call_step_id="create_call", source="return", parameter=""),
        step("guard", "nonnull_obj", eids["create"], condition={"kind": "nonnull", "value_id": "obj"}),
        step("call", "parse_call", eids["parse"], function_id=ids["parse"],
             arguments={"obj": {"kind": "value", "value_id": "obj"}}, guard_ids=["nonnull_obj"]),
        step("cleanup", "cleanup_obj", eids["destroy"], function_id=ids["destroy"],
             arguments={"obj": {"kind": "value", "value_id": "obj"}}, resource_value_id="obj", guard_ids=["nonnull_obj"]))
    strategy = normalize_strategy(proposed, ft, snapshot)
    inputs = dict(ft=ft, snapshot=snapshot, evidence=tools.evidence, authorized_ids=set(ids.values()), build_analysis=analysis)
    return inputs, strategy, project

def build_executable_plan(inputs, strategy):
    return ExecutablePlanBuilder().build(**inputs, strategy=strategy, headers=("api.h",))

LIGHTWEIGHT_HEADER = '''#include <stdlib.h>
typedef struct Object { int value; } Object;
typedef struct Other { int value; } Other;
Object *parse(const unsigned char *data, size_t size);
Object *create(void);
int use(Object *object, const unsigned char *data, size_t size);
void destroy(Object *object);
int unrelated(Other *other);
'''

LIGHTWEIGHT_SOURCE = '''#include "api.h"
Object *create(void) { return calloc(1, sizeof(Object)); }
Object *parse(const unsigned char *data, size_t size) {
    if (!size) return NULL;
    Object *object = create();
    if (object) object->value = data[0];
    return object;
}
int use(Object *object, const unsigned char *data, size_t size) {
    return size ? object->value + data[0] : object->value;
}
void destroy(Object *object) { free(object); }
static int hidden(Object *object) { return object->value; }
int unrelated(Other *other) { return other->value; }
'''

@pytest.fixture(scope="module")
def lightweight_sample(tmp_path_factory):
    root = tmp_path_factory.mktemp("lightweight_api")
    project, artifacts, commands, snapshot, analysis, ids = compile_fixture(root, source=LIGHTWEIGHT_SOURCE, header=LIGHTWEIGHT_HEADER)
    catalog = CandidateCatalog((), snapshot.source_fingerprint)
    index = RepositoryIndex(snapshot.artifacts, catalog, functions_path=artifacts / "functions.json")
    ids = {row["name"]: row["id"] for row in snapshot.functions.values() if row.get("defined")}
    return project, artifacts, commands, snapshot, analysis, ids, index

def context_for(lightweight_sample, anchor="parse", *, budget=None):
    _, _, _, snapshot, analysis, ids, index = lightweight_sample
    return build_context(snapshot, analysis, index, ids[anchor], budget=budget)

def proposal_for(lightweight_sample, context, evidence, *, use_create=False):
    ids = lightweight_sample[5]
    anchor = "use" if use_create else "parse"
    producer = "create" if use_create else anchor
    fid = ids[producer]
    steps = [{"step_id": "produce", "kind": "call", "function_id": fid,
        "arguments": {} if use_create else {"data": {"kind": "fuzz_bytes"}, "size": {"kind": "fuzz_size"}},
        "guard_ids": [], "evidence_ids": evidence[fid], "hypothesis_ids": []},
        {"step_id": "capture", "kind": "capture", "value_id": "object",
         "call_step_id": "produce", "source": "return", "parameter": "",
         "evidence_ids": evidence[fid], "hypothesis_ids": []},
        {"step_id": "nonnull", "kind": "guard", "condition": {"kind": "nonnull", "value_id": "object"},
         "evidence_ids": evidence[fid], "hypothesis_ids": []}]
    if use_create:
        steps.append({"step_id": "consume", "kind": "call", "function_id": ids["use"],
            "arguments": {"object": {"kind": "value", "value_id": "object"},
                "data": {"kind": "fuzz_bytes"}, "size": {"kind": "fuzz_size"}},
            "guard_ids": ["nonnull"], "evidence_ids": evidence[ids["use"]], "hypothesis_ids": []})
    steps.append({"step_id": "release", "kind": "cleanup", "function_id": ids["destroy"],
        "arguments": {"object": {"kind": "value", "value_id": "object"}},
        "guard_ids": ["nonnull"], "resource_value_id": "object",
        "evidence_ids": evidence[ids["destroy"]], "hypothesis_ids": []})
    return {"steps": steps, "hypotheses": [], "open_questions": []}

def quality_outcome(code="int fixture;", *, experimental=True):
    return {"success": True, "experimental": experimental,
            "generation_allowed": not experimental, "code": code,
            "plan_digest": "plan", "strategy_digest": "strategy",
            "build": {"success": True, "recipe_digest": "recipe", "target_input_digests": {}},
            "runtime": {"status": "passed", "cases": [{"success": True, "timed_out": False}]}}

def quality_measurement(tmp_path, work, effective):
    source, harness = tmp_path / "target.c", tmp_path / "harness.c"
    source.write_text("int target(int x) { return x != 0; }")
    harness.write_text(work["code"])
    probes = []
    for number in (1, 2):
        for repetition in (1, 2):
            region = "taken" if effective is True and number == 2 else "common"
            probes.append({"input_sha256": hashlib.sha256(bytes([number])).hexdigest(),
                "repetition": repetition, "execution": {"exit_code": 0, "timed_out": False},
                "target_profile": {"status": "recorded", "target_call_count": 1,
                    "valid_state_call_count": 0 if effective is False else 1,
                    "body_region_ids": ["common", "taken"],
                    "covered_body_region_ids": [region], "covered_body_edge_ids": []}})
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    return {"policy_version": POLICY, "buildable": True, "runtime_stable": True,
            "fuzz_effective": True,  # Deliberately false label for two cases.
            "source_identity_unchanged": True, "source_file_hashes": {str(source): source_hash},
            "build_dependency_hashes": {str(source): source_hash},
            "harness_sha256": execution_identity(work)["harness_sha256"], "harness_path": str(harness),
            "contract": {"status": "supported", "source_file": str(source)}, "probes": probes}

def quality_receipt(tmp_path, work, effective):
    evidence = quality_measurement(tmp_path, work, effective)
    return capture_live_quality(work, lambda: evidence, binding=execution_identity(work))

def planner_fixture(tmp_path, budget=None):
    """Exercise the shared FT planner without building a legacy FT pipeline."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "api.c").write_text(
        "typedef unsigned long size_t;\n"
        "int parse(const unsigned char *data, size_t size) { return size ? data[0] : 0; }\n"
    )
    store = ArtifactStore(tmp_path / "artifacts")
    assert parse_main(["--project", str(project), "--output", str(store.root)]) == 0
    snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(store.root))
    fid = next(row["id"] for row in snapshot.functions.values() if row["name"] == "parse")
    ft = {"ft_id": "ft_fixture_0123456789abcdef01234567", "anchor_function_id": fid,
          "core_functions": [{"function_id": fid, "role": "anchor"}],
          "support_candidates": [], "excluded_functions": []}
    metadata = {"fixture": "independent shared planner input"}
    catalog = CandidateCatalog((), snapshot.source_fingerprint)
    budget = budget or StrategyBudget()
    index = RepositoryIndex(snapshot.artifacts, catalog, functions_path=store.functions)
    tools = StrategyTools(snapshot, catalog, ft, budget, index=index)
    return store, ft, metadata, snapshot, budget, tools


def planner_source_request(fid):
    return AgentModelResponse(tool_calls=(AgentToolCall("body", "get_function", canonical({"function": fid})),))

def planner_proposal(fid, eid, *, integer_only=False, step_id="parse"):
    return {"steps": [{"step_id": step_id, "kind": "call", "function_id": fid,
        "arguments": {"data": {"kind": "null"} if integer_only else {"kind": "fuzz_bytes"},
                      "size": {"kind": "integer", "value": 0} if integer_only else {"kind": "fuzz_size"}},
        "guard_ids": [], "evidence_ids": [eid], "hypothesis_ids": []}],
        "hypotheses": [], "open_questions": []}

def planner_terminal(*, integer_only=False, multiple=False, call_id="submit"):
    def respond(messages, schemas):
        source = next(row for message in messages if message["role"] == "tool"
            for row in json.loads(message["content"]).get("evidence", []) if row.get("tool") == "get_function")
        proposals = [planner_proposal(source["function_id"], source["evidence_id"], integer_only=integer_only)]
        if multiple:
            proposals.append(deepcopy(proposals[0]))
        return AgentModelResponse(tool_calls=(AgentToolCall(call_id, "submit_harness_strategies",
            canonical({"strategies": proposals})),), metadata={"usage": {"prompt_tokens": 11,
                "completion_tokens": 7, "total_tokens": 18}, "finish_reason": "tool_calls"})
    return respond

def run_planner_fixture(sample, responses=None):
    store, ft, metadata, snapshot, budget, tools = sample
    model = FakeAgentModel(responses or [planner_source_request(ft["anchor_function_id"]), planner_terminal()])
    run = StrategyPlanner(model, budget).plan(ft, snapshot, tools)
    config = run_configuration(ft, metadata, snapshot, budget, model)
    return run, model, config
