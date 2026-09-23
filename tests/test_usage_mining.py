from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace

from sfg_builder.models import FunctionInfo, ParameterInfo
from sfg_builder.usage import load_usage_json, mine_usage_patterns, write_usage_json
from sfg_builder.usage_semantics import review_usage_semantics
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import (MockSemanticAnalyzer, SemanticDecision,
                                  USAGE_REVIEW_PROMPT_VERSION,
                                  usage_review_prompt)
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.triplet_extractor import extract_function_triplets


def parameter(name, base, *, depth=1, opaque=True):
    return ParameterInfo(
        name, base + (" *" * max(0, depth - 1)), f"{base} {name}",
        depth > 0, False, base, depth, True, opaque,
    )


def function(name, *, file="src/api.c", body="", return_type="void",
             return_base=None, return_depth=0, opaque_return=False, parameters=()):
    return FunctionInfo(
        f"{file}:1:{name}", name, file, 1, 3, return_type,
        return_base or return_type, return_depth, opaque_return,
        tuple(parameters), f"{return_type} {name}(void)", body, True,
        return_is_opaque_handle=opaque_return,
    )


def lifecycle_api():
    handle = parameter("parser", "Parser")
    return (
        function("ParserCreate", return_type="Parser", return_base="Parser",
                 return_depth=1, opaque_return=True),
        function("ParserParse", return_type="int", parameters=(handle,)),
        function("ParserReset", parameters=(handle,)),
        function("ParserFree", parameters=(handle,)),
    )


class SemanticMergeAnalyzer(MockSemanticAnalyzer):
    def review_usage_patterns(self, patterns, functions):
        prompt = usage_review_prompt(patterns, functions)
        decisions = []
        for pattern in patterns:
            sequence = list(pattern["sequence"])
            producer = pattern["producer_function"]
            decisions.append({
                "pattern_id": pattern["id"],
                "is_valid_lifecycle": True,
                "lifecycle_kind": pattern["lifecycle_kind"],
                "required_sequence": [
                    name for name in sequence if name != "ParserReset"
                ],
                "optional_calls": (["ParserReset"] if "ParserReset" in sequence else []),
                "merge_group": ("create_parse" if producer == "ParserCreate"
                                else "create_ns_parse"),
                "confidence": 0.92,
                "reason": "ParserReset is optional for this create/parse/free lifecycle",
            })
        data = {"decisions": decisions}
        return SemanticDecision(
            data, prompt, USAGE_REVIEW_PROMPT_VERSION, data, 0.92
        )


class InventingSemanticAnalyzer(MockSemanticAnalyzer):
    def review_usage_patterns(self, patterns, functions):
        decision = super().review_usage_patterns(patterns, functions)
        for item in decision.data["decisions"]:
            item["required_sequence"].insert(-1, "InventedAPI")
        return decision


class SingletonOnlySemanticAnalyzer(MockSemanticAnalyzer):
    def review_usage_patterns(self, patterns, functions):
        if len(patterns) > 1:
            raise RuntimeError("provider rejected a multi-pattern request")
        return super().review_usage_patterns(patterns, functions)


class FlakySingletonSemanticAnalyzer(MockSemanticAnalyzer):
    def __init__(self):
        self.attempts = 0

    def review_usage_patterns(self, patterns, functions):
        self.attempts += 1
        if self.attempts == 1:
            raise RuntimeError("transient malformed provider response")
        return super().review_usage_patterns(patterns, functions)


def test_support_is_aggregated_by_test_example_and_production_callers(tmp_path):
    callers = (
        function("test_usage", file="tests/parser_test.c",
                 body="{ Parser p = ParserCreate(); ParserParse(p); if (p) ParserFree(p); }"),
        function("example_usage", file="examples/basic.c",
                 body="{ Parser parser = ParserCreate(); ParserParse(parser); if (parser) ParserFree(parser); }"),
        function("real_usage", file="src/client.c",
                 body="{ Parser p = ParserCreate(); ParserParse(p); if (p) ParserFree(p); }"),
    )
    result = mine_usage_patterns((*lifecycle_api(), *callers))
    assert len(result.traces) == 3
    assert len(result.patterns) == 1
    pattern = result.patterns[0]
    assert pattern.sequence == ("ParserCreate", "ParserParse", "ParserFree")
    assert pattern.support_total == 3
    assert pattern.support_by_source == {"test": 1, "example": 1, "production": 1}
    assert pattern.conditions == ("($resource)",)
    assert pattern.path_kind == "conditional"

    path = write_usage_json(result, tmp_path / "usage_patterns.json")
    loaded = load_usage_json(path)
    assert loaded[0]["support_total"] == 3


def test_same_variable_dataflow_does_not_join_unrelated_handles():
    caller = function(
        "mixed", file="tests/mixed.c",
        body=("{ Parser a = ParserCreate(); Parser b = ParserCreate(); "
              "ParserParse(a); ParserReset(b); ParserFree(a); ParserFree(b); }")
    )
    patterns = mine_usage_patterns((*lifecycle_api(), caller)).patterns
    sequences = {pattern.sequence for pattern in patterns}
    assert ("ParserCreate", "ParserParse", "ParserFree") in sequences
    assert ("ParserCreate", "ParserReset", "ParserFree") in sequences
    assert all(not ({"ParserParse", "ParserReset"} <= set(pattern.consumers))
               for pattern in patterns)


def test_reassigning_one_variable_stops_the_previous_lifecycle():
    caller = function(
        "reuse", file="tests/reuse.c",
        body=("{ Parser p = ParserCreate(); ParserParse(p); ParserFree(p); "
              "p = ParserCreate(); ParserReset(p); ParserFree(p); }")
    )
    patterns = mine_usage_patterns((*lifecycle_api(), caller)).patterns
    assert {item.sequence for item in patterns} == {
        ("ParserCreate", "ParserParse", "ParserFree"),
        ("ParserCreate", "ParserReset", "ParserFree"),
    }


def test_direct_alias_keeps_one_resource_identity_through_cleanup():
    caller = function(
        "alias", file="src/alias.c",
        body=("{ Parser p = ParserCreate(); Parser q = p; "
              "ParserParse(q); ParserFree(q); }")
    )
    patterns = mine_usage_patterns((*lifecycle_api(), caller)).patterns
    assert len(patterns) == 1
    assert patterns[0].sequence == (
        "ParserCreate", "ParserParse", "ParserFree"
    )


def test_consumer_and_cleanup_argument_positions_are_preserved():
    scalar = ParameterInfo("mode", "int", "int mode", False, False, "int", 0)
    handle = parameter("parser", "Parser")
    consume = function("ParserConsume", return_type="int", parameters=(scalar, handle))
    release = function("ParserRelease", parameters=(scalar, handle, scalar))
    caller = function(
        "positions", file="examples/positions.c",
        body=("{ Parser p = ParserCreate(); ParserConsume(1, p); "
              "ParserRelease(0, p, 0); }")
    )
    pattern = mine_usage_patterns((
        lifecycle_api()[0], consume, release, caller,
    )).patterns[0]
    assert pattern.consumer_argument_indices == (1,)
    assert pattern.cleanup_argument_index == 1


def test_duplicate_static_names_resolve_to_the_callers_own_file():
    make_a = replace(
        function("make", file="src/a.c", return_type="Parser",
                 return_base="Parser", return_depth=1, opaque_return=True),
        storage=("static",),
    )
    make_b = replace(
        function("make", file="src/b.c", return_type="Parser",
                 return_base="Parser", return_depth=1, opaque_return=True),
        storage=("static",),
    )
    caller_a = function(
        "caller_a", file="src/a.c",
        body="{ Parser p = make(); ParserParse(p); ParserFree(p); }",
    )
    caller_b = function(
        "caller_b", file="src/b.c",
        body="{ Parser p = make(); ParserParse(p); ParserFree(p); }",
    )
    patterns = mine_usage_patterns((
        *lifecycle_api()[1:], make_a, make_b, caller_a, caller_b,
    )).patterns
    assert {item.producer_function_id for item in patterns} == {
        "src/a.c:1:make", "src/b.c:1:make",
    }


def test_distinct_usage_sequences_remain_distinct_patterns():
    caller_a = function(
        "simple", file="examples/simple.c",
        body="{ Parser p = ParserCreate(); ParserParse(p); ParserFree(p); }",
    )
    caller_b = function(
        "resetting", file="examples/reset.c",
        body="{ Parser p = ParserCreate(); ParserReset(p); ParserParse(p); ParserFree(p); }",
    )
    patterns = mine_usage_patterns((*lifecycle_api(), caller_a, caller_b)).patterns
    assert {pattern.sequence for pattern in patterns} == {
        ("ParserCreate", "ParserParse", "ParserFree"),
        ("ParserCreate", "ParserReset", "ParserParse", "ParserFree"),
    }


def test_semantic_review_cannot_invent_calls_or_override_static_dataflow():
    caller = function(
        "simple", file="tests/simple.c",
        body="{ Parser p = ParserCreate(); ParserParse(p); ParserFree(p); }",
    )
    functions = (*lifecycle_api(), caller)
    mined = mine_usage_patterns(functions)
    reviewed = review_usage_semantics(
        mined, functions,
        (SimpleNamespace(function="ParserParse", labels=("ISF",)),),
        InventingSemanticAnalyzer(),
    )
    review = reviewed.patterns[0].semantic_review
    assert review["status"] == "invalid_response"
    assert review["required_sequence"] == list(reviewed.patterns[0].sequence)
    assert "InventedAPI" not in review["required_sequence"]
    assert reviewed.semantic_reviews[0]["status"] == "ok"


def test_semantic_review_splits_failed_batches_and_retains_each_pattern():
    callers = (
        function(
            "simple", file="tests/simple.c",
            body="{ Parser p = ParserCreate(); ParserParse(p); ParserFree(p); }",
        ),
        function(
            "reset", file="tests/reset.c",
            body=("{ Parser p = ParserCreate(); ParserReset(p); "
                  "ParserParse(p); ParserFree(p); }"),
        ),
    )
    functions = (*lifecycle_api(), *callers)
    reviewed = review_usage_semantics(
        mine_usage_patterns(functions), functions,
        (SimpleNamespace(function="ParserParse", labels=("ISF",)),),
        SingletonOnlySemanticAnalyzer(),
    )

    assert len(reviewed.patterns) == 2
    assert {item.semantic_review["status"] for item in reviewed.patterns} == {
        "accepted"
    }
    assert [item["status"] for item in reviewed.semantic_reviews].count("error") == 1
    assert [item["status"] for item in reviewed.semantic_reviews].count("ok") == 2


def test_semantic_review_retries_a_failed_single_pattern_once():
    caller = function(
        "simple", file="tests/simple.c",
        body="{ Parser p = ParserCreate(); ParserParse(p); ParserFree(p); }",
    )
    functions = (*lifecycle_api(), caller)
    analyzer = FlakySingletonSemanticAnalyzer()
    reviewed = review_usage_semantics(
        mine_usage_patterns(functions), functions,
        (SimpleNamespace(function="ParserParse", labels=("ISF",)),), analyzer,
    )

    assert analyzer.attempts == 2
    assert reviewed.patterns[0].semantic_review["status"] == "accepted"
    assert [item["status"] for item in reviewed.semantic_reviews] == ["error", "ok"]


def test_out_parameter_producer_and_error_cleanup_are_modeled():
    open_api = function(
        "ParserOpen", return_type="int",
        parameters=(parameter("out", "Parser", depth=2),),
    )
    caller = function(
        "open_and_parse", file="src/client.c",
        body=("{ Parser p; int rc = ParserOpen(&p); if (rc != 0) { "
              "if (p) ParserFree(p); return; } ParserParse(p); ParserFree(p); }")
    )
    patterns = mine_usage_patterns((*lifecycle_api()[1:], open_api, caller)).patterns
    out_patterns = [item for item in patterns if item.producer_function == "ParserOpen"]
    assert out_patterns
    assert all(item.producer_binding == "out_parameter" for item in out_patterns)
    assert all(item.producer_argument_index == 0 for item in out_patterns)
    assert any(item.path_kind == "error" for item in out_patterns)
    assert any(item.path_kind == "normal" for item in out_patterns)


def test_goto_cleanup_label_is_recognized_as_an_error_path():
    open_api = function(
        "ParserOpen", return_type="int",
        parameters=(parameter("out", "Parser", depth=2),),
    )
    caller = function(
        "goto_cleanup", file="src/client.c",
        body=("{ Parser p; int rc = ParserOpen(&p); if (rc != 0) goto fail; "
              "ParserParse(p); return; fail: ParserFree(p); }")
    )
    patterns = mine_usage_patterns((*lifecycle_api()[1:], open_api, caller)).patterns
    pattern = next(item for item in patterns if item.producer_function == "ParserOpen")
    assert pattern.path_kind == "error"
    assert pattern.conditions == ("($value != 0)",)


def test_reference_count_pair_is_a_separate_lifecycle_kind():
    handle = parameter("parser", "Parser")
    retain = function("parser_ref", parameters=(handle,))
    release = function("parser_unref", parameters=(handle,))
    caller = function(
        "borrow", file="src/client.c",
        body="{ parser_ref(p); ParserParse(p); parser_unref(p); }",
        parameters=(handle,),
    )
    patterns = mine_usage_patterns((lifecycle_api()[1], retain, release, caller)).patterns
    pattern = next(item for item in patterns if item.lifecycle_kind == "reference_count")
    assert pattern.producer_binding == "existing_argument"
    assert pattern.producer_argument_index == 0
    assert pattern.sequence == ("parser_ref", "ParserParse", "parser_unref")


def test_pipeline_persists_usage_and_extractor_builds_one_ft_per_observed_mode(tmp_path):
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "tests").mkdir()
    (project / "examples").mkdir()
    (project / "src" / "api.h").write_text("""
typedef struct ParserStruct *Parser;
Parser ParserCreate(void);
Parser ParserCreateNS(const char *ns);
int ParserParse(Parser parser, const char *data, int size);
void ParserFree(Parser parser);
void ParserReset(Parser parser);
""")
    (project / "src" / "api.c").write_text("""
#include "api.h"
struct ParserStruct { int state; };
Parser ParserCreate(void) { return (Parser)0; }
Parser ParserCreateNS(const char *ns) { (void)ns; return (Parser)0; }
int ParserParse(Parser parser, const char *data, int size) {
  return parser && data ? size : -1;
}
void ParserFree(Parser parser) { (void)parser; }
void ParserReset(Parser parser) { (void)parser; }
""")
    (project / "tests" / "parse_test.c").write_text("""
#include "../src/api.h"
void test_parse(const char *data, int size) {
  Parser p = ParserCreate(); ParserParse(p, data, size);
  if (p) ParserFree(p);
}
""")
    (project / "examples" / "namespaced.c").write_text("""
#include "../src/api.h"
void example_parse(const char *data, int size) {
  Parser p = ParserCreateNS("x"); ParserParse(p, data, size);
  if (p) ParserFree(p);
}
""")
    (project / "tests" / "reset_test.c").write_text("""
#include "../src/api.h"
void test_reset_parse(const char *data, int size) {
  Parser p = ParserCreate(); ParserReset(p); ParserParse(p, data, size);
  if (p) ParserFree(p);
}
""")
    output = tmp_path / "artifacts"
    result = SFGPipeline(
        SemanticMergeAnalyzer(), ignored_directories=DEFAULT_IGNORES
    ).run(project, output)
    assert len(result.usage.patterns) == 3
    assert result.usage.semantic_reviews
    persisted = load_usage_json(output / "usage_patterns.json")
    assert {next(iter(item["support_by_source"])) for item in persisted} == {"test", "example"}
    create_reviews = [
        item["semantic_review"] for item in persisted
        if item["producer_function"] == "ParserCreate"
    ]
    assert len({item["semantic_group_id"] for item in create_reviews}) == 1
    assert {item["group_support_total"] for item in create_reviews} == {2}

    artifacts = load_sfg_artifacts(output)
    parse_id = next(
        item["id"] for item in artifacts.functions if item["name"] == "ParserParse"
    )
    triplets = [
        item for item in extract_function_triplets(artifacts)
        if item.isf.function_id == parse_id
    ]
    assert len(triplets) == 2
    assert len({item.id for item in triplets}) == 2
    assert {
        item.metadata["usage_pattern"]["producer_function"] for item in triplets
    } == {"ParserCreate", "ParserCreateNS"}
    create_ft = next(
        item for item in triplets
        if item.metadata["usage_pattern"]["producer_function"] == "ParserCreate"
    )
    assert create_ft.ownership_relations[0].observed_sequence == (
        "ParserCreate", "ParserParse", "ParserFree"
    )
    assert create_ft.ownership_relations[0].support_total == 2
    assert "ParserReset" not in {item.function for item in create_ft.functions}
