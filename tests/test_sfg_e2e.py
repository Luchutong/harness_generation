import json
from dataclasses import replace
from pathlib import Path
import pytest

from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer
from sfg_builder.client import BudgetedSemanticTransport, LLMSemanticAnalyzer
from sfg_builder.base import SemanticBudgetExceeded
from sfg_builder.base import SemanticReplayMismatch
from sfg_builder.replay import ReplayedSemanticAnalyzer
from sfg_builder.voting import vote_stream_parameter


PROJECT = Path(__file__).parent / "fixtures" / "simple_project"
EXPECTED_ARTIFACTS = {
    "functions.json",
    "candidates.json",
    "annotations.json",
    "flows.json",
    "sfg.json",
    "sfg.dot",
    "ownership.json",
    "usage_patterns.json",
}


def test_minimal_fixture_builds_expected_annotations_and_sfg(tmp_path):
    output = tmp_path / "artifacts" / "sfg"
    result = SFGPipeline(
        MockSemanticAnalyzer(), ignored_directories=DEFAULT_IGNORES
    ).run(PROJECT, output)

    labels = {
        annotation.function: list(annotation.labels)
        for annotation in result.annotations
    }
    assert labels == {
        "parser_from_memory": ["ISF", "HPF"],
        "parser_next": ["PRF"],
        "node_process": ["PRF"],
        "parser_free": ["HPF"],
    }

    edges = {
        (edge.source, edge.function, edge.target)
        for edge in result.graph.edges
    }
    assert {
        ("(null)", "parser_from_memory", "Parser"),
        ("Parser", "parser_next", "Node"),
        ("Node", "node_process", "(null)"),
        ("Parser", "parser_free", "(null)"),
    } <= edges

    assert {path.name for path in output.iterdir()} == EXPECTED_ARTIFACTS
    serialized = json.loads((output / "sfg.json").read_text(encoding="utf-8"))
    serialized_edges = {
        (edge["source"], edge["function"], edge["target"])
        for edge in serialized["edges"]
    }
    assert edges == serialized_edges


def test_phase1_ignores_prototypes_and_mock_rejects_textual_names(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "api.h").write_text(
        "typedef unsigned char xmlChar;\n"
        "int htmlTagLookup(const xmlChar *tag);\n"
        "int parseBytes(const xmlChar *data, int size);\n"
    )
    (project / "api.c").write_text(
        '#include "api.h"\n'
        "int htmlTagLookup(const xmlChar *tag) { return tag[0]; }\n"
        "int parseBytes(const xmlChar *data, int size) { return size && data[0]; }\n"
    )
    result = SFGPipeline(MockSemanticAnalyzer(), ignored_directories=()).run(
        project, tmp_path / "out"
    )
    assert {item.function for item in result.candidates} == {"htmlTagLookup", "parseBytes"}
    assert all(Path(item.file).suffix == ".c" for item in result.candidates)
    assert {item.function for item in result.annotations if "ISF" in item.labels} == {
        "parseBytes"
    }
    assert json.loads((tmp_path / "out" / "annotations.json").read_text())[
        "semantic_backend"
    ] == "mock"


def test_phase1_budget_stops_before_network_and_during_retries(tmp_path):
    requests = []
    def respond(payload):
        requests.append(payload)
        return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps({
            "is_byte_stream": True, "kind": "binary", "confidence": 0.9,
            "reason": "byte input",
        })}}]}

    transport = BudgetedSemanticTransport(respond, 1)
    analyzer = LLMSemanticAnalyzer(transport, "test")
    with pytest.raises(ValueError, match="needs at least"):
        SFGPipeline(
            analyzer, ignored_directories=(), max_semantic_requests=1
        ).run(PROJECT, tmp_path / "out")
    assert requests == []
    function = SFGPipeline(MockSemanticAnalyzer(), ignored_directories=()).parser.parse(
        PROJECT
    ).functions[0]
    with pytest.raises(SemanticBudgetExceeded):
        vote_stream_parameter(analyzer, function, function.parameters[1], ())
    assert len(requests) == 1


def test_paper_minimal_skips_usage_extension(tmp_path, monkeypatch):
    def unexpected_usage(_functions):
        raise AssertionError("usage mining is outside paper-minimal Phase 1")

    monkeypatch.setattr("sfg_builder.pipeline.mine_usage_patterns", unexpected_usage)
    output = tmp_path / "paper"
    result = SFGPipeline(
        MockSemanticAnalyzer(), ignored_directories=(), paper_minimal=True,
    ).run(PROJECT, output)
    assert result.usage.patterns == ()
    assert result.usage.semantic_reviews == ()
    assert json.loads((output / "usage_patterns.json").read_text())[
        "semantic_reviews"
    ] == []


def test_paper_minimal_skips_stream_only_functions_before_semantic_votes(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "api.c").write_text(
        "typedef struct Node { int value; } Node;\n"
        "int rawOnly(const unsigned char *data, int size) { return data[0] + size; }\n"
        "Node *parseNode(const unsigned char *data, int size) "
        "{ (void)data; (void)size; return 0; }\n"
    )
    result = SFGPipeline(
        MockSemanticAnalyzer(), ignored_directories=(), paper_minimal=True,
    ).run(project, tmp_path / "out")
    assert [candidate.function for candidate in result.candidates] == ["parseNode"]
    assert [item.function for item in result.annotations if "ISF" in item.labels] == [
        "parseNode"
    ]


def test_real_semantic_records_can_be_replayed_without_provider(tmp_path):
    original = tmp_path / "original"
    first = SFGPipeline(
        MockSemanticAnalyzer(), ignored_directories=(), paper_minimal=True,
    ).run(PROJECT, original)
    annotations_path = original / "annotations.json"
    document = json.loads(annotations_path.read_text())
    document["semantic_backend"] = "llm"  # Test fixture for recorded LLM decisions.
    annotations_path.write_text(json.dumps(document))

    replay = ReplayedSemanticAnalyzer(annotations_path)
    second = SFGPipeline(
        replay, ignored_directories=(), paper_minimal=True,
    ).run(PROJECT, tmp_path / "replayed")
    assert [item.labels for item in second.annotations] == [
        item.labels for item in first.annotations
    ]
    assert json.loads((tmp_path / "replayed" / "annotations.json").read_text())[
        "semantic_source"
    ] == "replayed"
    function = next(item for item in first.parsed.functions
                    if item.name == "parser_from_memory")
    with pytest.raises(SemanticReplayMismatch):
        replay.classify_stream_parameter(
            replace(function, body=function.body + " /* changed */"),
            function.parameters[1], first.parsed.structs, "direct",
        )
