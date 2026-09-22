import json
from pathlib import Path

from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer


PROJECT = Path(__file__).parent / "fixtures" / "simple_project"
EXPECTED_ARTIFACTS = {
    "functions.json",
    "candidates.json",
    "annotations.json",
    "flows.json",
    "sfg.json",
    "sfg.dot",
    "ownership.json",
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
