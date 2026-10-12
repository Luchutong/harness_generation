"""Recorded stack attribution is finite evidence, never a target-bug proof."""
from harness_generation.runtime_validation import (
    GENERATED_HARNESS_CRASH, POTENTIAL_TARGET_CRASH, UNCLASSIFIED_CRASH,
    classify_crash,
)


def classify(tmp_path, frames, *, leak=False):
    target, harness = tmp_path / "target", tmp_path / "output" / "harness.c"
    stderr = ("ERROR: LeakSanitizer: detected memory leaks\n" if leak else "") + frames(target, harness)
    return classify_crash(stderr, generated_sources=(harness,), target_root=target)


def test_target_fault_with_harness_caller_is_only_a_potential_target_crash(tmp_path):
    result = classify(tmp_path, lambda target, harness:
        f"#0 0x123 in parse {target}/parse.c:17:3\n#1 0x456 in LLVMFuzzerTestOneInput {harness}:24:2\n")
    assert result["classification"] == POTENTIAL_TARGET_CRASH
    assert result["attribution_frame"]["line"] == 17


def test_generated_fault_is_attributed_to_harness(tmp_path):
    result = classify(tmp_path, lambda target, harness: f"#0 0x123 in LLVMFuzzerTestOneInput {harness}:24:2\n")
    assert result["classification"] == GENERATED_HARNESS_CRASH


def test_unsymbolized_target_failure_remains_unclassified(tmp_path):
    result = classify(tmp_path, lambda target, harness: "Segmentation fault\n")
    assert result["classification"] == UNCLASSIFIED_CRASH
    assert result["stack_parser_status"] == "unavailable"


def test_target_allocation_stack_cannot_identify_missing_cleanup(tmp_path):
    result = classify(tmp_path, lambda target, harness:
        f"#0 0x123 in create {target}/create.c:17:3\n#1 0x456 in LLVMFuzzerTestOneInput {harness}:24:2\n", leak=True)
    assert result["classification"] == UNCLASSIFIED_CRASH
