"""Evidence-backed, multi-dimensional harness quality signals.

The evaluators in this module deliberately keep *what was observed* separate
from *what it proves*.  Most static signals are conservative AST heuristics:
they are useful for comparing generated harnesses and producing repair
feedback, but never stand in for target-code coverage or a dynamic trace.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..runtime_validation import (GENERATED_HARNESS_CRASH, GENERATED_HARNESS_LEAK,
                                  POTENTIAL_TARGET_CRASH, UNCLASSIFIED_CRASH)
from .types import (Evidence, EvaluationContext, Measurement, MetricId,
                    MetricResult, MetricStatus)
from ..source_analysis import (_load_tree_sitter, _make_language,
                               _make_parser)
from ..target_coverage import latest_target_coverage_summary


QUALITY_SIGNAL_VERSION = "2"
_ENTRYPOINT = "LLVMFuzzerTestOneInput"
_IO_OR_PROCESS_CALLS = frozenset({
    "fopen", "freopen", "fdopen", "open", "read", "write", "fread",
    "fwrite", "printf", "fprintf", "puts", "fputs", "system", "popen",
    "execve", "execl", "execvp",
})
_CRASH_MASKING_CALLS = frozenset({
    "signal", "sigaction", "setjmp", "_setjmp", "sigsetjmp", "longjmp",
    "siglongjmp", "exit", "_Exit", "quick_exit", "abort",
})
_ALLOCATION_CALLS = frozenset({"malloc", "calloc", "realloc", "aligned_alloc"})
_LOOP_TYPES = frozenset({"for_statement", "while_statement", "do_statement"})
_GUARD_TYPES = frozenset({
    "if_statement", "switch_statement", "conditional_expression", *(_LOOP_TYPES),
})


@dataclass(frozen=True)
class QualitySignalConfig:
    """Versioned thresholds and candidate-local artifact names.

    ``execution_speed_reference`` is only a normalization ceiling for the
    process-wide executions/s observed in the same environment.  It is not a
    claim about isolated target-call latency.
    """

    harness_artifact: str = "harness.c"
    metrics_artifact: str = "metrics.json"
    target_coverage_artifact: str = "target_coverage.json"
    replay_artifact: str = "replay_quality.json"
    execution_speed_reference: float = 10_000.0
    deep_reachability_reference_depth: int = 3

    def __post_init__(self) -> None:
        for field in (
            "harness_artifact", "metrics_artifact", "target_coverage_artifact",
            "replay_artifact",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or not value or Path(value).is_absolute():
                raise ValueError(f"{field} must be a non-empty relative artifact path")
        if (
            isinstance(self.execution_speed_reference, bool)
            or not isinstance(self.execution_speed_reference, (int, float))
            or not math.isfinite(self.execution_speed_reference)
            or self.execution_speed_reference <= 0
        ):
            raise ValueError("execution_speed_reference must be a finite positive number")
        if (
            type(self.deep_reachability_reference_depth) is not int
            or self.deep_reachability_reference_depth < 1
        ):
            raise ValueError("deep_reachability_reference_depth must be positive")


@dataclass(frozen=True)
class _CallFact:
    name: str
    line: int
    argument_identifiers: frozenset[str]
    guarded: bool


@dataclass(frozen=True)
class HarnessStaticFacts:
    """Bounded AST observations from the libFuzzer entrypoint only."""

    entrypoint_found: bool
    data_parameters: frozenset[str]
    size_parameters: frozenset[str]
    calls: tuple[_CallFact, ...]
    target_calls: tuple[_CallFact, ...]
    taint_sources: Mapping[str, frozenset[str]]
    input_subscripts: int
    input_controls: int
    bounded_loops: int
    unbounded_input_loops: int
    input_dependent_allocations: int
    suspicious_calls: tuple[str, ...]
    crash_masking_calls: tuple[str, ...]


class _StaticEvaluator:
    metric_id: MetricId

    def __init__(self, config: QualitySignalConfig | None = None) -> None:
        self.config = config or QualitySignalConfig()

    def _facts(self, context: EvaluationContext) -> HarnessStaticFacts | MetricResult:
        path = context.artifact(self.config.harness_artifact)
        if not path.is_file():
            return MetricResult(
                self.metric_id, MetricStatus.UNAVAILABLE, type(self).__name__,
                QUALITY_SIGNAL_VERSION,
                f"No harness artifact is available at {self.config.harness_artifact!r}.",
            )
        try:
            return analyze_harness_ast(path.read_bytes(), context.target_function)
        except HarnessSignalError as error:
            return MetricResult(
                self.metric_id, MetricStatus.ERROR, type(self).__name__,
                QUALITY_SIGNAL_VERSION, str(error),
                evidence=(Evidence(self.config.harness_artifact,
                                   "Harness source that could not be analyzed"),),
            )


class StaticReachabilityEvaluator(_StaticEvaluator):
    """Estimate direct target-call reachability from the Harness AST."""

    metric_id = MetricId.REACHABILITY

    def evaluate(self, context: EvaluationContext) -> MetricResult:
        facts = self._facts(context)
        if isinstance(facts, MetricResult):
            return facts
        calls = facts.target_calls
        if not facts.entrypoint_found:
            score, reason = 0.0, "The libFuzzer entrypoint was not found in the Harness AST."
        elif not calls:
            score, reason = 0.0, "No direct target call was found inside the libFuzzer entrypoint."
        elif any(not call.guarded for call in calls):
            score, reason = 1.0, "At least one direct target call is structurally unconditional."
        else:
            score, reason = 0.65, "All direct target calls are nested below input-dependent or loop guards."
        measurements = (
            Measurement("direct_target_calls", len(calls), "calls", "harness_static"),
            Measurement("guarded_target_calls", sum(call.guarded for call in calls),
                        "calls", "harness_static"),
        )
        return MetricResult(
            self.metric_id, MetricStatus.MEASURED, type(self).__name__,
            QUALITY_SIGNAL_VERSION,
            "Static AST potential only; it does not count dynamic target entries. " + reason,
            score=score, measurements=measurements,
            evidence=(Evidence(self.config.harness_artifact,
                               "Direct target-call and guard analysis"),),
        )


class InputExpressivenessEvaluator(_StaticEvaluator):
    """Measure whether fuzz bytes reach multiple target-call arguments."""

    metric_id = MetricId.INPUT_EXPRESSIVENESS

    def evaluate(self, context: EvaluationContext) -> MetricResult:
        facts = self._facts(context)
        if isinstance(facts, MetricResult):
            return facts
        target_sources = _target_argument_sources(facts)
        data_reaches = "data" in target_sources
        size_reaches = "size" in target_sources
        transformed = sum(
            1 for sources in facts.taint_sources.values()
            if sources and set(sources) != {"data"} and set(sources) != {"size"}
        )
        score = 0.0
        if facts.target_calls:
            score += 0.10
        if data_reaches:
            score += 0.35
        if size_reaches:
            score += 0.20
        if facts.input_subscripts or transformed:
            score += 0.20
        if facts.input_controls:
            score += 0.15
        score = round(min(score, 1.0), 6)
        reason = (
            "Static input-dependence heuristic: target arguments receive "
            f"{', '.join(sorted(target_sources)) or 'no traced fuzz-input source'}; "
            f"observed {facts.input_subscripts} input subscript(s), "
            f"{facts.input_controls} input control site(s), and {transformed} "
            "multi-source derived value(s)."
        )
        return MetricResult(
            self.metric_id, MetricStatus.MEASURED, type(self).__name__,
            QUALITY_SIGNAL_VERSION, reason, score=score,
            measurements=(
                Measurement("target_argument_input_sources", len(target_sources),
                            "sources", "harness_static"),
                Measurement("input_subscripts", facts.input_subscripts, "expressions",
                            "harness_static"),
                Measurement("input_control_sites", facts.input_controls, "sites",
                            "harness_static"),
                Measurement("derived_input_values", len(facts.taint_sources), "variables",
                            "harness_static"),
            ),
            evidence=(Evidence(self.config.harness_artifact,
                               "AST input-to-target argument dependence analysis"),),
        )


class TargetIsolationEvaluator(_StaticEvaluator):
    """Check for a direct core target call and avoid obvious CLI/I/O detours."""

    metric_id = MetricId.TARGET_ISOLATION

    def evaluate(self, context: EvaluationContext) -> MetricResult:
        facts = self._facts(context)
        if isinstance(facts, MetricResult):
            return facts
        if not facts.target_calls:
            score = 0.0
            reason = "No direct target call appears in the libFuzzer entrypoint."
        else:
            penalty = min(0.60, 0.20 * len(facts.suspicious_calls))
            score = max(0.0, 1.0 - penalty)
            if facts.suspicious_calls:
                reason = (
                    "A direct target call exists, but the Harness also calls potential "
                    "I/O/process APIs: " + ", ".join(facts.suspicious_calls) + "."
                )
            else:
                reason = "A direct target call exists and no obvious I/O/process detour was found."
        return MetricResult(
            self.metric_id, MetricStatus.MEASURED, type(self).__name__,
            QUALITY_SIGNAL_VERSION, reason, score=score,
            measurements=(
                Measurement("direct_target_calls", len(facts.target_calls), "calls",
                            "harness_static"),
                Measurement("io_or_process_calls", len(facts.suspicious_calls), "calls",
                            "harness_static"),
            ),
            evidence=(Evidence(self.config.harness_artifact,
                               "Direct target-call and I/O/process-call analysis"),),
        )


class ResourceBoundEvaluator(_StaticEvaluator):
    """Flag input-dependent loops and allocations lacking obvious static bounds."""

    metric_id = MetricId.RESOURCE_BOUND

    def evaluate(self, context: EvaluationContext) -> MetricResult:
        facts = self._facts(context)
        if isinstance(facts, MetricResult):
            return facts
        penalty = 0.55 * facts.unbounded_input_loops
        if facts.input_dependent_allocations:
            penalty += 0.20 * facts.input_dependent_allocations
        score = max(0.0, 1.0 - min(penalty, 1.0))
        reason = (
            "Static bound heuristic found "
            f"{facts.bounded_loops} syntactically bounded loop(s), "
            f"{facts.unbounded_input_loops} input-dependent loop(s) without a numeric cap, "
            f"and {facts.input_dependent_allocations} input-dependent allocation(s). "
            "It cannot prove resource bounds for all executions."
        )
        return MetricResult(
            self.metric_id, MetricStatus.MEASURED, type(self).__name__,
            QUALITY_SIGNAL_VERSION, reason, score=score,
            measurements=(
                Measurement("bounded_loops", facts.bounded_loops, "loops", "harness_static"),
                Measurement("unbounded_input_loops", facts.unbounded_input_loops,
                            "loops", "harness_static"),
                Measurement("input_dependent_allocations", facts.input_dependent_allocations,
                            "calls", "harness_static"),
            ),
            evidence=(Evidence(self.config.harness_artifact,
                               "Loop and allocation bound analysis"),),
        )


class CrashFidelityEvaluator(_StaticEvaluator):
    """Detect Harness-side masking and attribute observed crash signals."""

    metric_id = MetricId.CRASH_FIDELITY

    def evaluate(self, context: EvaluationContext) -> MetricResult:
        dynamic = _fuzz_crash_classification(context)
        if dynamic is not None:
            return dynamic
        facts = self._facts(context)
        if isinstance(facts, MetricResult):
            return facts
        score = 1.0 if not facts.crash_masking_calls else 0.30
        reason = (
            "No obvious signal/termination masking call was found in the Harness AST."
            if not facts.crash_masking_calls else
            "Potential crash-signal masking calls were found: "
            + ", ".join(facts.crash_masking_calls) + "."
        )
        return MetricResult(
            self.metric_id, MetricStatus.MEASURED, type(self).__name__,
            QUALITY_SIGNAL_VERSION,
            reason + " Static absence is not proof that sanitizer findings are preserved.",
            score=score,
            measurements=(Measurement("crash_masking_calls", len(facts.crash_masking_calls),
                                      "calls", "harness_static"),),
            evidence=(Evidence(self.config.harness_artifact,
                               "Signal and termination call analysis"),),
        )


class ExecutionSpeedEvaluator:
    """Normalize observed process-wide libFuzzer executions/second when present."""

    metric_id = MetricId.EXECUTION_SPEED

    def __init__(self, config: QualitySignalConfig | None = None) -> None:
        self.config = config or QualitySignalConfig()

    def evaluate(self, context: EvaluationContext) -> MetricResult:
        path = context.artifact(self.config.metrics_artifact)
        if not path.is_file():
            return MetricResult(
                self.metric_id, MetricStatus.UNAVAILABLE, type(self).__name__,
                QUALITY_SIGNAL_VERSION,
                "No metrics artifact is available; short fuzz execution speed was not measured.",
            )
        try:
            document = _read_json_object(path)
        except ValueError as error:
            return MetricResult(
                self.metric_id, MetricStatus.ERROR, type(self).__name__,
                QUALITY_SIGNAL_VERSION, str(error),
                evidence=(Evidence(self.config.metrics_artifact,
                                   "Invalid metrics artifact"),),
            )
        measurements = _measurement_values(document)
        rate = measurements.get("fuzzer_average_exec_per_sec")
        executed = measurements.get("fuzzer_number_of_executed_units")
        if rate is None:
            return MetricResult(
                self.metric_id, MetricStatus.UNAVAILABLE, type(self).__name__,
                QUALITY_SIGNAL_VERSION,
                "No measured libFuzzer executions/second is available in metrics.json.",
                evidence=(Evidence(self.config.metrics_artifact,
                                   "Collected runtime measurements"),),
            )
        if rate < 0 or (executed is not None and executed < 0):
            return MetricResult(
                self.metric_id, MetricStatus.ERROR, type(self).__name__,
                QUALITY_SIGNAL_VERSION, "Execution-speed measurements cannot be negative.",
                evidence=(Evidence(self.config.metrics_artifact,
                                   "Invalid runtime measurement"),),
            )
        score = min(1.0, float(rate) / float(self.config.execution_speed_reference))
        values = [Measurement("executions_per_second", rate, "executions/second",
                              "instrumented_program")]
        if executed is not None:
            values.append(Measurement("executed_units", executed, "executions",
                                      "instrumented_program"))
        for name, unit in (
            ("fuzzer_coverage_edges_or_blocks", "edges_or_blocks"),
            ("fuzzer_features", "features"),
            ("fuzzer_new_units_added", "corpus_units"),
        ):
            value = measurements.get(name)
            if value is not None:
                values.append(Measurement(name, value, unit, "instrumented_program"))
        return MetricResult(
            self.metric_id, MetricStatus.MEASURED, type(self).__name__,
            QUALITY_SIGNAL_VERSION,
            "Measured process-wide libFuzzer speed; compare only candidates with the same "
            f"budget and environment (normalization reference: {self.config.execution_speed_reference:g} exec/s).",
            score=score, measurements=tuple(values),
            evidence=(Evidence(self.config.metrics_artifact,
                               "Short fuzz execution statistics", "/measurements"),),
        )


class DeepReachabilityEvaluator:
    """Use target-only coverage plus a target call graph for an observed depth signal."""

    metric_id = MetricId.DEEP_REACHABILITY

    def __init__(self, config: QualitySignalConfig | None = None) -> None:
        self.config = config or QualitySignalConfig()

    def evaluate(self, context: EvaluationContext) -> MetricResult:
        coverage_path = latest_target_coverage_summary(
            context.artifact(self.config.target_coverage_artifact),
            recipe_identity=context.execution_result.get("recipe_identity"),
        )
        if coverage_path is None:
            proxy = _engine_deep_reachability_proxy(context, self.config.metrics_artifact)
            if proxy is not None:
                return proxy
            return MetricResult(
                self.metric_id, MetricStatus.UNAVAILABLE, type(self).__name__,
                QUALITY_SIGNAL_VERSION,
                "No target-only coverage artifact or libFuzzer discovery telemetry "
                "is available for call-depth analysis.",
            )
        try:
            coverage = _read_json_object(coverage_path)
        except ValueError as error:
            return MetricResult(
                self.metric_id, MetricStatus.ERROR, type(self).__name__,
                QUALITY_SIGNAL_VERSION, str(error),
                evidence=(Evidence(_relative(context.directory, coverage_path),
                                   "Invalid target-only coverage artifact"),),
            )
        if coverage.get("status") != "passed":
            return MetricResult(
                self.metric_id, MetricStatus.UNAVAILABLE, type(self).__name__,
                QUALITY_SIGNAL_VERSION,
                "Target-only coverage did not complete successfully.",
                evidence=(Evidence(_relative(context.directory, coverage_path),
                                   "Target-only coverage artifact"),),
            )
        entered = _entered_functions(coverage)
        target_path = context.artifact("target.c")
        if not target_path.is_file():
            return MetricResult(
                self.metric_id, MetricStatus.UNAVAILABLE, type(self).__name__,
                QUALITY_SIGNAL_VERSION,
                "The candidate-local target.c artifact is unavailable for call-depth analysis.",
                evidence=(Evidence(_relative(context.directory, coverage_path),
                                   "Target-only coverage artifact"),),
            )
        try:
            graph = target_call_graph(target_path.read_bytes())
        except HarnessSignalError as error:
            return MetricResult(
                self.metric_id, MetricStatus.ERROR, type(self).__name__,
                QUALITY_SIGNAL_VERSION, str(error),
                evidence=(Evidence("target.c", "Target source call-graph input"),),
            )
        depths = _call_depths(graph, context.target_function)
        observed_depths = [depths[name] for name in entered if name in depths]
        if not observed_depths:
            return MetricResult(
                self.metric_id, MetricStatus.UNAVAILABLE, type(self).__name__,
                QUALITY_SIGNAL_VERSION,
                "Target-only coverage contains no entered function reachable in the parsed target call graph.",
                evidence=(Evidence(_relative(context.directory, coverage_path),
                                   "Entered target functions", "/target_only/entered_functions"),),
            )
        depth = max(observed_depths)
        score = min(1.0, depth / self.config.deep_reachability_reference_depth)
        return MetricResult(
            self.metric_id, MetricStatus.MEASURED, type(self).__name__,
            QUALITY_SIGNAL_VERSION,
            "Observed target-only coverage reaches parsed call-graph depth "
            f"{depth} from {context.target_function!r}; this is a call-depth signal, "
            "not a security-sensitivity claim.",
            score=score,
            measurements=(
                Measurement("maximum_entered_call_depth", depth, "edges", "target_code"),
                Measurement("entered_target_functions", len(entered), "functions", "target_code"),
            ),
            evidence=(
                Evidence(_relative(context.directory, coverage_path),
                         "Target-only entered functions", "/target_only/entered_functions"),
                Evidence("target.c", "Parsed target call graph"),
            ),
        )


class ReplayQualityEvaluator:
    """Read an explicit replay probe artifact for determinism or state reset.

    The candidate runner does not fabricate this artifact from fresh-process
    Smoke results.  A future in-process probe can write it without changing
    the evaluator or feedback schema.
    """

    def __init__(self, metric_id: MetricId, key: str,
                 config: QualitySignalConfig | None = None) -> None:
        if metric_id not in {MetricId.DETERMINISM, MetricId.STATE_RESET}:
            raise ValueError("ReplayQualityEvaluator supports determinism or state_reset only")
        self.metric_id = metric_id
        self.key = key
        self.config = config or QualitySignalConfig()

    def evaluate(self, context: EvaluationContext) -> MetricResult:
        path = context.artifact(self.config.replay_artifact)
        if not path.is_file():
            return MetricResult(
                self.metric_id, MetricStatus.UNAVAILABLE, type(self).__name__,
                QUALITY_SIGNAL_VERSION,
                f"No {self.key} replay probe artifact is available; fresh-process Smoke is insufficient.",
            )
        try:
            document = _read_json_object(path)
            entry = document.get(self.key)
            if not isinstance(entry, Mapping):
                raise ValueError(f"Replay artifact lacks a {self.key!r} object")
            attempted = _nonnegative_number(entry.get("attempted_cases"), "attempted_cases")
            matching = _nonnegative_number(entry.get("matching_cases"), "matching_cases")
            if attempted == 0 or matching > attempted:
                raise ValueError(f"Replay artifact has invalid {self.key} counts")
        except ValueError as error:
            return MetricResult(
                self.metric_id, MetricStatus.ERROR, type(self).__name__,
                QUALITY_SIGNAL_VERSION, str(error),
                evidence=(Evidence(self.config.replay_artifact,
                                   "Invalid replay quality artifact"),),
            )
        score = matching / attempted
        return MetricResult(
            self.metric_id, MetricStatus.MEASURED, type(self).__name__,
            QUALITY_SIGNAL_VERSION,
            f"Replay probe observed {matching:g}/{attempted:g} matching {self.key} case(s).",
            score=score,
            measurements=(
                Measurement("attempted_cases", attempted, "cases", "in_process_replay"),
                Measurement("matching_cases", matching, "cases", "in_process_replay"),
            ),
            evidence=(Evidence(self.config.replay_artifact,
                               f"In-process {self.key} replay result", f"/{self.key}"),),
        )


def default_quality_evaluators(
    config: QualitySignalConfig | None = None,
) -> tuple[object, ...]:
    """Return the default multi-dimensional signal set in registry order."""

    from .coverage import TargetCoverageEvaluator

    config = config or QualitySignalConfig()
    return (
        StaticReachabilityEvaluator(config),
        TargetCoverageEvaluator(config.target_coverage_artifact),
        ExecutionSpeedEvaluator(config),
        ReplayQualityEvaluator(MetricId.DETERMINISM, "determinism", config),
        ReplayQualityEvaluator(MetricId.STATE_RESET, "state_reset", config),
        InputExpressivenessEvaluator(config),
        DeepReachabilityEvaluator(config),
        CrashFidelityEvaluator(config),
        ResourceBoundEvaluator(config),
        TargetIsolationEvaluator(config),
    )


class HarnessSignalError(ValueError):
    """Raised only for malformed/missing syntax evidence, never for low quality."""


def analyze_harness_ast(source: bytes, target_function: str) -> HarnessStaticFacts:
    """Parse one Harness with tree-sitter and derive conservative data-flow facts."""

    if not isinstance(target_function, str) or not target_function:
        raise HarnessSignalError("A non-empty target function name is required for signal analysis")
    root = _parse_c(source, "Harness")
    entrypoint = next(
        (node for node in _walk(root)
         if node.type == "function_definition" and _function_name(node, source) == _ENTRYPOINT),
        None,
    )
    if entrypoint is None:
        return HarnessStaticFacts(False, frozenset(), frozenset(), (), (), {}, 0, 0, 0, 0, 0, (), ())
    declarator = entrypoint.child_by_field_name("declarator")
    body = entrypoint.child_by_field_name("body")
    if declarator is None or body is None:
        raise HarnessSignalError("libFuzzer entrypoint has no declarator or compound body")
    data_parameters, size_parameters = _entrypoint_parameters(declarator, source)
    calls: list[_CallFact] = []
    flows: list[tuple[str, frozenset[str]]] = []
    input_subscripts = 0
    input_controls = 0
    bounded_loops = 0
    unbounded_input_loops = 0

    raw_input_names = data_parameters | size_parameters
    for node in _walk(body):
        if node.type == "call_expression":
            name = _call_name(node, source)
            if name:
                args = node.child_by_field_name("arguments")
                identifiers = _identifiers(args, source) if args is not None else frozenset()
                calls.append(_CallFact(
                    name, node.start_point[0] + 1, identifiers,
                    _has_ancestor_before(node, body, _GUARD_TYPES),
                ))
                if name in {"memcpy", "memmove"} and args is not None:
                    arguments = tuple(args.named_children)
                    if len(arguments) >= 2:
                        destinations = _identifiers(arguments[0], source)
                        sources = _identifiers(arguments[1], source)
                        for destination in destinations:
                            flows.append((destination, sources))
        elif node.type in {"init_declarator", "assignment_expression"}:
            left = node.child_by_field_name("declarator") or node.child_by_field_name("left")
            right = node.child_by_field_name("value") or node.child_by_field_name("right")
            if left is not None and right is not None:
                destinations = _identifiers(left, source)
                sources = _identifiers(right, source)
                for destination in destinations:
                    flows.append((destination, sources))
        elif node.type == "subscript_expression":
            if _identifiers(node, source) & raw_input_names:
                input_subscripts += 1
        elif node.type in {"if_statement", "switch_statement", *_LOOP_TYPES}:
            condition = node.child_by_field_name("condition")
            if condition is not None and _identifiers(condition, source) & raw_input_names:
                input_controls += 1
            if node.type in _LOOP_TYPES:
                condition_identifiers = _identifiers(condition, source) if condition is not None else frozenset()
                if condition_identifiers & raw_input_names:
                    if _has_numeric_literal(condition):
                        bounded_loops += 1
                    else:
                        unbounded_input_loops += 1

    source_map = _taint_sources(flows, data_parameters, size_parameters)
    target_calls = tuple(call for call in calls if call.name == target_function)
    input_dependent_allocations = sum(
        1 for call in calls
        if call.name in _ALLOCATION_CALLS and _sources_for_identifiers(call.argument_identifiers, source_map)
    )
    call_names = [call.name for call in calls]
    suspicious_calls = tuple(sorted(set(call_names) & _IO_OR_PROCESS_CALLS))
    crash_masking_calls = tuple(sorted(set(call_names) & _CRASH_MASKING_CALLS))
    return HarnessStaticFacts(
        True, data_parameters, size_parameters, tuple(calls), target_calls, source_map,
        input_subscripts, input_controls, bounded_loops, unbounded_input_loops,
        input_dependent_allocations, suspicious_calls, crash_masking_calls,
    )


def target_call_graph(source: bytes) -> dict[str, frozenset[str]]:
    """Extract a definition-local C call graph using tree-sitter."""

    root = _parse_c(source, "target source")
    graph: dict[str, frozenset[str]] = {}
    for node in _walk(root):
        if node.type != "function_definition":
            continue
        name = _function_name(node, source)
        body = node.child_by_field_name("body")
        if not name or body is None:
            continue
        called = frozenset(
            called_name for child in _walk(body)
            if child.type == "call_expression"
            and (called_name := _call_name(child, source)) is not None
        )
        graph[name] = called
    return graph


def _parse_c(source: bytes, label: str):
    try:
        tree_sitter, tree_sitter_c = _load_tree_sitter()
        language = _make_language(tree_sitter.Language, tree_sitter_c)
        parser = _make_parser(tree_sitter.Parser, language)
        root = parser.parse(source).root_node
    except Exception as error:  # dependency failures need become metric evidence
        raise HarnessSignalError(f"{label} tree-sitter setup failed: {type(error).__name__}") from None
    errors = sum(1 for node in _walk(root) if node.type == "ERROR" or getattr(node, "is_error", False))
    if root.has_error or errors:
        raise HarnessSignalError(f"{label} tree-sitter parse failed with {errors or 1} error node(s)")
    return root


def _entrypoint_parameters(declarator, source: bytes) -> tuple[frozenset[str], frozenset[str]]:
    parameters = declarator.child_by_field_name("parameters")
    data: set[str] = set()
    size: set[str] = set()
    if parameters is None:
        return frozenset(), frozenset()
    for parameter in parameters.named_children:
        if parameter.type != "parameter_declaration":
            continue
        name = _declarator_identifier(parameter.child_by_field_name("declarator"), source)
        if not name:
            continue
        value = _text(source, parameter).lower()
        if "uint8_t" in value or "unsigned char" in value or "char" in value:
            data.add(name)
        elif "size_t" in value or "unsigned long" in value or "uint32_t" in value:
            size.add(name)
    return frozenset(data), frozenset(size)


def _function_name(node, source: bytes) -> str | None:
    return _declarator_identifier(node.child_by_field_name("declarator"), source)


def _declarator_identifier(node, source: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return _text(source, node)
    field = node.child_by_field_name("declarator")
    if field is not None:
        name = _declarator_identifier(field, source)
        if name:
            return name
    for child in node.named_children:
        name = _declarator_identifier(child, source)
        if name:
            return name
    return None


def _call_name(node, source: bytes) -> str | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "identifier":
        return None
    return _text(source, function)


def _identifiers(node, source: bytes) -> frozenset[str]:
    if node is None:
        return frozenset()
    return frozenset(
        _text(source, child) for child in _walk(node) if child.type == "identifier"
    )


def _walk(node) -> Iterable[Any]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _text(source: bytes, node) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _has_ancestor_before(node, stop, kinds: Iterable[str]) -> bool:
    kinds = set(kinds)
    current = node.parent
    while current is not None and current != stop:
        if current.type in kinds:
            return True
        current = current.parent
    return False


def _has_numeric_literal(node) -> bool:
    if node is None:
        return False
    return any(child.type in {"number_literal", "char_literal"} for child in _walk(node))


def _taint_sources(
    flows: Iterable[tuple[str, frozenset[str]]],
    data_parameters: frozenset[str],
    size_parameters: frozenset[str],
) -> dict[str, frozenset[str]]:
    sources: dict[str, set[str]] = {
        **{name: {"data"} for name in data_parameters},
        **{name: {"size"} for name in size_parameters},
    }
    pairs = tuple(flows)
    for _ in range(max(1, len(pairs) + 1)):
        changed = False
        for destination, inputs in pairs:
            observed: set[str] = set()
            for value in inputs:
                observed.update(sources.get(value, ()))
            if observed and not observed.issubset(sources.get(destination, set())):
                sources.setdefault(destination, set()).update(observed)
                changed = True
        if not changed:
            break
    return {
        name: frozenset(value) for name, value in sorted(sources.items()) if value
    }


def _sources_for_identifiers(identifiers: Iterable[str],
                             source_map: Mapping[str, frozenset[str]]) -> frozenset[str]:
    result: set[str] = set()
    for identifier in identifiers:
        result.update(source_map.get(identifier, ()))
    return frozenset(result)


def _target_argument_sources(facts: HarnessStaticFacts) -> frozenset[str]:
    result: set[str] = set()
    for call in facts.target_calls:
        result.update(_sources_for_identifiers(call.argument_identifiers, facts.taint_sources))
    return frozenset(result)


def _read_json_object(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read JSON artifact {path.name}: {type(error).__name__}") from None
    if not isinstance(value, Mapping):
        raise ValueError(f"JSON artifact {path.name} must be an object")
    return value


def _measurement_values(document: Mapping[str, Any]) -> dict[str, float]:
    values: dict[str, float] = {}
    raw = document.get("measurements")
    if not isinstance(raw, list):
        return values
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        name = entry.get("name")
        value = entry.get("value")
        if (
            isinstance(name, str)
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        ):
            values[name] = float(value)
    return values


def _fuzz_crash_classification(context: EvaluationContext) -> MetricResult | None:
    fuzzing = context.execution_result.get("fuzzing")
    smoke = context.execution_result.get("smoke")
    stage = "fuzzing" if isinstance(fuzzing, Mapping) and fuzzing.get("status") == "finding" else "smoke"
    finding = fuzzing if stage == "fuzzing" else smoke
    if not isinstance(finding, Mapping) or finding.get("status") != "finding":
        return None
    raw = finding.get("crash_classification")
    classification = (
        raw.get("classification")
        if isinstance(raw, Mapping) and isinstance(raw.get("classification"), str)
        else UNCLASSIFIED_CRASH
    )
    findings = finding.get("findings")
    artifacts = finding.get("artifacts")
    finding_count = len(findings) if isinstance(findings, list) else 0
    artifact_count = len(artifacts) if isinstance(artifacts, list) else 0
    measurements = (
        Measurement("crash_classification", classification, "category",
                    "sanitizer_diagnostics"),
        Measurement("sanitizer_findings", finding_count, "findings",
                    "sanitizer_diagnostics"),
        Measurement("crash_artifacts", artifact_count, "artifacts",
                    "sanitizer_diagnostics"),
    )
    if classification == POTENTIAL_TARGET_CRASH:
        score = 1.0
        reason = (
            "A sanitizer/libFuzzer finding was attributed to target source. "
            "This rewards preserving the target crash signal; it is not an "
            "exploitability classification."
        )
    elif classification == GENERATED_HARNESS_LEAK:
        score = 0.0
        reason = (
            "The generated Harness acquired a target resource and never "
            "released it, so the leak reports on the Harness rather than "
            "on the target."
        )
    elif classification == GENERATED_HARNESS_CRASH:
        score = 0.0
        reason = "A sanitizer/libFuzzer finding was attributed to generated Harness code."
    else:
        score = 0.0
        reason = (
            "A sanitizer/libFuzzer finding could not be attributed to target "
            "source, so it is not accepted as target crash fidelity."
        )
    return MetricResult(
        MetricId.CRASH_FIDELITY,
        MetricStatus.MEASURED,
        "CrashFidelityEvaluator",
        QUALITY_SIGNAL_VERSION,
        reason,
        score=score,
        measurements=measurements,
        evidence=(
            Evidence(
                "fuzz_result.json" if stage == "fuzzing" else "smoke_result.json",
                "libFuzzer finding classification",
            ),
            Evidence(
                "fuzz_stderr.txt" if stage == "fuzzing" else "smoke_result.json",
                "sanitizer/libFuzzer stderr",
            ),
        ),
    )


def _engine_deep_reachability_proxy(
    context: EvaluationContext,
    artifact: str,
) -> MetricResult | None:
    path = context.artifact(artifact)
    if not path.is_file():
        return None
    try:
        document = _read_json_object(path)
    except ValueError:
        return None
    measurements = _measurement_values(document)
    new_units = measurements.get("fuzzer_new_units_added")
    coverage = measurements.get("fuzzer_coverage_edges_or_blocks")
    features = measurements.get("fuzzer_features")
    if new_units is None and coverage is None and features is None:
        return None
    signal = max(
        0.0,
        float(new_units or 0.0),
        float(coverage or 0.0) / 4.0,
        float(features or 0.0) / 6.0,
    )
    score = min(1.0, math.log1p(signal) / math.log1p(32.0))
    values = []
    if new_units is not None:
        values.append(Measurement("engine_new_units_added", new_units,
                                  "corpus_units", "instrumented_program"))
    if coverage is not None:
        values.append(Measurement("engine_coverage_edges_or_blocks", coverage,
                                  "edges_or_blocks", "instrumented_program"))
    if features is not None:
        values.append(Measurement("engine_features", features, "features",
                                  "instrumented_program"))
    return MetricResult(
        MetricId.DEEP_REACHABILITY,
        MetricStatus.MEASURED,
        "DeepReachabilityEvaluator",
        QUALITY_SIGNAL_VERSION,
        "No target-only call-depth artifact is available; using libFuzzer "
        "corpus-discovery telemetry as a bounded deep-reachability proxy. "
        "This is not a security-sensitivity claim.",
        score=round(score, 6),
        measurements=tuple(values),
        evidence=(Evidence(artifact, "Collected libFuzzer discovery telemetry"),),
    )


def _entered_functions(document: Mapping[str, Any]) -> frozenset[str]:
    target_only = document.get("target_only")
    raw = target_only.get("entered_functions") if isinstance(target_only, Mapping) else None
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(value for value in raw if isinstance(value, str) and value)


def _call_depths(graph: Mapping[str, frozenset[str]], root: str) -> dict[str, int]:
    if root not in graph:
        return {}
    depths = {root: 0}
    queue = [root]
    while queue:
        current = queue.pop(0)
        for child in sorted(graph.get(current, ())):
            if child not in graph or child in depths:
                continue
            depths[child] = depths[current] + 1
            queue.append(child)
    return depths


def _nonnegative_number(value: object, name: str) -> float:
    if (
        isinstance(value, bool) or not isinstance(value, (int, float))
        or not math.isfinite(float(value)) or value < 0
    ):
        raise ValueError(f"Replay artifact field {name!r} must be a finite non-negative number")
    return float(value)


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)
