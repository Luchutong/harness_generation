"""Validation policy joining persisted Stage artifacts to the orchestrator."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
from typing import Any, Iterable, Mapping, Sequence

from .artifacts import ArtifactStore, TripletArtifacts
from .compiler_validation import CompilerConfig, CompilerValidator
from .fuzzer_build import FuzzerBuildValidator
from .fuzz_smoke import (LibFuzzerSmokeConfig, LibFuzzerSmokeValidator,
                         Runner as FuzzRunner)
from .runtime_validation import RuntimeValidationResult, RuntimeValidator
from .source_paths import SourcePathResolver
from .stage1 import Stage1Result
from .stage2 import Stage2Result, required_processing_units
from .stage3 import Stage3Result
from .stage4 import Stage4Result
from .stage4_outcome import record_validation_exception, record_validation_result
from .target_build import TargetBuildConfig
from .triplet import FunctionTriplet, missing_structural_steps
from .validation import (
    DEFAULT_ALLOWED_FUNCTIONS,
    IntermediateValidator,
    ValidationResult,
    _syntax_facts,
)


@dataclass(frozen=True)
class PipelineValidationConfig:
    """Optional execution dependencies for the persisted Stage 4 artifact."""

    compiler: CompilerConfig | None = None
    target_build: TargetBuildConfig | None = None
    target_build_path: Path | None = None
    executable: Path | None = None
    runtime_arguments: tuple[str, ...] = ()
    runtime_timeout: float = 30.0
    build_enabled: bool = True
    fuzz_smoke: LibFuzzerSmokeConfig | None = LibFuzzerSmokeConfig()
    fuzz_runner: FuzzRunner = subprocess.run
    stage4_policy: str = "strict"

    def __post_init__(self) -> None:
        if type(self.build_enabled) is not bool:
            raise ValueError("build_enabled must be boolean")
        if self.stage4_policy not in {"strict", "hybrid"}:
            raise ValueError("stage4_policy must be strict or hybrid")
        if self.stage4_policy == "hybrid" and not self.build_enabled:
            raise ValueError("hybrid stage4_policy requires build validation")
        if self.target_build is not None and self.target_build_path is not None:
            raise ValueError("target_build and target_build_path are mutually exclusive")
        if self.target_build_path is not None:
            object.__setattr__(self, "target_build_path", Path(self.target_build_path))
        if not self.build_enabled and self.fuzz_smoke is not None:
            raise ValueError("fuzz smoke requires build validation")


class PipelineStageValidator:
    """Return one canonical ``ValidationResult`` for each generated Stage."""

    def __init__(
        self,
        triplet: FunctionTriplet,
        *,
        artifacts: str | Path,
        functions_json: str | Path,
        project_root: str | Path | None = None,
        config: PipelineValidationConfig | None = None,
    ) -> None:
        self.triplet = triplet
        self.artifacts = Path(artifacts)
        self.functions_json = Path(functions_json)
        self.layout = ArtifactStore(self.artifacts).for_triplet(triplet.id)
        self.config = config or PipelineValidationConfig()
        self.project_root = _resolve_project_root(
            self.functions_json, project_root
        )
        self.target_functions = _target_function_names(self.functions_json)
        self.target_build = self.config.target_build
        if self.target_build is None and self.config.target_build_path is not None:
            self.target_build = TargetBuildConfig.load(
                self.config.target_build_path,
                project_root=self.project_root,
            )
        if self.target_build is None and self.config.compiler is None:
            self.target_build = ArtifactStore(self.artifacts).load_target_build(
                project_root=self.project_root,
            )
        if self.target_build is None and self.config.compiler is None:
            self.target_build = _discover_target_build(self.project_root)

    def validate_stage1(self, result: Stage1Result) -> ValidationResult:
        errors: list[str] = []
        document = _json_object(result.output_path, errors, "Stage 1")
        expected = {
            function.function_id: function.function
            for function in self.triplet.functions
        }
        records = document.get("documents") if document else None
        if document and document.get("triplet_id") != self.triplet.id:
            errors.append("Stage 1 artifact belongs to a different triplet")
        if not isinstance(records, list):
            errors.append("Stage 1 documents must be an array")
            records = []
        observed: dict[str, str] = {}
        for record in records:
            if not isinstance(record, Mapping):
                errors.append("Stage 1 document must be an object")
                continue
            function_id = record.get("function_id")
            function = record.get("function")
            if not isinstance(function_id, str) or not isinstance(function, str):
                errors.append("Stage 1 document requires function_id and function")
                continue
            if function_id in observed:
                errors.append(f"duplicate Stage 1 documentation: {function_id}")
            observed[function_id] = function
            for field in (
                "signature", "functionality", "application_scenario", "example_code"
            ):
                value = record.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"empty Stage 1 {field}: {function}")
        if observed != expected:
            errors.append("Stage 1 function documentation does not match the FT")
        return _result("stage1", errors, metadata={
            "artifact": str(result.output_path),
            "expected_functions": sorted(expected.values()),
            "observed_functions": sorted(observed.values()),
        })

    def validate_stage2(self, result: Stage2Result) -> ValidationResult:
        errors: list[str] = []
        document = _json_object(result.output_path, errors, "Stage 2")
        records = document.get("units") if document else None
        if document and document.get("triplet_id") != self.triplet.id:
            errors.append("Stage 2 artifact belongs to a different triplet")
        if not isinstance(records, list) or not records:
            errors.append("Stage 2 requires a non-empty units array")
            records = []

        expected = {function.function for function in self.triplet.functions}
        required_units = {
            unit["id"]: {
                "functions": set(unit["functions"]),
                "input_structure": unit["input_structure"],
                "output_structure": unit["output_structure"],
            }
            for unit in required_processing_units(self.triplet)
        }
        covered: set[str] = set()
        observed_ids: set[str] = set()
        for record in records:
            if not isinstance(record, Mapping):
                errors.append("Stage 2 unit must be an object")
                continue
            unit_id = record.get("id")
            functions = record.get("functions")
            code = record.get("generated_code")
            if not isinstance(unit_id, str) or not unit_id:
                errors.append("Stage 2 unit id must be non-empty")
                continue
            if unit_id in observed_ids:
                errors.append(f"duplicate Stage 2 unit: {unit_id}")
            observed_ids.add(unit_id)
            if not isinstance(functions, list) or any(
                not isinstance(function, str) for function in functions
            ):
                errors.append(f"Stage 2 unit functions are invalid: {unit_id}")
                continue
            if not isinstance(code, str) or not code.strip():
                errors.append(f"Stage 2 snippet is empty: {unit_id}")
                continue
            declared = set(functions)
            covered.update(declared)
            required = required_units.get(unit_id)
            if required is None:
                errors.append(f"unexpected Stage 2 processing unit: {unit_id}")
            else:
                if declared != required["functions"]:
                    errors.append(
                        f"Stage 2 unit functions do not match {unit_id}"
                    )
                for field in ("input_structure", "output_structure"):
                    if record.get(field) != required[field]:
                        errors.append(
                            f"Stage 2 unit {field} does not match {unit_id}"
                        )
            try:
                facts = _syntax_facts(
                    "void __stage2_snippet(void) {\n" + code + "\n}\n"
                )
            except ImportError:
                return _unavailable(
                    "stage2", "tree-sitter C dependencies are unavailable"
                )
            if facts.syntax_error_count:
                errors.append(f"Stage 2 snippet is not valid C syntax: {unit_id}")
                continue
            calls = set(facts.calls)
            # A unit is one structural step, so its declared functions are
            # alternatives for that step: calling any one of them realizes it.
            missing = missing_structural_steps(declared, (declared,), calls)
            invented = sorted(
                calls - self.target_functions - DEFAULT_ALLOWED_FUNCTIONS
            )
            if missing:
                errors.append(
                    f"Stage 2 snippet calls no declared function in {unit_id}: "
                    + ", ".join(missing)
                )
            if invented:
                errors.append(
                    f"Stage 2 snippet calls unknown APIs in {unit_id}: "
                    + ", ".join(invented)
                )
        missing_units = sorted(expected - covered)
        outside_ft = sorted(covered - expected)
        missing_processing_units = sorted(set(required_units) - observed_ids)
        if missing_processing_units:
            errors.append(
                "Stage 2 omits required processing units: "
                + ", ".join(missing_processing_units)
            )
        if missing_units:
            errors.append("Stage 2 omits FT functions: " + ", ".join(missing_units))
        if outside_ft:
            errors.append(
                "Stage 2 references functions outside the FT: "
                + ", ".join(outside_ft)
            )
        return _result("stage2", errors, metadata={
            "artifact": str(result.output_path),
            "expected_functions": sorted(expected),
            "covered_functions": sorted(covered),
            "processing_units": sorted(observed_ids),
            "required_processing_units": sorted(required_units),
        })

    def validate_stage3(self, result: Stage3Result) -> ValidationResult:
        validation = IntermediateValidator().validate_triplet(
            result.rough_code_path,
            self.triplet,
            functions_json=self.functions_json,
            artifacts=self.artifacts,
            stage="stage3_rough",
            allowed_functions={
                relation.cleanup_function for relation in self.triplet.ownership_relations
            },
        )
        _copy_attempt_validation(
            self.layout,
            result.attempt_directory,
            "intermediate",
        )
        return _with_failure_type(validation, "stage3_validation")

    def validate_stage4(self, result: Stage4Result) -> ValidationResult:
        # Stage 3 and previous Stage 4 attempts may have left validation files.
        # A new candidate must earn every component status afresh.
        for path in (
            self.layout.intermediate_validation,
            self.layout.compiler_validation,
            self.layout.linker_validation,
            self.layout.runtime_validation,
            self.layout.validation_summary,
        ):
            path.unlink(missing_ok=True)
        try:
            validation = self._validate_stage4(result)
        except Exception as error:
            record_validation_exception(result.attempt_directory, error)
            raise
        record_validation_result(result.attempt_directory, validation)
        return validation

    def _validate_stage4(self, result: Stage4Result) -> ValidationResult:
        attempt = result.attempt_directory
        intermediate = IntermediateValidator().validate_triplet(
            result.harness_path,
            self.triplet,
            functions_json=self.functions_json,
            artifacts=self.artifacts,
            stage="stage4_harness",
            allowed_functions={
                relation.cleanup_function for relation in self.triplet.ownership_relations
            },
        )
        if intermediate.status == "failed":
            if self.config.stage4_policy == "hybrid":
                intermediate = _hybrid_intermediate_result(intermediate)
                self.layout.write_validation("intermediate", intermediate.to_dict())
            else:
                _copy_attempt_validation(self.layout, attempt, "intermediate")
                return _with_failure_type(
                    intermediate, "intermediate_validation"
                )
        _copy_attempt_validation(self.layout, attempt, "intermediate")
        if not self.config.build_enabled:
            return _result("stage4", (), metadata={
                "component_statuses": (intermediate.status,),
                "build_requested": False,
                "fuzz_smoke_completed": False,
            })

        if self.target_build is not None:
            compile_link = FuzzerBuildValidator().validate(
                result.harness_path,
                self.target_build,
                artifacts=self.artifacts,
                ft_id=self.triplet.id,
                stage="stage4_compile_link",
            )
            _copy_attempt_validation(self.layout, attempt, "compiler")
            _copy_attempt_validation(self.layout, attempt, "linker")
            if compile_link.status != "passed":
                RuntimeValidator(timeout=self.config.runtime_timeout).validate_triplet(
                    None,
                    artifacts=self.artifacts,
                    ft_id=self.triplet.id,
                    stage="stage4_runtime",
                )
                _copy_attempt_validation(self.layout, attempt, "runtime")
                return compile_link

            executable = self.layout.build / "fuzzer"
            runtime = RuntimeValidator(
                timeout=self.config.runtime_timeout
            ).validate_smoke_triplet(
                executable,
                artifacts=self.artifacts,
                ft_id=self.triplet.id,
                generated_sources=(
                    result.harness_path,
                    result.attempt_directory / "harness.c",
                    self.layout.harness,
                ),
                target_root=self.project_root,
                arguments=self.config.runtime_arguments,
                stage="stage4_runtime_smoke",
            )
            _copy_attempt_validation(self.layout, attempt, "runtime")
            if runtime.status == "failed":
                return runtime
            if runtime.status == "passed_with_limitations":
                return runtime
            statuses: tuple[str, ...] = (
                intermediate.status,
                "passed",
                "passed",
                runtime.status,
            )
            if runtime.status in {"skipped", "unavailable"}:
                return _limited_result("stage4", statuses)
            if self.config.fuzz_smoke is not None:
                fuzz_smoke = LibFuzzerSmokeValidator(
                    self.config.fuzz_smoke,
                    runner=self.config.fuzz_runner,
                ).validate_triplet(
                    executable,
                    artifacts=self.artifacts,
                    ft_id=self.triplet.id,
                    generated_sources=(
                        result.harness_path,
                        result.attempt_directory / "harness.c",
                        self.layout.harness,
                    ),
                    target_root=self.project_root,
                )
                statuses = (*statuses, fuzz_smoke.status)
                if fuzz_smoke.status == "failed":
                    return fuzz_smoke
                if fuzz_smoke.status == "passed_with_limitations":
                    return fuzz_smoke
                if fuzz_smoke.status in {"skipped", "unavailable"}:
                    return _limited_result("stage4", statuses)
            return _result("stage4", (), metadata={
                "component_statuses": statuses,
                "fuzzer": str(executable),
                "fuzz_smoke_completed": self.config.fuzz_smoke is not None,
            })

        compiler_config = self.config.compiler or _default_compiler_config(
            self.project_root
        )
        configured_executable = self.config.executable
        executable = configured_executable
        if executable is None and compiler_config.has_link_configuration:
            executable = self.layout.generation / "fuzzer"
        compiler = CompilerValidator(compiler_config).validate_triplet(
            result.harness_path,
            artifacts=self.artifacts,
            ft_id=self.triplet.id,
            output=executable,
            stage="stage4_compile",
            preserve_existing_linker=False,
        )
        _copy_attempt_validation(self.layout, attempt, "compiler")
        _copy_attempt_validation(self.layout, attempt, "linker")

        if compiler.status == "failed":
            RuntimeValidator(timeout=self.config.runtime_timeout).validate_triplet(
                None,
                artifacts=self.artifacts,
                ft_id=self.triplet.id,
                stage="stage4_runtime",
            )
            _copy_attempt_validation(self.layout, attempt, "runtime")
            if compiler.metadata.get("syntax_valid"):
                return _persisted_failure(
                    self.layout.linker_validation,
                    fallback_errors=compiler.errors,
                    failure_type="link_error",
                )
            return _with_failure_type(compiler, _compiler_failure_type(compiler))

        linker = _load_json(self.layout.linker_validation)
        link_status = linker.get("status", "unavailable")
        runtime_executable = (
            configured_executable
            if configured_executable is not None
            else executable if link_status == "passed" else None
        )
        runtime = RuntimeValidator(
            timeout=self.config.runtime_timeout
        ).validate_triplet(
            runtime_executable,
            artifacts=self.artifacts,
            ft_id=self.triplet.id,
            arguments=self.config.runtime_arguments,
            stage="stage4_runtime",
        )
        _copy_attempt_validation(self.layout, attempt, "runtime")
        if runtime.status in {"failed", "timed_out"}:
            return _runtime_result(runtime)

        statuses: tuple[str, ...] = (
            intermediate.status, compiler.status, link_status, runtime.status
        )
        required_statuses = statuses[:2]
        if "unavailable" in required_statuses:
            return _nonblocking_result("stage4", "unavailable", statuses)
        if "skipped" in required_statuses:
            return _nonblocking_result("stage4", "skipped", statuses)
        if any(status in {"skipped", "unavailable"} for status in statuses[2:]):
            return _limited_result("stage4", statuses)
        if self.config.fuzz_smoke is not None:
            fuzz_smoke = LibFuzzerSmokeValidator(
                self.config.fuzz_smoke,
                runner=self.config.fuzz_runner,
            ).validate_triplet(
                runtime_executable,
                artifacts=self.artifacts,
                ft_id=self.triplet.id,
                generated_sources=(
                    result.harness_path,
                    result.attempt_directory / "harness.c",
                    self.layout.harness,
                ),
                target_root=self.project_root,
            )
            statuses = (*statuses, fuzz_smoke.status)
            if fuzz_smoke.status == "failed":
                return fuzz_smoke
            if fuzz_smoke.status == "passed_with_limitations":
                return fuzz_smoke
            if fuzz_smoke.status in {"skipped", "unavailable"}:
                return _limited_result("stage4", statuses)
        return _result("stage4", (), metadata={
            "component_statuses": statuses,
            "fuzz_smoke_completed": self.config.fuzz_smoke is not None,
        })


def _result(
    validator: str,
    errors: Iterable[str],
    *,
    warnings: Iterable[str] = (),
    metadata: Mapping[str, Any] | None = None,
) -> ValidationResult:
    canonical_errors = tuple(dict.fromkeys(errors))
    return ValidationResult(
        success=not canonical_errors,
        errors=canonical_errors,
        warnings=tuple(dict.fromkeys(warnings)),
        metadata={"validator": validator, **dict(metadata or {})},
    )


def _unavailable(validator: str, reason: str) -> ValidationResult:
    return ValidationResult(
        success=None,
        errors=(),
        warnings=(reason,),
        metadata={"validator": validator},
        status="unavailable",
    )


def _nonblocking_result(
    validator: str,
    status: str,
    component_statuses: Sequence[str],
) -> ValidationResult:
    return ValidationResult(
        success=None,
        errors=(),
        warnings=(f"Stage validation completed with status {status}",),
        metadata={
            "validator": validator,
            "component_statuses": list(component_statuses),
        },
        status=status,
    )


def _limited_result(
    validator: str,
    component_statuses: Sequence[str],
) -> ValidationResult:
    return ValidationResult(
        success=True,
        errors=(),
        warnings=(
            "Required syntax validation passed, but link or runtime validation "
            "was not available",
        ),
        metadata={
            "validator": validator,
            "component_statuses": list(component_statuses),
        },
        status="passed_with_limitations",
    )


def _hybrid_intermediate_result(result: ValidationResult) -> ValidationResult:
    """Downgrade strict Stage 4 policy errors so real build/runtime can decide."""

    strict_errors = tuple(dict.fromkeys(result.errors))
    warnings = tuple(dict.fromkeys((
        *result.warnings,
        *(
            f"Hybrid Stage 4 policy warning: {message}"
            for message in strict_errors
        ),
    )))
    return ValidationResult(
        success=True,
        errors=(),
        warnings=warnings,
        metadata={
            **dict(result.metadata),
            "hybrid_policy": "intermediate_errors_as_warnings",
            "strict_status": result.status,
            "strict_errors": list(strict_errors),
        },
        status="passed_with_warnings",
    )


def _with_failure_type(
    result: ValidationResult, failure_type: str
) -> ValidationResult:
    return ValidationResult(
        success=result.success,
        errors=result.errors,
        warnings=result.warnings,
        metadata={**dict(result.metadata), "failure_type": failure_type},
        status=result.status,
    )


def _runtime_result(result: RuntimeValidationResult) -> ValidationResult:
    reason = result.reason or "runtime validation failed"
    return ValidationResult(
        success=False,
        errors=(reason,),
        warnings=(),
        metadata={
            **dict(result.metadata),
            "validator": "runtime",
            "failure_type": "runtime_failure",
        },
        status="failed",
    )


def _compiler_failure_type(result: ValidationResult) -> str:
    if not result.metadata.get("syntax_valid"):
        return "compile_error"
    return "link_error"


def _persisted_failure(
    path: Path,
    *,
    fallback_errors: Sequence[str],
    failure_type: str,
) -> ValidationResult:
    document = _load_json(path)
    errors = document.get("errors")
    warnings = document.get("warnings")
    metadata = document.get("metadata")
    canonical_errors = tuple(
        error for error in errors if isinstance(error, str) and error
    ) if isinstance(errors, list) else tuple(fallback_errors)
    if not canonical_errors:
        canonical_errors = tuple(fallback_errors) or ("validation failed",)
    canonical_warnings = tuple(
        warning for warning in warnings if isinstance(warning, str) and warning
    ) if isinstance(warnings, list) else ()
    validator = document.get("validator", "stage")
    return ValidationResult(
        success=False,
        errors=canonical_errors,
        warnings=canonical_warnings,
        metadata={
            **(dict(metadata) if isinstance(metadata, Mapping) else {}),
            "validator": validator,
            "failure_type": failure_type,
        },
        status="failed",
    )


def _json_object(path: Path, errors: list[str], owner: str) -> Mapping[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        errors.append(f"{owner} artifact is unreadable: {type(error).__name__}")
        return {}
    if not isinstance(document, Mapping):
        errors.append(f"{owner} artifact must contain an object")
        return {}
    return document


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return document if isinstance(document, Mapping) else {}


def _copy_attempt_validation(
    layout: TripletArtifacts,
    attempt_directory: Path,
    validator: str,
) -> Path:
    document = _load_json(layout.validation_path(validator))
    destination = attempt_directory / "validation" / f"{validator}.json"
    layout.write_json(destination, dict(document))
    return destination


def _resolve_project_root(
    functions_json: Path, project_root: str | Path | None
) -> Path:
    document = _load_json(functions_json)
    return SourcePathResolver.from_functions_document(
        document,
        functions_json,
        project_root=project_root,
    ).project_root


def _target_function_names(functions_json: Path) -> frozenset[str]:
    document = _load_json(functions_json)
    records = document.get("functions", [])
    if not isinstance(records, list):
        return frozenset()
    return frozenset(
        record["name"]
        for record in records
        if isinstance(record, Mapping) and isinstance(record.get("name"), str)
    )


def _default_compiler_config(project_root: Path) -> CompilerConfig:
    include_paths = tuple(
        path for path in (project_root, project_root / "include") if path.is_dir()
    )
    return CompilerConfig(
        compiler="clang++",
        include_paths=include_paths,
        compiler_flags=("-x", "c++", "-std=c++17"),
    )


def _discover_target_build(project_root: Path) -> TargetBuildConfig | None:
    """Use the inspected simple src/include layout when target sources exist."""

    try:
        return TargetBuildConfig.for_simple_project(project_root)
    except (OSError, ValueError):
        return None
