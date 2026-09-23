"""Bounded smoke execution for a compiled harness executable."""

from __future__ import annotations

import math
import os
import re
import signal as signal_module
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .artifacts import ArtifactStore
from .records import write_json
from .validation import VALIDATION_SCHEMA_VERSION, ValidationResult


RUNTIME_PASSED = "passed"
RUNTIME_FAILED = "failed"
RUNTIME_TIMED_OUT = "timed_out"
RUNTIME_SKIPPED = "skipped"
_RUNTIME_STATUSES = frozenset({
    RUNTIME_PASSED,
    RUNTIME_FAILED,
    RUNTIME_TIMED_OUT,
    RUNTIME_SKIPPED,
})

_STACK_FRAME = re.compile(
    r"^\s*#(?P<index>\d+)\s+.*?(?P<source>(?:/|[A-Za-z]:[\\/])"
    r"[^\s()]+?\.(?:c|h|cc|cpp)):(?P<line>\d+)(?::(?P<column>\d+))?",
    re.MULTILINE,
)

# The single authority for fault attribution.  These strings travel through
# saved metadata into evaluators, feedback loops and promotion gates, so a
# consumer that hardcodes its own copy silently stops covering new values.
CRASH_NONE = "none"
CRASH_TIMEOUT = "timeout"
#: Smoke could not be attributed because it never produced a stack at all.
CLASSIFICATION_UNAVAILABLE = "unavailable"
GENERATED_HARNESS_CRASH = "generated_harness_crash"
GENERATED_HARNESS_LEAK = "generated_harness_leak"
POTENTIAL_TARGET_CRASH = "potential_target_crash"
UNCLASSIFIED_CRASH = "unclassified_crash"

#: Faults the harness itself is answerable for, whatever the target did.
HARNESS_CRASH_CLASSIFICATIONS = frozenset({
    GENERATED_HARNESS_CRASH,
    GENERATED_HARNESS_LEAK,
})

#: Faults that stop the harness from being published.
BLOCKING_CRASH_CLASSIFICATIONS = HARNESS_CRASH_CLASSIFICATIONS | {UNCLASSIFIED_CRASH}

#: Every value `_classify_frames` can return, for consumers that must cover all
#: of them rather than the ones that existed when they were written.
CRASH_CLASSIFICATIONS = (
    HARNESS_CRASH_CLASSIFICATIONS
    | {POTENTIAL_TARGET_CRASH, UNCLASSIFIED_CRASH}
)

_LEAK_MARKER = re.compile(
    r"LeakSanitizer:\s*detected\s+memory\s+leaks|Sanitizer:\s*\d+\s+byte\(s\)\s+leaked",
    re.IGNORECASE,
)

#: libFuzzer names saved artifacts by fault kind; a `leak-` input is a leak
#: even when the process exit path never printed a sanitizer report.
ARTIFACT_CRASH_PREFIXES = ("crash-", "leak-", "oom-", "timeout-")
LEAK_ARTIFACT_PREFIX = "leak-"


@dataclass(frozen=True)
class RuntimeValidationResult:
    """Serializable four-state result; skipped validation is never success."""

    status: str
    reason: str | None
    stdout: str
    stderr: str
    return_code: int | None
    command: tuple[str, ...]
    timed_out: bool
    timeout_seconds: float
    metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.status not in _RUNTIME_STATUSES:
            raise ValueError(f"invalid runtime validation status: {self.status}")
        if self.status == RUNTIME_SKIPPED and not self.reason:
            raise ValueError("skipped runtime validation requires a reason")
        if self.status == RUNTIME_PASSED:
            if self.return_code != 0 or self.timed_out or self.reason is not None:
                raise ValueError(
                    "passed runtime validation requires return_code 0, no timeout, "
                    "and no reason"
                )
        elif self.status == RUNTIME_FAILED:
            if self.return_code in (None, 0) or self.timed_out or not self.reason:
                raise ValueError(
                    "failed runtime validation requires a nonzero return code and reason"
                )
        elif self.status == RUNTIME_TIMED_OUT:
            if not self.timed_out or self.return_code is not None or not self.reason:
                raise ValueError(
                    "timed_out status requires timeout information and no return code"
                )
        elif self.return_code is not None or self.timed_out:
            raise ValueError(
                "skipped runtime validation cannot have a return code or timeout"
            )

    @property
    def success(self) -> bool | None:
        if self.status == RUNTIME_SKIPPED:
            return None
        return self.status == RUNTIME_PASSED

    def to_dict(self) -> dict[str, Any]:
        status = "failed" if self.status == RUNTIME_TIMED_OUT else self.status
        errors = (
            [self.reason]
            if self.status in {RUNTIME_FAILED, RUNTIME_TIMED_OUT} and self.reason
            else []
        )
        warnings = (
            [self.reason]
            if self.status == RUNTIME_SKIPPED and self.reason
            else []
        )
        metadata = dict(self.metadata)
        metadata["runtime_status"] = self.status
        return {
            "validator": "runtime",
            "status": status,
            "success": self.success,
            "errors": errors,
            "warnings": warnings,
            "reason": self.reason,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "command": list(self.command),
            "timed_out": self.timed_out,
            "timeout_seconds": self.timeout_seconds,
            "metadata": metadata,
        }

    def save(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_json(destination, self.to_dict(), sort_keys=True, allow_nan=False)
        return destination


Runner = Callable[..., subprocess.CompletedProcess[str]]


class RuntimeValidator:
    """Execute one smoke command when its executable is locally available."""

    def __init__(
        self,
        *,
        timeout: float = 30.0,
        runner: Runner = subprocess.run,
    ) -> None:
        if (isinstance(timeout, bool)
                or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout)
                or timeout <= 0):
            raise ValueError("timeout must be a positive finite number")
        self.timeout = timeout
        self.runner = runner

    def validate(
        self,
        executable: str | Path | None,
        *,
        validation_path: str | Path,
        arguments: Sequence[str] = (),
        working_directory: str | Path | None = None,
        stage: str = "runtime",
    ) -> RuntimeValidationResult:
        arguments = _arguments(arguments)
        executable_path = _resolve_executable(executable)
        command = (() if executable_path is None else
                   (str(executable_path), *arguments))
        cwd = (Path(working_directory) if working_directory is not None else
               (executable_path.parent if executable_path is not None else None))
        metadata = {
            "schema_version": VALIDATION_SCHEMA_VERSION,
            "stage": stage,
            "validator": "runtime",
            "executable": None if executable_path is None else str(executable_path),
            "working_directory": None if cwd is None else str(cwd),
        }

        unavailable_reason = _unavailable_reason(executable, executable_path)
        if unavailable_reason is not None:
            return self._save(
                validation_path,
                status=RUNTIME_SKIPPED,
                reason=unavailable_reason,
                command=command,
                metadata=metadata,
            )

        try:
            completed = self.runner(
                list(command),
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            return self._save(
                validation_path,
                status=RUNTIME_TIMED_OUT,
                reason=f"smoke test exceeded {self.timeout:g} seconds",
                stdout=_diagnostic_text(error.stdout),
                stderr=_diagnostic_text(error.stderr),
                command=command,
                timed_out=True,
                metadata=metadata,
            )
        except OSError as error:
            return self._save(
                validation_path,
                status=RUNTIME_SKIPPED,
                reason=f"executable could not be started: {error}",
                command=command,
                metadata=metadata,
            )

        return_code = completed.returncode
        passed = return_code == 0
        return self._save(
            validation_path,
            status=RUNTIME_PASSED if passed else RUNTIME_FAILED,
            reason=None if passed else f"smoke test exited with return code {return_code}",
            stdout=_diagnostic_text(completed.stdout),
            stderr=_diagnostic_text(completed.stderr),
            return_code=return_code,
            command=command,
            metadata=metadata,
        )

    def validate_triplet(
        self,
        executable: str | Path | None,
        *,
        artifacts: str | Path,
        ft_id: str,
        arguments: Sequence[str] = (),
        working_directory: str | Path | None = None,
        stage: str = "runtime",
    ) -> RuntimeValidationResult:
        """Run smoke validation and persist its isolated canonical artifact."""

        layout = ArtifactStore(Path(artifacts)).for_triplet(ft_id)
        result = self.validate(
            executable,
            validation_path=layout.runtime_validation,
            arguments=arguments,
            working_directory=working_directory,
            stage=stage,
        )
        canonical_status = (
            "failed" if result.status == RUNTIME_TIMED_OUT else result.status
        )
        errors = (
            [result.reason]
            if result.status in {RUNTIME_FAILED, RUNTIME_TIMED_OUT} and result.reason
            else []
        )
        warnings = (
            [result.reason]
            if result.status == RUNTIME_SKIPPED and result.reason
            else []
        )
        metadata = dict(result.metadata)
        metadata["runtime_status"] = result.status
        layout.write_validation("runtime", {
            "validator": "runtime",
            "status": canonical_status,
            "errors": errors,
            "warnings": warnings,
            "timeout": result.timeout_seconds,
            "timed_out": result.timed_out,
            "command": list(result.command),
            "return_code": result.return_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "metadata": metadata,
        })
        return result

    def validate_smoke_triplet(
        self,
        executable: str | Path | None,
        *,
        artifacts: str | Path,
        ft_id: str,
        generated_sources: Sequence[str | Path],
        target_root: str | Path,
        arguments: Sequence[str] = (),
        stage: str = "stage4_runtime_smoke",
    ) -> ValidationResult:
        """Run fixed empty/minimal inputs without starting a fuzz campaign."""

        arguments = _arguments(arguments)
        if any(argument.startswith("-runs=") for argument in arguments):
            raise ValueError("runtime smoke controls -runs; do not pass it explicitly")
        layout = ArtifactStore(Path(artifacts)).for_triplet(ft_id).ensure_build()
        executable_path = _resolve_executable(executable)
        unavailable_reason = _unavailable_reason(executable, executable_path)
        generated = tuple(Path(path).resolve() for path in generated_sources)
        target = Path(target_root).resolve()
        inputs_directory = layout.build / "runtime_inputs"
        inputs_directory.mkdir(parents=True, exist_ok=True)
        inputs = (
            ("empty", inputs_directory / "empty.bin", b""),
            ("minimal", inputs_directory / "minimal.bin", b"\x00"),
        )
        for _name, path, content in inputs:
            path.write_bytes(content)

        if unavailable_reason is not None:
            document = {
                "validator": "runtime",
                "status": "skipped",
                "errors": [],
                "warnings": [unavailable_reason],
                "command": [],
                "return_code": None,
                "signal": None,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
                "timeout": self.timeout,
                "metadata": {
                    "schema_version": VALIDATION_SCHEMA_VERSION,
                    "stage": stage,
                    "mode": "fixed_inputs",
                    "reason": unavailable_reason,
                    "cases": [],
                },
            }
            layout.write_validation("runtime", document)
            return ValidationResult(
                success=None,
                errors=(),
                warnings=(unavailable_reason,),
                metadata={"validator": "runtime", "stage": stage},
                status="skipped",
            )

        started = time.monotonic()
        cases: list[dict[str, Any]] = []
        runtime_environment = _runtime_environment()
        for name, input_path, content in inputs:
            remaining = self.timeout - (time.monotonic() - started)
            command = (
                str(executable_path),
                *arguments,
                str(input_path.resolve()),
            )
            if remaining <= 0:
                cases.append(_timeout_case(
                    name, input_path, content, command, self.timeout, "", ""
                ))
                break
            try:
                completed = self.runner(
                    list(command),
                    cwd=layout.build.resolve(),
                    capture_output=True,
                    text=True,
                    timeout=remaining,
                    check=False,
                    env=runtime_environment,
                )
            except subprocess.TimeoutExpired as error:
                cases.append(_timeout_case(
                    name,
                    input_path,
                    content,
                    command,
                    self.timeout,
                    _diagnostic_text(error.stdout),
                    _diagnostic_text(error.stderr),
                ))
                break
            except OSError as error:
                case = _case_record(
                    name=name,
                    input_path=input_path,
                    content=content,
                    command=command,
                    return_code=None,
                    stdout="",
                    stderr=str(error),
                    timed_out=False,
                    generated_sources=generated,
                    target_root=target,
                )
                case["status"] = "unavailable"
                cases.append(case)
                break
            cases.append(_case_record(
                name=name,
                input_path=input_path,
                content=content,
                command=command,
                return_code=completed.returncode,
                stdout=_diagnostic_text(completed.stdout),
                stderr=_diagnostic_text(completed.stderr),
                timed_out=False,
                generated_sources=generated,
                target_root=target,
            ))

        status, errors, warnings, classification = _smoke_policy(cases)
        primary = next(
            (case for case in cases if case["status"] != "passed"),
            cases[-1] if cases else None,
        )
        stdout = "\n".join(
            case["stdout"].rstrip("\n") for case in cases if case["stdout"]
        )
        stderr = "\n".join(
            case["stderr"].rstrip("\n") for case in cases if case["stderr"]
        )
        stack_statuses = {
            case["stack_parser_status"] for case in cases
            if case["return_code"] not in (None, 0)
        }
        document = {
            "validator": "runtime",
            "status": status,
            "errors": errors,
            "warnings": warnings,
            "command": [] if primary is None else primary["command"],
            "return_code": None if primary is None else primary["return_code"],
            "signal": None if primary is None else primary["signal"],
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": any(case["timed_out"] for case in cases),
            "timeout": self.timeout,
            "metadata": {
                "schema_version": VALIDATION_SCHEMA_VERSION,
                "stage": stage,
                "mode": "fixed_inputs",
                "fuzzing": False,
                "executable": str(executable_path),
                "input_directory": str(inputs_directory.resolve()),
                "generated_sources": [str(path) for path in generated],
                "target_root": str(target),
                "crash_classification": classification,
                "stack_parser_status": (
                    "not_needed" if not stack_statuses
                    else "parsed" if stack_statuses == {"parsed"}
                    else "unavailable"
                ),
                "cases": cases,
            },
        }
        layout.write_validation("runtime", document)
        return ValidationResult(
            success=(True if status in {"passed", "passed_with_limitations"}
                     else None if status == "skipped" else False),
            errors=tuple(errors),
            warnings=tuple(warnings),
            metadata={
                "validator": "runtime",
                "stage": stage,
                "failure_type": _runtime_failure_type(classification),
                "failed_stage": "runtime_smoke" if status == "failed" else None,
                "crash_classification": classification,
                "runtime_artifact": str(layout.runtime_validation),
            },
            status=status,
        )

    def _save(
        self,
        path: str | Path,
        *,
        status: str,
        reason: str | None,
        command: tuple[str, ...],
        metadata: Mapping[str, Any],
        stdout: str = "",
        stderr: str = "",
        return_code: int | None = None,
        timed_out: bool = False,
    ) -> RuntimeValidationResult:
        result = RuntimeValidationResult(
            status=status,
            reason=reason,
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
            command=command,
            timed_out=timed_out,
            timeout_seconds=self.timeout,
            metadata=metadata,
        )
        result.save(path)
        return result


def validate_runtime(
    executable: str | Path | None,
    *,
    validation_path: str | Path,
    arguments: Sequence[str] = (),
    working_directory: str | Path | None = None,
    timeout: float = 30.0,
    stage: str = "runtime",
) -> RuntimeValidationResult:
    return RuntimeValidator(timeout=timeout).validate(
        executable,
        validation_path=validation_path,
        arguments=arguments,
        working_directory=working_directory,
        stage=stage,
    )


def _resolve_executable(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    if not isinstance(value, (str, Path)) or not str(value).strip():
        raise ValueError("executable must be a non-empty path or None")
    candidate = Path(value).expanduser()
    if candidate.exists() or candidate.parent != Path("."):
        return candidate.resolve()
    located = shutil.which(str(value))
    return Path(located).resolve() if located is not None else candidate.resolve()


def _unavailable_reason(
    original: str | Path | None,
    executable: Path | None,
) -> str | None:
    if original is None:
        return "executable was not provided"
    if executable is None or not executable.exists():
        return f"executable does not exist: {executable}"
    if not executable.is_file():
        return f"executable is not a regular file: {executable}"
    if not os.access(executable, os.X_OK):
        return f"executable is not executable: {executable}"
    return None


def _arguments(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError("arguments must be a sequence of arguments")
    result = tuple(values)
    if any(not isinstance(value, str) or not value for value in result):
        raise ValueError("arguments must contain non-empty strings")
    return result


def _case_record(
    *,
    name: str,
    input_path: Path,
    content: bytes,
    command: Sequence[str],
    return_code: int | None,
    stdout: str,
    stderr: str,
    timed_out: bool,
    generated_sources: Sequence[Path],
    target_root: Path,
) -> dict[str, Any]:
    frames = _source_frames(stderr)
    frame = frames[0] if frames else None
    if timed_out:
        status = "timed_out"
        classification = CRASH_TIMEOUT
    elif return_code == 0:
        status = "passed"
        classification = CRASH_NONE
    elif return_code is None:
        status = "unavailable"
        classification = CLASSIFICATION_UNAVAILABLE
    else:
        attribution_frame, classification = _classify_frames(
            frames, generated_sources, target_root, _leak_reported(stderr)
        )
        status = "crashed"
    if return_code in (None, 0) or timed_out:
        attribution_frame = None
    signal_number = -return_code if return_code is not None and return_code < 0 else None
    return {
        "name": name,
        "input": str(input_path.resolve()),
        "input_size": len(content),
        "command": list(command),
        "status": status,
        "return_code": return_code,
        "signal": signal_number,
        "signal_name": _signal_name(signal_number),
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "crash_classification": classification,
        "top_frame": frame,
        "attribution_frame": attribution_frame,
        "stack_parser_status": (
            "not_needed" if return_code == 0
            else "parsed" if frame is not None
            else "unavailable"
        ),
    }


def _timeout_case(
    name: str,
    input_path: Path,
    content: bytes,
    command: Sequence[str],
    timeout: float,
    stdout: str,
    stderr: str,
) -> dict[str, Any]:
    case = _case_record(
        name=name,
        input_path=input_path,
        content=content,
        command=command,
        return_code=None,
        stdout=stdout,
        stderr=stderr,
        timed_out=True,
        generated_sources=(),
        target_root=Path("/").resolve(),
    )
    case["timeout"] = timeout
    return case


def _source_frames(stderr: str) -> tuple[dict[str, Any], ...]:
    return tuple({
        "index": int(match.group("index")),
        "source": match.group("source"),
        "line": int(match.group("line")),
        "column": (
            None if match.group("column") is None
            else int(match.group("column"))
        ),
        "raw": match.group(0).strip(),
    } for match in _STACK_FRAME.finditer(stderr))


def classify_crash(
    stderr: str,
    *,
    generated_sources: Sequence[str | Path],
    target_root: str | Path,
    leaked: bool | None = None,
) -> dict[str, Any]:
    """Attribute sanitizer/libFuzzer frames without interpreting a target bug.

    `leaked` distinguishes a leak from a hard fault.  Left as None it is read
    from the sanitizer's own report in `stderr`.
    """

    frames = _source_frames(stderr)
    frame, classification = _classify_frames(
        frames,
        tuple(Path(path).resolve() for path in generated_sources),
        Path(target_root).resolve(),
        _leak_reported(stderr) if leaked is None else leaked,
    )
    return {
        "classification": classification,
        "top_frame": frames[0] if frames else None,
        "attribution_frame": frame,
        "stack_parser_status": "parsed" if frames else "unavailable",
    }


def _leak_reported(stderr: str) -> bool:
    """Report LeakSanitizer's own verdict, not a guess from a return code."""
    return _LEAK_MARKER.search(stderr) is not None


def _classify_frames(
    frames: Sequence[Mapping[str, Any]],
    generated_sources: Sequence[Path],
    target_root: Path,
    leaked: bool = False,
) -> tuple[Mapping[str, Any] | None, str]:
    """Use the first attributed fault frame; treat mixed leak stacks as unknown.

    A normal fault stack contains the harness entry below the target frame.
    That caller frame cannot override the actual fault location. A leak stack
    describes where memory was allocated, not who omitted the release, so a
    target allocation reached through generated code is insufficient to blame
    either side. The ambiguous leak is blocked without being called a target bug.
    """
    generated = set(generated_sources)
    attributed = []
    for frame in frames:
        source = Path(str(frame["source"])).resolve()
        if source in generated:
            attributed.append((frame, "harness"))
        elif _under(source, target_root):
            attributed.append((frame, "target"))
    if not attributed:
        return None, UNCLASSIFIED_CRASH
    first_frame, first_kind = attributed[0]
    if leaked:
        kinds = {kind for _, kind in attributed}
        if kinds == {"harness"}:
            return first_frame, GENERATED_HARNESS_LEAK
        # A target allocator in the LSan allocation stack does not identify
        # the missing cleanup site, even when no harness frame was symbolized.
        return first_frame, UNCLASSIFIED_CRASH
    if first_kind == "harness":
        return first_frame, GENERATED_HARNESS_CRASH
    if first_kind == "target":
        return first_frame, POTENTIAL_TARGET_CRASH
    return None, UNCLASSIFIED_CRASH


def _under(source: Path, root: Path) -> bool:
    try:
        source.relative_to(root)
    except ValueError:
        return False
    return True


def _smoke_policy(
    cases: Sequence[Mapping[str, Any]],
) -> tuple[str, list[str], list[str], str]:
    classifications = [case["crash_classification"] for case in cases]
    if CRASH_TIMEOUT in classifications:
        return (
            "failed",
            ["runtime smoke exceeded its timeout"],
            [],
            CRASH_TIMEOUT,
        )
    if GENERATED_HARNESS_LEAK in classifications:
        return (
            "failed",
            ["runtime smoke leaked a target resource; the generated harness did "
             "not release what it acquired"],
            [],
            GENERATED_HARNESS_LEAK,
        )
    if GENERATED_HARNESS_CRASH in classifications:
        return (
            "failed",
            ["runtime smoke crashed in generated harness code"],
            [],
            GENERATED_HARNESS_CRASH,
        )
    if UNCLASSIFIED_CRASH in classifications:
        return (
            "failed",
            ["runtime smoke crashed; stack source attribution is unavailable"],
            [],
            UNCLASSIFIED_CRASH,
        )
    if CLASSIFICATION_UNAVAILABLE in classifications:
        return (
            "skipped",
            [],
            ["runtime smoke executable could not be started"],
            CLASSIFICATION_UNAVAILABLE,
        )
    if POTENTIAL_TARGET_CRASH in classifications:
        return (
            "passed_with_limitations",
            [],
            ["runtime smoke found a potential target crash; preserved for triage"],
            POTENTIAL_TARGET_CRASH,
        )
    return "passed", [], [], CRASH_NONE


def _runtime_failure_type(classification: str) -> str | None:
    return {
        CRASH_TIMEOUT: "runtime_timeout",
        GENERATED_HARNESS_CRASH: GENERATED_HARNESS_CRASH,
        GENERATED_HARNESS_LEAK: GENERATED_HARNESS_LEAK,
        UNCLASSIFIED_CRASH: "unclassified_runtime_crash",
    }.get(classification)


def _signal_name(number: int | None) -> str | None:
    if number is None:
        return None
    try:
        return signal_module.Signals(number).name
    except ValueError:
        return None


def _runtime_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "abort_on_error=1:symbolize=1")
    environment.setdefault(
        "UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"
    )
    return environment


def _diagnostic_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
