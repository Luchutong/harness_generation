"""Real target/harness compilation and libFuzzer link validation."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
import subprocess
from typing import Any, Callable, Mapping, Sequence

from .artifacts import ArtifactStore, TripletArtifacts
from .compiler_validation import BuildAdapter, CommandResult, CompilerConfig
from .target_build import TargetBuildAdapter, TargetBuildConfig, TargetBuildResult
from .validation import VALIDATION_SCHEMA_VERSION, ValidationResult


DEFAULT_FUZZER_COMPILE_FLAGS = (
    "-g",
    "-O1",
    "-Werror=implicit-function-declaration",
    "-fsanitize=fuzzer-no-link,address,undefined",
)
DEFAULT_HARNESS_COMPILE_FLAGS = (
    "-x",
    "c++",
    "-std=c++17",
    "-g",
    "-O1",
    "-fsanitize=fuzzer-no-link,address,undefined",
)
DEFAULT_FUZZER_LINK_FLAGS = (
    "-g",
    "-O1",
    "-fsanitize=fuzzer,address,undefined",
)
#: What compiles and links a harness.  The pipeline emits a C++ translation
#: unit (see :func:`harness_generation.stage4.normalize_cpp_harness`).  The
#: compile step needs C++ syntax; using the same driver for the link keeps the
#: toolchain consistent.  With the current ``-fsanitize=fuzzer`` link flags,
#: clang also links the C++ runtime, so this is an invariant rather than a
#: repair for a reproduced link failure.  One name lets callers change every
#: path that builds a harness together.
DEFAULT_HARNESS_COMPILER = "clang++"


@dataclass(frozen=True)
class FuzzerBuildConfig:
    """Flags and diagnostic bounds for a real libFuzzer executable build."""

    compile_flags: tuple[str, ...] = DEFAULT_FUZZER_COMPILE_FLAGS
    harness_compile_flags: tuple[str, ...] = DEFAULT_HARNESS_COMPILE_FLAGS
    link_flags: tuple[str, ...] = DEFAULT_FUZZER_LINK_FLAGS
    harness_compiler: str = DEFAULT_HARNESS_COMPILER
    link_compiler: str = DEFAULT_HARNESS_COMPILER
    stderr_tail_lines: int = 20
    stderr_tail_chars: int = 4000

    def __post_init__(self) -> None:
        for field in ("compile_flags", "harness_compile_flags", "link_flags"):
            values = getattr(self, field)
            if isinstance(values, (str, bytes)) or any(
                not isinstance(value, str) or not value for value in values
            ):
                raise ValueError(f"{field} must contain non-empty arguments")
            object.__setattr__(self, field, tuple(values))
        for field in ("harness_compiler", "link_compiler"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be non-empty text")
        if type(self.stderr_tail_lines) is not int or self.stderr_tail_lines < 1:
            raise ValueError("stderr_tail_lines must be a positive integer")
        if type(self.stderr_tail_chars) is not int or self.stderr_tail_chars < 1:
            raise ValueError("stderr_tail_chars must be a positive integer")


Runner = Callable[..., subprocess.CompletedProcess[str]]


class FuzzerBuildValidator:
    """Build target objects, compile one harness, and perform a real link."""

    def __init__(
        self,
        config: FuzzerBuildConfig | None = None,
        *,
        build_adapter: BuildAdapter | None = None,
        runner: Runner = subprocess.run,
    ) -> None:
        self.config = config or FuzzerBuildConfig()
        self.build_adapter = build_adapter or BuildAdapter()
        self.runner = runner

    def validate(
        self,
        harness: str | Path,
        target: TargetBuildConfig,
        *,
        artifacts: str | Path,
        ft_id: str,
        stage: str = "stage4_compile_link",
    ) -> ValidationResult:
        harness_path = Path(harness).resolve()
        layout = ArtifactStore(Path(artifacts)).for_triplet(ft_id).ensure_build()
        build_directory = layout.build.resolve()
        fuzzer = build_directory / "fuzzer"
        fuzzer.unlink(missing_ok=True)

        instrumented_target = replace(
            target,
            compiler_flags=_unique_flags(
                target.compiler_flags, self.config.compile_flags
            ),
        )
        target_result = TargetBuildAdapter(
            build_adapter=self.build_adapter,
            runner=self.runner,
        ).build(instrumented_target, artifacts=artifacts, ft_id=ft_id)

        all_compile_commands = list(target_result.commands)
        if not target_result.success:
            failed_stage = _target_failed_stage(target_result, target)
            failure = self._failure_context(
                target_result.commands[-1] if target_result.commands else None,
                failed_stage=failed_stage,
                fallback=target_result.errors[0] if target_result.errors else None,
            )
            status = target_result.status
            self._write_compiler(
                layout,
                status=status,
                commands=all_compile_commands,
                failure=failure,
                stage=stage,
                target_result=target_result,
            )
            self._write_linker_skipped(layout, stage, "target build did not pass")
            self._finish_build_manifest(
                layout, status=status, harness_compile=None, link=None, fuzzer=None
            )
            return _failure_result(status, failure, "compiler")

        harness_object = build_directory / "objects" / "harness.o"
        harness_object.parent.mkdir(parents=True, exist_ok=True)
        harness_object.unlink(missing_ok=True)
        harness_config = CompilerConfig(
            compiler=self.config.harness_compiler,
            include_paths=target.include_paths,
            compiler_flags=self.config.harness_compile_flags,
            working_directory=target.project_root,
            timeout=target.timeout,
        )
        harness_command = self.build_adapter.object_command(
            harness_path, harness_object, harness_config
        )
        harness_compile = self._run(harness_command, target)
        all_compile_commands.append(harness_compile)
        self._append_compile_command(
            layout, harness_path, harness_object, harness_command, target.project_root
        )

        harness_compiled = (
            harness_compile.status == "completed"
            and harness_compile.return_code == 0
            and harness_object.is_file()
        )
        if not harness_compiled:
            failure = self._failure_context(
                harness_compile,
                failed_stage="harness_compile",
                fallback=(
                    f"harness compiler did not create object: {harness_object}"
                    if harness_compile.return_code == 0 else None
                ),
            )
            status = (
                "unavailable"
                if harness_compile.status == "unavailable" else "failed"
            )
            self._write_compiler(
                layout,
                status=status,
                commands=all_compile_commands,
                failure=failure,
                stage=stage,
                target_result=target_result,
            )
            self._write_linker_skipped(layout, stage, "harness compilation did not pass")
            self._finish_build_manifest(
                layout,
                status=status,
                harness_compile=harness_compile,
                link=None,
                fuzzer=None,
            )
            self._write_combined_diagnostics(layout, all_compile_commands)
            return _failure_result(status, failure, "compiler")

        self._write_compiler(
            layout,
            status="passed",
            commands=all_compile_commands,
            failure=None,
            stage=stage,
            target_result=target_result,
        )

        link_config = CompilerConfig(
            compiler=self.config.link_compiler,
            link_flags=self.config.link_flags,
            working_directory=target.project_root,
            timeout=target.timeout,
        )
        link_inputs = (*target_result.object_files, harness_object)
        link_command = self.build_adapter.objects_link_command(
            link_inputs, fuzzer, link_config
        )
        link = self._run(link_command, target)
        link_passed = (
            link.status == "completed"
            and link.return_code == 0
            and fuzzer.is_file()
        )
        if link_passed:
            self._write_linker(layout, "passed", link, stage, None)
            status = "passed"
            failure = None
        else:
            failure = self._failure_context(
                link,
                failed_stage="link",
                fallback=(
                    f"linker did not create executable: {fuzzer}"
                    if link.return_code == 0 else None
                ),
            )
            status = "unavailable" if link.status == "unavailable" else "failed"
            self._write_linker(layout, status, link, stage, failure)

        self._finish_build_manifest(
            layout,
            status=status,
            harness_compile=harness_compile,
            link=link,
            fuzzer=fuzzer if link_passed else None,
        )
        self._write_combined_diagnostics(
            layout, (*all_compile_commands, link)
        )
        if failure is not None:
            return _failure_result(status, failure, "linker")
        return ValidationResult(
            success=True,
            errors=(),
            warnings=(),
            metadata={
                "validator": "compiler_linker",
                "stage": stage,
                "compiler_status": "passed",
                "linker_status": "passed",
                "fuzzer": str(fuzzer),
                "build_manifest": str(build_directory / "build.json"),
            },
            status="passed",
        )

    def _run(
        self,
        command: Sequence[str],
        target: TargetBuildConfig,
    ) -> CommandResult:
        canonical = tuple(command)
        try:
            completed = self.runner(
                list(canonical),
                cwd=target.project_root,
                capture_output=True,
                text=True,
                timeout=target.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            return CommandResult(
                canonical,
                _diagnostic_text(error.stdout),
                _diagnostic_text(error.stderr),
                None,
                "timed_out",
            )
        except OSError as error:
            return CommandResult(canonical, "", str(error), None, "unavailable")
        return CommandResult(
            canonical,
            _diagnostic_text(completed.stdout),
            _diagnostic_text(completed.stderr),
            completed.returncode,
            "completed",
        )

    def _failure_context(
        self,
        command: CommandResult | None,
        *,
        failed_stage: str,
        fallback: str | None = None,
    ) -> dict[str, str]:
        stderr = "" if command is None else command.stderr
        if command is not None and command.status == "unavailable":
            failure_type = "tool_unavailable"
        elif command is not None and command.status == "timed_out":
            failure_type = "timeout"
        elif failed_stage == "link":
            failure_type = "link_error"
        else:
            failure_type = "compile_error"
        tail = _bounded_tail(
            stderr,
            lines=self.config.stderr_tail_lines,
            characters=self.config.stderr_tail_chars,
        )
        summary = fallback or _error_summary(tail) or (
            f"{failed_stage} failed"
            if command is None or command.return_code is None
            else f"{failed_stage} failed with return code {command.return_code}"
        )
        return {
            "failure_type": failure_type,
            "error_summary": summary[:500],
            "relevant_stderr_tail": tail,
            "failed_stage": failed_stage,
        }

    @staticmethod
    def _write_compiler(
        layout: TripletArtifacts,
        *,
        status: str,
        commands: Sequence[CommandResult],
        failure: Mapping[str, str] | None,
        stage: str,
        target_result: TargetBuildResult,
    ) -> None:
        primary = commands[-1] if commands else None
        error_summary = None if failure is None else failure["error_summary"]
        layout.write_validation("compiler", {
            "validator": "compiler",
            "status": status,
            "errors": [] if status != "failed" else [error_summary],
            "warnings": [] if status != "unavailable" else [error_summary],
            "command": [] if primary is None else list(primary.command),
            "return_code": None if primary is None else primary.return_code,
            "stdout": "" if primary is None else primary.stdout,
            "stderr": "" if primary is None else primary.stderr,
            "metadata": {
                "schema_version": VALIDATION_SCHEMA_VERSION,
                "stage": stage,
                "syntax_valid": status == "passed",
                "commands": [command.to_dict() for command in commands],
                "target_status": target_result.status,
                "target_objects": [str(path) for path in target_result.object_files],
                "target_library": (
                    None if target_result.library is None
                    else str(target_result.library)
                ),
                "failure_context": None if failure is None else dict(failure),
            },
        })

    @staticmethod
    def _write_linker(
        layout: TripletArtifacts,
        status: str,
        command: CommandResult,
        stage: str,
        failure: Mapping[str, str] | None,
    ) -> None:
        error_summary = None if failure is None else failure["error_summary"]
        layout.write_validation("linker", {
            "validator": "linker",
            "status": status,
            "errors": [] if status != "failed" else [error_summary],
            "warnings": [] if status != "unavailable" else [error_summary],
            "command": list(command.command),
            "return_code": command.return_code,
            "stdout": command.stdout,
            "stderr": command.stderr,
            "metadata": {
                "schema_version": VALIDATION_SCHEMA_VERSION,
                "stage": stage,
                "execution_status": command.status,
                "failure_context": None if failure is None else dict(failure),
            },
        })

    @staticmethod
    def _write_linker_skipped(
        layout: TripletArtifacts,
        stage: str,
        reason: str,
    ) -> None:
        layout.write_validation("linker", {
            "validator": "linker",
            "status": "skipped",
            "errors": [],
            "warnings": [reason],
            "command": [],
            "return_code": None,
            "stdout": "",
            "stderr": "",
            "metadata": {
                "schema_version": VALIDATION_SCHEMA_VERSION,
                "stage": stage,
                "reason": reason,
            },
        })

    @staticmethod
    def _append_compile_command(
        layout: TripletArtifacts,
        source: Path,
        output: Path,
        command: Sequence[str],
        working_directory: Path,
    ) -> None:
        path = layout.build / "compile_commands.json"
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            document = []
        records = document if isinstance(document, list) else []
        records.append({
            "directory": str(working_directory),
            "file": str(source),
            "output": str(output),
            "arguments": list(command),
        })
        layout.write_json(path, records)

    @staticmethod
    def _finish_build_manifest(
        layout: TripletArtifacts,
        *,
        status: str,
        harness_compile: CommandResult | None,
        link: CommandResult | None,
        fuzzer: Path | None,
    ) -> None:
        path = layout.build / "build.json"
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            document = {}
        manifest = dict(document) if isinstance(document, Mapping) else {}
        manifest["target_status"] = manifest.get("status")
        manifest["status"] = status
        manifest["success"] = status == "passed"
        manifest["harness_object"] = (
            None if harness_compile is None
            else str(layout.build.resolve() / "objects" / "harness.o")
        )
        manifest["harness_compile"] = (
            None if harness_compile is None else harness_compile.to_dict()
        )
        manifest["link"] = None if link is None else link.to_dict()
        manifest["fuzzer"] = None if fuzzer is None else str(fuzzer)
        layout.write_json(path, manifest)

    @staticmethod
    def _write_combined_diagnostics(
        layout: TripletArtifacts,
        commands: Sequence[CommandResult],
    ) -> None:
        for field in ("stdout", "stderr"):
            values = [getattr(command, field).rstrip("\n") for command in commands]
            text = "\n".join(value for value in values if value)
            layout.write_text(
                layout.build / f"{field}.txt", text + ("\n" if text else "")
            )


def _failure_result(
    status: str,
    failure: Mapping[str, str],
    validator: str,
) -> ValidationResult:
    metadata = {"validator": validator, **dict(failure)}
    if status == "unavailable":
        return ValidationResult(
            success=None,
            errors=(),
            warnings=(failure["error_summary"],),
            metadata=metadata,
            status="unavailable",
        )
    return ValidationResult(
        success=False,
        errors=(failure["error_summary"],),
        warnings=(),
        metadata=metadata,
        status="failed",
    )


def _target_failed_stage(
    result: TargetBuildResult,
    target: TargetBuildConfig,
) -> str:
    if len(result.commands) <= len(target.source_files):
        return "target_compile"
    return "target_archive"


def _unique_flags(*groups: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(flag for group in groups for flag in group))


def _bounded_tail(value: str, *, lines: int, characters: int) -> str:
    selected = "\n".join(value.splitlines()[-lines:])
    return selected[-characters:]


def _error_summary(stderr_tail: str) -> str:
    lines = [line.strip() for line in stderr_tail.splitlines() if line.strip()]
    for line in lines:
        if "error:" in line.lower():
            return line
    return lines[-1] if lines else ""


def _diagnostic_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
