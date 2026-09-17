"""LLVM source-based coverage scoped strictly to target source files."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Callable, Mapping, Sequence

from .artifacts import ArtifactStore
from .compiler_validation import BuildAdapter, CommandResult, CompilerConfig
from .fuzzer_build import DEFAULT_FUZZER_COMPILE_FLAGS, DEFAULT_FUZZER_LINK_FLAGS
from .records import write_json
from .target_build import TargetBuildConfig


TARGET_COVERAGE_SCHEMA_VERSION = 1
_PROFILE_FLAGS = ("-fprofile-instr-generate", "-fcoverage-mapping")
_DEFAULT_SEEDS = (
    ("empty", b""),
    ("zero", b"\x00"),
    ("small", b"\x00\x01\xff"),
)


@dataclass(frozen=True)
class TargetCoverageConfig:
    """Bounded target-only coverage settings.

    ``compile_target_sources=False`` supports benchmark harnesses that include
    the target implementation directly, while still filtering coverage to the
    configured target source files.
    """

    runs: int = 64
    timeout: float = 30.0
    compiler_flags: tuple[str, ...] = DEFAULT_FUZZER_COMPILE_FLAGS
    link_flags: tuple[str, ...] = DEFAULT_FUZZER_LINK_FLAGS
    llvm_profdata: str = "llvm-profdata"
    llvm_cov: str = "llvm-cov"
    compile_target_sources: bool = True

    def __post_init__(self) -> None:
        if type(self.runs) is not int or self.runs < 1:
            raise ValueError("runs must be a positive integer")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise ValueError("timeout must be positive")
        for field in ("compiler_flags", "link_flags"):
            values = getattr(self, field)
            if isinstance(values, (str, bytes)) or any(
                not isinstance(value, str) or not value for value in values
            ):
                raise ValueError(f"{field} must contain non-empty arguments")
            object.__setattr__(self, field, tuple(values))
        for field in ("llvm_profdata", "llvm_cov"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be non-empty text")


@dataclass(frozen=True)
class TargetCoverageResult:
    status: str
    artifact_directory: Path
    summary: Mapping[str, Any]
    commands: tuple[CommandResult, ...]
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def success(self) -> bool:
        return self.status == "passed"


Runner = Callable[..., subprocess.CompletedProcess[str]]


class TargetCoverageCollector:
    """Build and run a coverage-instrumented fuzzer, then filter to target code."""

    def __init__(
        self,
        config: TargetCoverageConfig | None = None,
        *,
        build_adapter: BuildAdapter | None = None,
        runner: Runner = subprocess.run,
    ) -> None:
        self.config = config or TargetCoverageConfig()
        self.build_adapter = build_adapter or BuildAdapter()
        self.runner = runner

    def measure(
        self,
        harness: str | Path,
        target: TargetBuildConfig,
        *,
        artifacts: str | Path,
        ft_id: str,
        corpus: str | Path | None = None,
    ) -> TargetCoverageResult:
        target.validate_inputs()
        layout = ArtifactStore(Path(artifacts)).for_triplet(ft_id)
        attempt, directory = layout.next_coverage_run()
        directory = directory.resolve()
        objects = directory / "objects"
        objects.mkdir()
        corpus_directory = directory / "corpus"
        corpus_directory.mkdir()
        _prepare_corpus(corpus_directory, corpus)

        started_at = datetime.now(timezone.utc)
        commands: list[CommandResult] = []
        errors: list[str] = []
        warnings: list[str] = []
        compiler = _tool_path(target.compiler)
        profdata_tool = _tool_path(self.config.llvm_profdata)
        cov_tool = _tool_path(self.config.llvm_cov)
        missing = [
            name for name, path in (
                (target.compiler, compiler),
                (self.config.llvm_profdata, profdata_tool),
                (self.config.llvm_cov, cov_tool),
            ) if path is None
        ]
        tool_error = (
            "target coverage unavailable: missing " + ", ".join(missing)
            if missing else None
        )
        if tool_error is not None:
            summary = self._summary(
                ft_id, attempt, "unavailable", target, started_at,
                errors=(), warnings=(tool_error,), command_count=0,
            )
            _persist_summary(directory, summary, commands)
            return TargetCoverageResult(
                "unavailable", directory, summary, (), warnings=(tool_error,)
            )

        compile_config = CompilerConfig(
            compiler=target.compiler,
            include_paths=target.include_paths,
            compiler_flags=_unique_flags(
                target.compiler_flags, self.config.compiler_flags, _PROFILE_FLAGS
            ),
            working_directory=target.project_root,
            timeout=self.config.timeout,
        )
        object_files: list[Path] = []
        if self.config.compile_target_sources:
            for source in target.source_files:
                output = objects / source.relative_to(target.project_root).with_suffix(".o")
                output.parent.mkdir(parents=True, exist_ok=True)
                result = self._run(
                    self.build_adapter.object_command(source, output, compile_config),
                    cwd=target.project_root,
                )
                commands.append(result)
                if not _command_passed(result, output):
                    errors.append(_failure("target_compile", source, result))
                    break
                object_files.append(output)

        harness_path = Path(harness).resolve()
        harness_object = objects / "harness.o"
        if not errors:
            result = self._run(
                self.build_adapter.object_command(
                    harness_path, harness_object, compile_config
                ),
                cwd=target.project_root,
            )
            commands.append(result)
            if not _command_passed(result, harness_object):
                errors.append(_failure("harness_compile", harness_path, result))
            else:
                object_files.append(harness_object)

        executable = directory / "coverage_fuzzer"
        if not errors:
            link_config = CompilerConfig(
                compiler=target.compiler,
                link_flags=_unique_flags(self.config.link_flags, _PROFILE_FLAGS),
                working_directory=target.project_root,
                timeout=self.config.timeout,
            )
            result = self._run(
                self.build_adapter.objects_link_command(
                    tuple(object_files), executable, link_config
                ),
                cwd=target.project_root,
            )
            commands.append(result)
            if not _command_passed(result, executable):
                errors.append(_failure("link", executable, result))

        profraw = directory / "default.profraw"
        if not errors:
            command = (
                str(executable),
                f"-runs={self.config.runs}",
                "-seed=1",
                str(corpus_directory),
            )
            result = self._run(
                command,
                cwd=directory,
                env={**os.environ, "LLVM_PROFILE_FILE": str(profraw)},
            )
            commands.append(result)
            if result.status != "completed" or result.return_code != 0:
                errors.append(_failure("coverage_run", executable, result))
            elif not profraw.is_file():
                errors.append("coverage_run did not create default.profraw")

        profdata = directory / "default.profdata"
        if not errors:
            result = self._run(
                (str(profdata_tool), "merge", "-sparse", str(profraw),
                 "-o", str(profdata)),
                cwd=directory,
            )
            commands.append(result)
            if not _command_passed(result, profdata):
                errors.append(_failure("profdata_merge", profdata, result))

        export: dict[str, Any] | None = None
        if not errors:
            export_path = directory / "coverage_export.json"
            result = self._run(
                (
                    str(cov_tool),
                    "export",
                    str(executable),
                    f"-instr-profile={profdata}",
                    "-format=text",
                ),
                cwd=directory,
            )
            commands.append(result)
            if result.status != "completed" or result.return_code != 0:
                errors.append(_failure("llvm_cov_export", executable, result))
            else:
                try:
                    export = json.loads(result.stdout)
                except json.JSONDecodeError as error:
                    errors.append(f"llvm_cov_export returned invalid JSON: {error}")
                else:
                    write_json(export_path, export, sort_keys=True, allow_nan=False)

        status = "passed" if not errors else "failed"
        summary = self._summary(
            ft_id, attempt, status, target, started_at,
            errors=tuple(errors), warnings=tuple(warnings),
            command_count=len(commands),
            export=export,
            executable=executable if executable.is_file() else None,
            profraw=profraw if profraw.is_file() else None,
            profdata=profdata if profdata.is_file() else None,
        )
        _persist_summary(directory, summary, commands)
        return TargetCoverageResult(
            status, directory, summary, tuple(commands),
            errors=tuple(errors), warnings=tuple(warnings),
        )

    def _run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        canonical = tuple(command)
        try:
            completed = self.runner(
                list(canonical),
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as error:
            return CommandResult(
                canonical, _text(error.stdout), _text(error.stderr), None, "timed_out"
            )
        except OSError as error:
            return CommandResult(canonical, "", str(error), None, "unavailable")
        return CommandResult(
            canonical, _text(completed.stdout), _text(completed.stderr),
            completed.returncode, "completed",
        )

    def _summary(
        self,
        ft_id: str,
        attempt: int,
        status: str,
        target: TargetBuildConfig,
        started_at: datetime,
        *,
        errors: Sequence[str],
        warnings: Sequence[str],
        command_count: int,
        export: Mapping[str, Any] | None = None,
        executable: Path | None = None,
        profraw: Path | None = None,
        profdata: Path | None = None,
    ) -> dict[str, Any]:
        target_files = tuple(path.resolve() for path in target.source_files)
        target_only = target_only_summary(export or {}, target_files)
        finished_at = datetime.now(timezone.utc)
        return {
            "schema_version": TARGET_COVERAGE_SCHEMA_VERSION,
            "ft_id": ft_id,
            "attempt": attempt,
            "status": status,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "runs": self.config.runs,
            "scope": "target_code",
            "target_files": [str(path) for path in target_files],
            "compile_target_sources": self.config.compile_target_sources,
            "executable": None if executable is None else str(executable),
            "profraw": None if profraw is None else str(profraw),
            "profdata": None if profdata is None else str(profdata),
            "command_count": command_count,
            "target_only": target_only,
            "errors": list(errors),
            "warnings": list(warnings),
        }


def target_only_summary(
    export: Mapping[str, Any],
    target_files: Sequence[str | Path],
) -> dict[str, Any]:
    """Extract target-file-only coverage totals from an ``llvm-cov export`` JSON."""

    targets = tuple(Path(path).resolve() for path in target_files)
    matched_files: list[dict[str, Any]] = []
    aggregate: dict[str, dict[str, int | float]] = {}
    functions: list[dict[str, Any]] = []
    for section in export.get("data", []) if isinstance(export, Mapping) else []:
        if not isinstance(section, Mapping):
            continue
        file_indexes: set[int] = set()
        for index, file_entry in enumerate(section.get("files", [])):
            if not isinstance(file_entry, Mapping):
                continue
            filename = file_entry.get("filename")
            if not isinstance(filename, str) or not _is_target_file(filename, targets):
                continue
            file_indexes.add(index)
            summary = _coverage_summary(file_entry.get("summary", {}))
            matched_files.append({"filename": filename, "summary": summary})
            _merge_totals(aggregate, summary)
        for function in section.get("functions", []):
            if not isinstance(function, Mapping):
                continue
            filenames = [
                value for value in function.get("filenames", [])
                if isinstance(value, str) and _is_target_file(value, targets)
            ]
            if not filenames:
                regions = function.get("regions", [])
                indexes = {
                    region[0] for region in regions
                    if isinstance(region, list) and region
                    and isinstance(region[0], int)
                }
                if not indexes.intersection(file_indexes):
                    continue
            functions.append({
                "name": function.get("name"),
                "count": function.get("count"),
                "filenames": filenames,
            })
    return {
        "files": sorted(matched_files, key=lambda item: str(item["filename"])),
        "totals": _finalize_totals(aggregate),
        "functions": sorted(
            functions,
            key=lambda item: (str(item.get("name")), str(item.get("filenames"))),
        ),
        "entered_functions": sorted(
            str(function.get("name"))
            for function in functions
            if isinstance(function.get("name"), str)
            and isinstance(function.get("count"), int)
            and function["count"] > 0
        ),
    }


def _coverage_summary(value: Any) -> dict[str, dict[str, int | float]]:
    summary: dict[str, dict[str, int | float]] = {}
    if not isinstance(value, Mapping):
        return summary
    for key, data in value.items():
        if not isinstance(key, str) or not isinstance(data, Mapping):
            continue
        count = data.get("count")
        covered = data.get("covered")
        if isinstance(count, int) and isinstance(covered, int):
            summary[key] = {
                "count": count,
                "covered": covered,
                "percent": round((covered / count * 100.0), 4) if count else 0.0,
            }
    return summary


def _merge_totals(
    aggregate: dict[str, dict[str, int | float]],
    summary: Mapping[str, Mapping[str, int | float]],
) -> None:
    for key, data in summary.items():
        current = aggregate.setdefault(key, {"count": 0, "covered": 0})
        current["count"] = int(current["count"]) + int(data.get("count", 0))
        current["covered"] = int(current["covered"]) + int(data.get("covered", 0))


def _finalize_totals(
    aggregate: Mapping[str, Mapping[str, int | float]],
) -> dict[str, dict[str, int | float]]:
    result: dict[str, dict[str, int | float]] = {}
    for key in sorted(aggregate):
        count = int(aggregate[key].get("count", 0))
        covered = int(aggregate[key].get("covered", 0))
        result[key] = {
            "count": count,
            "covered": covered,
            "percent": round((covered / count * 100.0), 4) if count else 0.0,
        }
    return result


def latest_target_coverage_summary(coverage_root: str | Path) -> Path | None:
    root = Path(coverage_root)
    if root.is_file():
        return root
    if not root.is_dir():
        return None
    candidates = sorted(
        path for path in root.glob("run_*/target_coverage.json") if path.is_file()
    )
    return candidates[-1] if candidates else None


def _persist_summary(
    directory: Path,
    summary: Mapping[str, Any],
    commands: Sequence[CommandResult],
) -> None:
    write_json(directory / "target_coverage.json", summary, sort_keys=True, allow_nan=False)
    write_json(
        directory / "commands.json",
        [command.to_dict() for command in commands],
        sort_keys=True,
        allow_nan=False,
    )
    (directory / "stdout.txt").write_text(
        "\n".join(command.stdout.rstrip("\n") for command in commands if command.stdout)
        + ("\n" if any(command.stdout for command in commands) else ""),
        encoding="utf-8",
    )
    (directory / "stderr.txt").write_text(
        "\n".join(command.stderr.rstrip("\n") for command in commands if command.stderr)
        + ("\n" if any(command.stderr for command in commands) else ""),
        encoding="utf-8",
    )


def _prepare_corpus(destination: Path, corpus: str | Path | None) -> None:
    for name, data in _DEFAULT_SEEDS:
        (destination / name).write_bytes(data)
    if corpus is None:
        return
    source = Path(corpus).resolve()
    if source.is_file():
        shutil.copy2(source, destination / source.name)
    elif source.is_dir():
        for path in sorted(item for item in source.iterdir() if item.is_file()):
            shutil.copy2(path, destination / path.name)
    else:
        raise ValueError(f"corpus path does not exist: {source}")


def _tool_path(tool: str) -> str | None:
    direct = shutil.which(tool)
    if direct is not None:
        return direct
    for version in ("20", "19", "18", "17", "16", "15", "14"):
        candidate = shutil.which(f"{tool}-{version}")
        if candidate is not None:
            return candidate
    return None


def _unique_flags(*groups: Sequence[str]) -> tuple[str, ...]:
    result: list[str] = []
    for group in groups:
        for value in group:
            if value not in result:
                result.append(value)
    return tuple(result)


def _command_passed(result: CommandResult, output: Path) -> bool:
    return (
        result.status == "completed"
        and result.return_code == 0
        and output.is_file()
    )


def _failure(stage: str, path: Path, result: CommandResult) -> str:
    if result.status == "completed":
        return f"{stage} failed for {path.name} with return code {result.return_code}"
    return f"{stage} {result.status} for {path.name}"


def _is_target_file(filename: str, targets: Sequence[Path]) -> bool:
    candidate = Path(filename)
    resolved = candidate.resolve() if candidate.is_absolute() else candidate.resolve()
    for target in targets:
        if resolved == target:
            return True
        try:
            if candidate.is_absolute() and candidate.resolve() == target:
                return True
        except OSError:
            pass
        if candidate.as_posix() == target.as_posix() or candidate.name == target.name:
            return True
    return False


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
