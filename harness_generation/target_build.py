"""Minimal, reproducible target build support for end-to-end validation."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Any, Callable, Sequence

from .artifacts import ArtifactStore
from .compiler_validation import BuildAdapter, CommandResult, CompilerConfig


BUILD_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class TargetBuildConfig:
    """Target sources and toolchain settings, independent of harness linking."""

    project_root: Path
    source_files: tuple[Path, ...]
    header_files: tuple[Path, ...] = ()
    include_paths: tuple[Path, ...] = ()
    compiler: str = "clang"
    archiver: str = "ar"
    compiler_flags: tuple[str, ...] = ("-std=c11",)
    archive_name: str = "libtarget.a"
    timeout: float = 30.0

    def __post_init__(self) -> None:
        root = Path(self.project_root).resolve()
        object.__setattr__(self, "project_root", root)
        object.__setattr__(
            self, "source_files", _owned_paths(root, self.source_files, "source_files")
        )
        object.__setattr__(
            self, "header_files", _owned_paths(root, self.header_files, "header_files")
        )
        object.__setattr__(
            self, "include_paths", _owned_paths(root, self.include_paths, "include_paths")
        )
        if not self.source_files:
            raise ValueError("source_files must not be empty")
        for field, value in (("compiler", self.compiler), ("archiver", self.archiver)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be non-empty text")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise ValueError("timeout must be positive")
        if (
            not isinstance(self.archive_name, str)
            or Path(self.archive_name).name != self.archive_name
            or not self.archive_name.endswith(".a")
        ):
            raise ValueError("archive_name must be a safe .a basename")
        if isinstance(self.compiler_flags, (str, bytes)):
            raise ValueError("compiler_flags must be a sequence of arguments")
        flags = tuple(self.compiler_flags)
        if any(not isinstance(flag, str) or not flag for flag in flags):
            raise ValueError("compiler_flags must contain non-empty strings")
        object.__setattr__(self, "compiler_flags", flags)

    @classmethod
    def for_simple_project(cls, project_root: str | Path) -> "TargetBuildConfig":
        """Inspect conventional project source roots and root-level implementations.

        Vendor, generated, build, and artifact trees are excluded from automatic
        discovery; callers can still provide an explicit configuration.
        """

        root = Path(project_root).resolve()
        ignored = {"build", "out", "vendor", "third_party", "generated", "artifacts"}
        candidates = []
        for path in (root / "src").rglob("*.c") if (root / "src").is_dir() else ():
            if not any(part.casefold() in ignored for part in path.relative_to(root).parts):
                candidates.append(path)
        for path in root.glob("*.c"):
            if path.name != "harness.c":
                candidates.append(path)
        sources = tuple(sorted(set(candidates)))
        headers = tuple(sorted(
            path for path in ((root / "include").rglob("*.h")
                              if (root / "include").is_dir() else ())
            if not any(part.casefold() in ignored for part in path.relative_to(root).parts)
        ))
        include_paths = tuple(
            path for path in ((root,) if any(path.parent == root for path in sources) else ())
            + ((root / "include",) if (root / "include").is_dir() else ())
        )
        return cls(
            project_root=root,
            source_files=sources,
            header_files=headers,
            include_paths=include_paths,
            compiler_flags=("-std=c11",),
            archive_name="libsimple_target.a",
        )

    @property
    def compiler_config(self) -> CompilerConfig:
        """Adapt target settings to the existing compiler abstraction."""

        return CompilerConfig(
            compiler=self.compiler,
            include_paths=self.include_paths,
            compiler_flags=self.compiler_flags,
            working_directory=self.project_root,
            timeout=self.timeout,
        )

    def validate_inputs(self) -> None:
        if not self.project_root.is_dir():
            raise ValueError(f"project root does not exist: {self.project_root}")
        for source in self.source_files:
            if not source.is_file():
                raise ValueError(f"target source does not exist: {source}")
        for header in self.header_files:
            if not header.is_file():
                raise ValueError(f"target header does not exist: {header}")
        for include in self.include_paths:
            if not include.is_dir():
                raise ValueError(f"include path does not exist: {include}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_root": str(self.project_root),
            "source_files": [str(path) for path in self.source_files],
            "header_files": [str(path) for path in self.header_files],
            "include_paths": [str(path) for path in self.include_paths],
            "compiler": self.compiler,
            "archiver": self.archiver,
            "compiler_flags": list(self.compiler_flags),
            "archive_name": self.archive_name,
            "timeout": self.timeout,
        }


@dataclass(frozen=True)
class TargetBuildResult:
    status: str
    output_directory: Path
    object_files: tuple[Path, ...]
    library: Path | None
    commands: tuple[CommandResult, ...]
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def success(self) -> bool:
        return self.status == "passed"

    def to_dict(self, *, config: TargetBuildConfig, ft_id: str) -> dict[str, Any]:
        return {
            "schema_version": BUILD_SCHEMA_VERSION,
            "ft_id": ft_id,
            "status": self.status,
            "success": self.success,
            "config": config.to_dict(),
            "output_directory": str(self.output_directory),
            "object_files": [str(path) for path in self.object_files],
            "library": None if self.library is None else str(self.library),
            "commands": [command.to_dict() for command in self.commands],
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "stdout": "stdout.txt",
            "stderr": "stderr.txt",
            "compile_commands": "compile_commands.json",
        }


Runner = Callable[..., subprocess.CompletedProcess[str]]


class TargetBuildAdapter:
    """Compile target objects and archive them under one FT artifact directory."""

    def __init__(
        self,
        *,
        build_adapter: BuildAdapter | None = None,
        runner: Runner = subprocess.run,
    ) -> None:
        self.build_adapter = build_adapter or BuildAdapter()
        self.runner = runner

    def build(
        self,
        config: TargetBuildConfig,
        *,
        artifacts: str | Path,
        ft_id: str,
    ) -> TargetBuildResult:
        config.validate_inputs()
        layout = ArtifactStore(Path(artifacts)).for_triplet(ft_id).ensure_build()
        output_directory = layout.build.resolve()
        object_root = output_directory / "objects"
        object_root.mkdir(parents=True, exist_ok=True)
        compiler_config = config.compiler_config

        objects = tuple(
            object_root / source.relative_to(config.project_root).with_suffix(".o")
            for source in config.source_files
        )
        compile_commands: list[dict[str, Any]] = []
        commands: list[CommandResult] = []
        errors: list[str] = []
        warnings: list[str] = []

        for source, object_file in zip(config.source_files, objects):
            object_file.parent.mkdir(parents=True, exist_ok=True)
            object_file.unlink(missing_ok=True)
            command = self.build_adapter.object_command(
                source, object_file, compiler_config
            )
            compile_commands.append({
                "directory": str(config.project_root),
                "file": str(source),
                "output": str(object_file),
                "arguments": list(command),
            })
            result = self._run(command, config)
            commands.append(result)
            if result.status == "unavailable":
                errors.append(f"target compiler unavailable: {result.stderr}")
                break
            if result.status != "completed":
                errors.append(f"target compilation {result.status}: {source.name}")
                break
            if result.return_code != 0:
                errors.append(
                    f"target compilation failed for {source.name} with return code "
                    f"{result.return_code}"
                )
                break
            if not object_file.is_file():
                errors.append(f"target compiler did not create object: {object_file}")
                break

        library_path = output_directory / config.archive_name
        library: Path | None = None
        if not errors:
            library_path.unlink(missing_ok=True)
            archive_command = self.build_adapter.archive_command(
                objects, library_path, archiver=config.archiver
            )
            archive_result = self._run(archive_command, config)
            commands.append(archive_result)
            if archive_result.status == "unavailable":
                errors.append(f"target archiver unavailable: {archive_result.stderr}")
            elif archive_result.status != "completed":
                errors.append(f"target archiving {archive_result.status}")
            elif archive_result.return_code != 0:
                errors.append(
                    "target archiving failed with return code "
                    f"{archive_result.return_code}"
                )
            elif not library_path.is_file():
                errors.append(f"target archiver did not create library: {library_path}")
            else:
                library = library_path

        status = "passed"
        if errors:
            status = (
                "unavailable"
                if any(command.status == "unavailable" for command in commands)
                else "failed"
            )
        result = TargetBuildResult(
            status=status,
            output_directory=output_directory,
            object_files=tuple(path for path in objects if path.is_file()),
            library=library,
            commands=tuple(commands),
            errors=tuple(errors),
            warnings=tuple(warnings),
        )
        layout.write_json(output_directory / "compile_commands.json", compile_commands)
        layout.write_text(
            output_directory / "stdout.txt",
            _combined_diagnostics(commands, "stdout"),
        )
        layout.write_text(
            output_directory / "stderr.txt",
            _combined_diagnostics(commands, "stderr"),
        )
        layout.write_json(
            output_directory / "build.json",
            result.to_dict(config=config, ft_id=ft_id),
        )
        return result

    def _run(
        self,
        command: Sequence[str],
        config: TargetBuildConfig,
    ) -> CommandResult:
        canonical = tuple(command)
        try:
            completed = self.runner(
                list(canonical),
                cwd=config.project_root,
                capture_output=True,
                text=True,
                timeout=config.timeout,
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


def _owned_paths(
    root: Path,
    values: Sequence[str | Path],
    field: str,
) -> tuple[Path, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field} must be a sequence of paths")
    result: list[Path] = []
    for value in values:
        path = Path(value)
        resolved = (path if path.is_absolute() else root / path).resolve()
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise ValueError(f"{field} contains a path outside project_root") from error
        result.append(resolved)
    return tuple(sorted(result, key=lambda path: path.as_posix()))


def _combined_diagnostics(commands: Sequence[CommandResult], field: str) -> str:
    sections = []
    for command in commands:
        value = getattr(command, field)
        if value:
            sections.append(value.rstrip("\n"))
    return "\n".join(sections) + ("\n" if sections else "")


def _diagnostic_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
