"""Configurable compiler validation for generated C harnesses."""

from __future__ import annotations

import math
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .artifacts import ArtifactStore
from .validation import VALIDATION_SCHEMA_VERSION, ValidationResult


LINK_VALID = "valid"
LINK_INVALID = "invalid"
LINK_UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class CompilerConfig:
    """Compiler/build settings kept outside the generation pipeline."""

    compiler: str = "clang"
    include_paths: tuple[Path, ...] = ()
    library_paths: tuple[Path, ...] = ()
    compiler_flags: tuple[str, ...] = ()
    link_flags: tuple[str, ...] = ()
    build_command: tuple[str, ...] | None = None
    working_directory: Path | None = None
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if not isinstance(self.compiler, str) or not self.compiler.strip():
            raise ValueError("compiler must be non-empty text")
        if (isinstance(self.timeout, bool)
                or not isinstance(self.timeout, (int, float))
                or not math.isfinite(self.timeout)
                or self.timeout <= 0):
            raise ValueError("timeout must be positive")
        object.__setattr__(self, "include_paths", _paths(
            self.include_paths, "include_paths"
        ))
        object.__setattr__(self, "library_paths", _paths(
            self.library_paths, "library_paths"
        ))
        object.__setattr__(self, "compiler_flags", _arguments(
            self.compiler_flags, "compiler_flags"
        ))
        object.__setattr__(self, "link_flags", _arguments(
            self.link_flags, "link_flags"
        ))
        if self.build_command is not None:
            command = _arguments(self.build_command, "build_command")
            if not command:
                raise ValueError("build_command must not be empty")
            object.__setattr__(self, "build_command", command)
        if self.working_directory is not None:
            object.__setattr__(self, "working_directory", Path(self.working_directory))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CompilerConfig":
        """Load config data while accepting a shell-like build command string."""

        if not isinstance(value, Mapping):
            raise ValueError("compiler config must be an object")
        build_command = value.get("build_command")
        if isinstance(build_command, str):
            build_command = tuple(shlex.split(build_command))
        elif build_command is not None:
            build_command = tuple(build_command)
        return cls(
            compiler=value.get("compiler", "clang"),
            include_paths=value.get("include_paths", ()),
            library_paths=value.get("library_paths", ()),
            compiler_flags=value.get("compiler_flags", ()),
            link_flags=value.get("link_flags", ()),
            build_command=build_command,
            working_directory=value.get("working_directory"),
            timeout=value.get("timeout", 30.0),
        )

    @property
    def has_link_configuration(self) -> bool:
        return bool(self.build_command or self.library_paths or self.link_flags)


class BuildAdapter:
    """Translate compiler config into argv without invoking a shell."""

    def object_command(
        self,
        source: Path,
        output: Path,
        config: CompilerConfig,
    ) -> tuple[str, ...]:
        """Compile one target source into an object without linking."""

        return (
            config.compiler,
            *config.compiler_flags,
            *_path_options("-I", config.include_paths),
            "-c",
            str(source),
            "-o",
            str(output),
        )

    def archive_command(
        self,
        objects: Sequence[Path],
        output: Path,
        *,
        archiver: str = "ar",
    ) -> tuple[str, ...]:
        """Create a static target archive from compiled objects."""

        if not archiver.strip():
            raise ValueError("archiver must be non-empty text")
        if not objects:
            raise ValueError("at least one object is required")
        return (archiver, "rcs", str(output), *(str(path) for path in objects))

    def objects_link_command(
        self,
        objects: Sequence[Path],
        output: Path,
        config: CompilerConfig,
    ) -> tuple[str, ...]:
        """Link precompiled objects with explicitly configured runtime flags."""

        if not objects:
            raise ValueError("at least one object is required")
        return (
            config.compiler,
            *(str(path) for path in objects),
            *_path_options("-L", config.library_paths),
            *config.link_flags,
            "-o",
            str(output),
        )

    def syntax_command(self, source: Path, config: CompilerConfig) -> tuple[str, ...]:
        return (
            config.compiler,
            *config.compiler_flags,
            *_path_options("-I", config.include_paths),
            "-fsyntax-only",
            str(source),
        )

    def link_command(
        self,
        source: Path,
        output: Path,
        config: CompilerConfig,
    ) -> tuple[str, ...] | None:
        if config.build_command is not None:
            substitutions = {
                "compiler": config.compiler,
                "source": str(source),
                "source_name": source.name,
                "source_dir": str(source.parent),
                "output": str(output),
            }
            try:
                return tuple(
                    argument.format_map(substitutions)
                    for argument in config.build_command
                )
            except (KeyError, ValueError) as error:
                raise ValueError(f"invalid build_command placeholder: {error}") from error
        if not config.has_link_configuration:
            return None
        return (
            config.compiler,
            *config.compiler_flags,
            *_path_options("-I", config.include_paths),
            str(source),
            *_path_options("-L", config.library_paths),
            *config.link_flags,
            "-o",
            str(output),
        )


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    stdout: str
    stderr: str
    return_code: int | None
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "status": self.status,
        }


Runner = Callable[..., subprocess.CompletedProcess[str]]


class CompilerValidator:
    """Run syntax and optional link validation and persist one validation record."""

    def __init__(
        self,
        config: CompilerConfig | None = None,
        *,
        build_adapter: BuildAdapter | None = None,
        runner: Runner = subprocess.run,
    ) -> None:
        self.config = config or CompilerConfig()
        self.build_adapter = build_adapter or BuildAdapter()
        self.runner = runner

    def validate(
        self,
        source: str | Path,
        *,
        validation_path: str | Path,
        output: str | Path | None = None,
        stage: str = "compiler",
    ) -> ValidationResult:
        source_path = Path(source).resolve()
        output_path = (
            Path(output).resolve()
            if output is not None
            else source_path.with_name(source_path.name + ".out")
        )
        errors: list[str] = []
        warnings: list[str] = []

        syntax_command = self.build_adapter.syntax_command(source_path, self.config)
        syntax = self._run(syntax_command)
        syntax_valid = syntax.status == "completed" and syntax.return_code == 0
        link: CommandResult | None = None
        link_validation = LINK_UNAVAILABLE
        validation_status = "passed"

        if not syntax_valid:
            if syntax.status == "unavailable":
                validation_status = "unavailable"
                warnings.append("compiler syntax validation unavailable")
            elif syntax.status == "completed":
                errors.append(
                    f"compiler syntax validation failed with return code "
                    f"{syntax.return_code}"
                )
            else:
                errors.append(f"compiler syntax validation {syntax.status}")
        else:
            try:
                link_command = self.build_adapter.link_command(
                    source_path, output_path, self.config
                )
            except ValueError as error:
                link_command = None
                warnings.append(f"link validation unavailable: {error}")
            if link_command is None:
                if not warnings:
                    warnings.append(
                        "link validation unavailable: no build or link configuration"
                    )
            else:
                link = self._run(link_command)
                if link.status != "completed":
                    warnings.append(f"link validation unavailable: {link.status}")
                elif link.return_code == 0:
                    link_validation = LINK_VALID
                else:
                    link_validation = LINK_INVALID
                    errors.append(
                        f"compiler link validation failed with return code "
                        f"{link.return_code}"
                    )

        primary = link or syntax
        metadata = {
            "schema_version": VALIDATION_SCHEMA_VERSION,
            "stage": stage,
            "validator": "compiler",
            "syntax_valid": syntax_valid,
            "link_validation": link_validation,
            "stdout": primary.stdout,
            "stderr": primary.stderr,
            "return_code": primary.return_code,
            "command": list(primary.command),
            "syntax": syntax.to_dict(),
            "link": None if link is None else link.to_dict(),
            "source": str(source_path),
            "output": str(output_path),
        }
        result = ValidationResult(
            success=(None if validation_status == "unavailable" else not errors),
            errors=tuple(errors),
            warnings=tuple(warnings),
            metadata=metadata,
            status=validation_status if not errors else "failed",
        )
        result.save(validation_path)
        return result

    def validate_triplet(
        self,
        source: str | Path,
        *,
        artifacts: str | Path,
        ft_id: str,
        output: str | Path | None = None,
        stage: str = "compiler",
        preserve_existing_linker: bool = True,
    ) -> ValidationResult:
        """Validate and persist isolated compiler/linker artifacts."""

        layout = ArtifactStore(Path(artifacts)).for_triplet(ft_id)
        result = self.validate(
            source,
            validation_path=layout.compiler_validation,
            output=output,
            stage=stage,
        )
        metadata = result.metadata
        syntax = metadata["syntax"]
        syntax_valid = bool(metadata["syntax_valid"])
        compiler_status = (
            "passed" if syntax_valid else
            "unavailable" if syntax["status"] == "unavailable" else
            "failed"
        )
        compiler_errors = list(result.errors) if compiler_status == "failed" else []
        compiler_warnings = (
            list(result.warnings) if compiler_status == "unavailable" else []
        )
        layout.write_validation("compiler", {
            "validator": "compiler",
            "status": compiler_status,
            "errors": compiler_errors,
            "warnings": compiler_warnings,
            "command": list(syntax["command"]),
            "return_code": syntax["return_code"],
            "stdout": syntax["stdout"],
            "stderr": syntax["stderr"],
            "metadata": {
                "schema_version": VALIDATION_SCHEMA_VERSION,
                "stage": stage,
                "source": metadata["source"],
                "syntax_valid": syntax_valid,
                "execution_status": syntax["status"],
            },
        })

        link_status = metadata["link_validation"]
        link = metadata["link"]
        if compiler_status != "passed":
            persisted_link_status = "skipped"
            link_errors: list[str] = []
            link_warnings = [
                "link validation skipped because compiler validation did not pass"
            ]
        elif link_status == LINK_VALID:
            persisted_link_status = "passed"
            link_errors = []
            link_warnings = []
        elif link_status == LINK_INVALID:
            persisted_link_status = "failed"
            link_errors = list(result.errors)
            link_warnings = []
        else:
            persisted_link_status = "unavailable"
            link_errors = []
            link_warnings = list(result.warnings)
        linker_document = {
            "validator": "linker",
            "status": persisted_link_status,
            "errors": link_errors,
            "warnings": link_warnings,
            "command": [] if link is None else list(link["command"]),
            "return_code": None if link is None else link["return_code"],
            "stdout": "" if link is None else link["stdout"],
            "stderr": "" if link is None else link["stderr"],
            "metadata": {
                "schema_version": VALIDATION_SCHEMA_VERSION,
                "stage": stage,
                "source": metadata["source"],
                "output": metadata["output"],
                "link_validation": link_status,
                "execution_status": None if link is None else link["status"],
            },
        }
        # A syntax-only compiler rerun must not overwrite an independently
        # persisted linker result. Create the initial unavailable record, but
        # only replace it when a link command actually ran.
        if (
            link is not None
            or not preserve_existing_linker
            or not layout.linker_validation.is_file()
        ):
            layout.write_validation("linker", linker_document)
        return result

    def _run(self, command: Sequence[str]) -> CommandResult:
        canonical = tuple(command)
        try:
            completed = self.runner(
                list(canonical),
                cwd=self.config.working_directory,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
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


def validate_compiler(
    source: str | Path,
    *,
    validation_path: str | Path,
    config: CompilerConfig | None = None,
    output: str | Path | None = None,
    stage: str = "compiler",
) -> ValidationResult:
    return CompilerValidator(config).validate(
        source,
        validation_path=validation_path,
        output=output,
        stage=stage,
    )


def _paths(values: Sequence[str | Path], field: str) -> tuple[Path, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field} must be a sequence of paths")
    result = tuple(Path(value) for value in values)
    if any(not str(value) for value in result):
        raise ValueError(f"{field} must contain non-empty paths")
    return result


def _arguments(values: Sequence[str], field: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field} must be a sequence of arguments")
    result = tuple(values)
    if any(not isinstance(value, str) or not value for value in result):
        raise ValueError(f"{field} must contain non-empty strings")
    return result


def _path_options(prefix: str, paths: Sequence[Path]) -> tuple[str, ...]:
    return tuple(f"{prefix}{path}" for path in paths)


def _diagnostic_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
