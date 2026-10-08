"""Reproducible target build configuration for frozen Context plans."""
from __future__ import annotations
import math
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from .compiler_validation import CompilerConfig
from project_catalog import BuildRecipe, ProjectCatalog

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
    linker: str | None = None
    link_flags: tuple[str, ...] = ()
    provenance: str = "target_build_config"

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
        if self.linker is not None and (
            not isinstance(self.linker, str) or not self.linker.strip()
        ):
            raise ValueError("linker must be non-empty text when provided")
        if isinstance(self.link_flags, (str, bytes)):
            raise ValueError("link_flags must be a sequence of arguments")
        link_flags = tuple(self.link_flags)
        if any(not isinstance(flag, str) or not flag for flag in link_flags):
            raise ValueError("link_flags must contain non-empty strings")
        object.__setattr__(self, "link_flags", link_flags)

    @classmethod
    def from_recipe(cls, recipe: BuildRecipe) -> "TargetBuildConfig":
        return cls(
            project_root=recipe.project_root,
            source_files=recipe.source_files,
            header_files=recipe.header_files,
            include_paths=recipe.include_paths,
            compiler=recipe.compiler,
            archiver=recipe.archiver,
            compiler_flags=recipe.compiler_flags,
            archive_name=recipe.archive_name,
            timeout=recipe.timeout,
            linker=recipe.linker,
            link_flags=recipe.link_flags,
            provenance=recipe.provenance,
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        project_root: str | Path | None = None,
    ) -> "TargetBuildConfig":
        if not isinstance(value, Mapping):
            raise ValueError("target build config must be an object")
        recipe_value = value.get("recipe")
        if isinstance(recipe_value, Mapping):
            recipe = BuildRecipe.from_dict(recipe_value, project_root=project_root)
        else:
            recipe = BuildRecipe.from_dict(value, project_root=project_root)
        return cls.from_recipe(recipe)

    @classmethod
    def load(cls, path: str | Path, *, project_root: str | Path | None = None) -> "TargetBuildConfig":
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
            return cls.from_dict(document, project_root=project_root)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError(f"cannot load target build config: {type(error).__name__}") from error

    def to_recipe(self) -> BuildRecipe:
        return BuildRecipe(
            project_root=self.project_root,
            source_files=self.source_files,
            header_files=self.header_files,
            include_paths=self.include_paths,
            compiler=self.compiler,
            archiver=self.archiver,
            compiler_flags=self.compiler_flags,
            archive_name=self.archive_name,
            timeout=self.timeout,
            linker=self.linker,
            link_flags=self.link_flags,
            provenance=self.provenance,
        )

    @classmethod
    def for_simple_project(cls, project_root: str | Path) -> "TargetBuildConfig":
        """Inspect conventional project source roots and root-level implementations.

        Vendor, generated, build, and artifact trees are excluded from automatic
        discovery; callers can still provide an explicit configuration.
        """

        catalog = ProjectCatalog.discover(project_root)
        return cls.from_recipe(BuildRecipe.from_catalog(
            catalog, compiler="clang", archiver="ar",
            compiler_flags=("-std=c11",), archive_name="libsimple_target.a",
        ))

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
            "linker": self.linker,
            "link_flags": list(self.link_flags),
        }


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
