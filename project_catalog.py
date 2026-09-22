"""Read-only project source facts and reproducible target build recipes."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


CATALOG_SCHEMA_VERSION = 1
RECIPE_SCHEMA_VERSION = 1
DEFAULT_IGNORED_DIRECTORIES = (
    ".git", "build", "out", "cmake-build*", "third_party", "vendor",
    "external", "generated", "artifacts",
)
DEFAULT_SOURCE_SUFFIXES = (".c",)
DEFAULT_HEADER_SUFFIXES = (".h", ".hh", ".hpp")


def _normalize_patterns(values: Iterable[str]) -> tuple[str, ...]:
    result = tuple(dict.fromkeys(str(value) for value in values))
    if any(not value for value in result):
        raise ValueError("directory patterns must be non-empty strings")
    return result


def _inside_ignored(path: Path, root: Path, patterns: tuple[str, ...]) -> bool:
    import fnmatch

    return any(
        fnmatch.fnmatch(part, pattern)
        for part in path.relative_to(root).parts[:-1]
        for pattern in patterns
    )


def _owned_paths(root: Path, values: Iterable[str | Path], field: str) -> tuple[Path, ...]:
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
    return tuple(sorted(set(result), key=lambda item: item.as_posix()))


@dataclass(frozen=True)
class ProjectCatalog:
    """Deterministic, read-only facts about project-owned source paths.

    The catalog describes files that exist in the project. It does not claim that
    every source is part of a target build; that distinction belongs to
    :class:`BuildRecipe`.
    """

    project_root: Path
    sources: tuple[Path, ...]
    headers: tuple[Path, ...] = ()
    include_paths: tuple[Path, ...] = ()
    ignored_directories: tuple[str, ...] = DEFAULT_IGNORED_DIRECTORIES
    source_suffixes: tuple[str, ...] = DEFAULT_SOURCE_SUFFIXES
    header_suffixes: tuple[str, ...] = DEFAULT_HEADER_SUFFIXES
    provenance: str = "directory_scan"

    def __post_init__(self) -> None:
        root = Path(self.project_root).resolve()
        object.__setattr__(self, "project_root", root)
        object.__setattr__(self, "ignored_directories", _normalize_patterns(self.ignored_directories))
        object.__setattr__(self, "source_suffixes", tuple(sorted(set(self.source_suffixes))))
        object.__setattr__(self, "header_suffixes", tuple(sorted(set(self.header_suffixes))))
        object.__setattr__(self, "sources", _owned_paths(root, self.sources, "sources"))
        object.__setattr__(self, "headers", _owned_paths(root, self.headers, "headers"))
        object.__setattr__(self, "include_paths", _owned_paths(root, self.include_paths, "include_paths"))
        if not isinstance(self.provenance, str) or not self.provenance:
            raise ValueError("catalog provenance must be non-empty text")

    @classmethod
    def discover(
        cls,
        project_root: str | Path,
        *,
        ignored_directories: Iterable[str] = DEFAULT_IGNORED_DIRECTORIES,
        source_suffixes: Iterable[str] = DEFAULT_SOURCE_SUFFIXES,
        header_suffixes: Iterable[str] = DEFAULT_HEADER_SUFFIXES,
    ) -> "ProjectCatalog":
        root = Path(project_root).resolve()
        if not root.is_dir():
            raise ValueError(f"project root does not exist: {root}")
        ignored = _normalize_patterns(ignored_directories)
        source_exts = tuple(sorted(set(str(value).lower() for value in source_suffixes)))
        header_exts = tuple(sorted(set(str(value).lower() for value in header_suffixes)))
        files = tuple(
            path for path in sorted(root.rglob("*"), key=lambda item: item.as_posix())
            if path.is_file() and not _inside_ignored(path, root, ignored)
        )
        sources = tuple(
            path for path in files
            if path.suffix.lower() in source_exts and path.name != "harness.c"
        )
        headers = tuple(path for path in files if path.suffix.lower() in header_exts)
        include_paths: list[Path] = []
        include = root / "include"
        if include.is_dir() and not _inside_ignored(include / "placeholder.h", root, ignored):
            include_paths.append(include)
        if any(path.parent == root for path in sources):
            include_paths.insert(0, root)
        return cls(
            root, sources, headers, tuple(include_paths), ignored,
            source_exts, header_exts,
        )

    @property
    def relative_sources(self) -> tuple[str, ...]:
        return tuple(path.relative_to(self.project_root).as_posix() for path in self.sources)

    @property
    def relative_headers(self) -> tuple[str, ...]:
        return tuple(path.relative_to(self.project_root).as_posix() for path in self.headers)

    @property
    def relative_include_paths(self) -> tuple[str, ...]:
        return tuple(path.relative_to(self.project_root).as_posix() for path in self.include_paths)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CATALOG_SCHEMA_VERSION,
            "project_root": str(self.project_root),
            "sources": list(self.relative_sources),
            "headers": list(self.relative_headers),
            "include_paths": list(self.relative_include_paths),
            "ignored_directories": list(self.ignored_directories),
            "source_suffixes": list(self.source_suffixes),
            "header_suffixes": list(self.header_suffixes),
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class BuildRecipe:
    """The exact target compilation inputs and toolchain identity."""

    project_root: Path
    source_files: tuple[Path, ...]
    header_files: tuple[Path, ...] = ()
    include_paths: tuple[Path, ...] = ()
    compiler: str = "clang"
    archiver: str = "ar"
    compiler_flags: tuple[str, ...] = ("-std=c11",)
    archive_name: str = "libtarget.a"
    linker: str | None = None
    link_flags: tuple[str, ...] = ()
    timeout: float = 30.0
    provenance: str = "catalog"

    def __post_init__(self) -> None:
        root = Path(self.project_root).resolve()
        object.__setattr__(self, "project_root", root)
        for field in ("source_files", "header_files", "include_paths"):
            object.__setattr__(self, field, _owned_paths(root, getattr(self, field), field))
        if not self.source_files:
            raise ValueError("source_files must not be empty")
        for field in ("compiler", "archiver"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be non-empty text")
        if self.linker is not None and (not isinstance(self.linker, str) or not self.linker.strip()):
            raise ValueError("linker must be non-empty text when provided")
        if Path(self.archive_name).name != self.archive_name or not self.archive_name.endswith(".a"):
            raise ValueError("archive_name must be a safe .a basename")
        object.__setattr__(self, "compiler_flags", _arguments(self.compiler_flags, "compiler_flags"))
        object.__setattr__(self, "link_flags", _arguments(self.link_flags, "link_flags"))
        if not isinstance(self.timeout, (int, float)) or isinstance(self.timeout, bool) or self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if not isinstance(self.provenance, str) or not self.provenance:
            raise ValueError("recipe provenance must be non-empty text")

    @classmethod
    def from_catalog(
        cls,
        catalog: ProjectCatalog,
        *,
        compiler: str = "clang",
        archiver: str = "ar",
        compiler_flags: Iterable[str] = ("-std=c11",),
        archive_name: str = "libtarget.a",
        linker: str | None = None,
        link_flags: Iterable[str] = (),
        timeout: float = 30.0,
    ) -> "BuildRecipe":
        return cls(
            project_root=catalog.project_root,
            source_files=catalog.sources,
            header_files=catalog.headers,
            include_paths=catalog.include_paths,
            compiler=compiler,
            archiver=archiver,
            compiler_flags=tuple(compiler_flags),
            archive_name=archive_name,
            linker=linker,
            link_flags=tuple(link_flags),
            timeout=timeout,
            provenance=f"catalog:{catalog.provenance}",
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        project_root: str | Path | None = None,
    ) -> "BuildRecipe":
        """Load a persisted recipe without weakening path or identity checks."""

        if not isinstance(value, Mapping):
            raise ValueError("build recipe must be an object")
        if value.get("schema_version") != RECIPE_SCHEMA_VERSION:
            raise ValueError("unsupported build recipe schema_version")
        supplied_root = value.get("project_root")
        root_value = project_root if project_root is not None else supplied_root
        if not isinstance(root_value, (str, Path)) or not str(root_value):
            raise ValueError("build recipe requires project_root")
        root = Path(root_value).resolve()
        if supplied_root is not None and Path(supplied_root).resolve() != root:
            raise ValueError("build recipe project_root does not match loader root")
        try:
            recipe = cls(
                project_root=root,
                source_files=value.get("source_files", ()),
                header_files=value.get("header_files", ()),
                include_paths=value.get("include_paths", ()),
                compiler=value.get("compiler", "clang"),
                archiver=value.get("archiver", "ar"),
                compiler_flags=value.get("compiler_flags", ("-std=c11",)),
                archive_name=value.get("archive_name", "libtarget.a"),
                linker=value.get("linker"),
                link_flags=value.get("link_flags", ()),
                timeout=value.get("timeout", 30.0),
                provenance=value.get("provenance", "persisted_recipe"),
            )
        except (TypeError, ValueError) as error:
            raise ValueError(f"invalid build recipe: {type(error).__name__}") from error
        supplied_identity = value.get("identity")
        if supplied_identity is not None and supplied_identity != recipe.identity:
            raise ValueError("build recipe identity does not match its contents")
        return recipe

    @property
    def identity(self) -> str:
        payload = json.dumps(self._identity_document(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _identity_document(self) -> dict[str, Any]:
        relative = lambda paths: [path.relative_to(self.project_root).as_posix() for path in paths]
        return {
            "schema_version": RECIPE_SCHEMA_VERSION,
            "source_files": relative(self.source_files),
            "header_files": relative(self.header_files),
            "include_paths": relative(self.include_paths),
            "compiler": self.compiler,
            "archiver": self.archiver,
            "compiler_flags": list(self.compiler_flags),
            "archive_name": self.archive_name,
            "linker": self.linker,
            "link_flags": list(self.link_flags),
            "timeout": self.timeout,
            "provenance": self.provenance,
        }

    def to_dict(self) -> dict[str, Any]:
        document = {"project_root": str(self.project_root), **self._identity_document()}
        document["identity"] = self.identity
        return document

    def target_compile_config(self, extra_flags: Iterable[str] = ()) -> Any:
        from harness_generation.compiler_validation import CompilerConfig
        return CompilerConfig(
            compiler=self.compiler,
            include_paths=self.include_paths,
            compiler_flags=tuple(self.compiler_flags) + tuple(extra_flags),
            working_directory=self.project_root,
            timeout=self.timeout,
        )

    def harness_compile_config(
        self, language: str = "c++", extra_flags: Iterable[str] = (),
        *, compiler: str | None = None,
    ) -> Any:
        from harness_generation.compiler_validation import CompilerConfig
        selected = compiler or ("clang++" if language == "c++" else self.compiler)
        return CompilerConfig(
            compiler=selected,
            include_paths=self.include_paths,
            compiler_flags=tuple(extra_flags),
            working_directory=self.project_root,
            timeout=self.timeout,
        )

    def link_config(self, extra_flags: Iterable[str] = ()) -> Any:
        from harness_generation.compiler_validation import CompilerConfig
        return CompilerConfig(
            compiler=self.linker or self.compiler,
            link_flags=tuple(self.link_flags) + tuple(extra_flags),
            working_directory=self.project_root,
            timeout=self.timeout,
        )


def _arguments(values: Iterable[str], field: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field} must be a sequence of arguments")
    result = tuple(values)
    if any(not isinstance(value, str) or not value for value in result):
        raise ValueError(f"{field} must contain non-empty strings")
    return result
