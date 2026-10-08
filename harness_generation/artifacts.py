"""Artifact paths for the source-grounded HG chain."""

from __future__ import annotations

from dataclasses import dataclass

import json

from pathlib import Path

import re

from .records import write_json

from .entry_candidates import CandidateCatalog



@dataclass(frozen=True)

class ArtifactStore:

    """Paths for parser, Candidate, Slice, Minimal FT and Context stages."""

    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root))


    @property
    def functions(self) -> Path:
        return self.root / "functions.json"


    @property
    def annotations(self) -> Path:
        return self.root / "annotations.json"


    @property
    def flows(self) -> Path:
        return self.root / "flows.json"


    @property
    def sfg(self) -> Path:
        return self.root / "sfg.json"


    @property
    def candidate_discovery_directory(self) -> Path:
        return self.root / "candidate_discovery"


    @property
    def entry_candidates(self) -> Path:
        """Entry hypotheses; distinct from Phase 1's legacy candidates.json."""
        return self.candidate_discovery_directory / "candidates.json"


    @property
    def validated_candidates(self) -> Path:
        return self.candidate_discovery_directory / "validated_candidates.json"


    @property
    def candidate_agent_runs(self) -> Path:
        return self.candidate_discovery_directory / "agent_runs"


    def candidate_agent_run(self, candidate_id: str) -> Path:
        if not re.fullmatch(r"candidate_[0-9a-f]{24}", candidate_id):
            raise ValueError("invalid candidate run ID")
        return self.candidate_agent_runs / candidate_id


    @property
    def semantic_slices_directory(self) -> Path:
        return self.root / "semantic_slices"


    def semantic_slice_run(self, candidate_id: str) -> Path:
        if not re.fullmatch(r"candidate_[0-9a-f]{24}", candidate_id):
            raise ValueError("invalid semantic slice ID")
        return self.semantic_slices_directory / candidate_id


    @property
    def minimal_fts_directory(self) -> Path:
        return self.root / "minimal_fts"


    @property
    def minimal_ft_catalog(self) -> Path:
        return self.minimal_fts_directory / "catalog.json"


    def minimal_ft_run(self, ft_id: str) -> Path:
        if not isinstance(ft_id, str) or not re.fullmatch(r"ft_[A-Za-z0-9_]{1,48}_[0-9a-f]{24}", ft_id):
            raise ValueError("invalid minimal FT ID")
        path = self.minimal_fts_directory / ft_id
        _require_owned_path(path, self.root)
        return path


    @property
    def target_build(self) -> Path:
        return self.root / "target_build.json"


    def write_candidate_catalog(self, catalog: CandidateCatalog) -> Path:
        if not isinstance(catalog, CandidateCatalog):
            raise TypeError("catalog must be a CandidateCatalog")
        self.candidate_discovery_directory.mkdir(parents=True, exist_ok=True)
        write_json(self.entry_candidates, catalog.to_dict(), sort_keys=True, allow_nan=False)
        return self.entry_candidates


    def load_candidate_catalog(self, path: Path | None = None) -> CandidateCatalog | None:
        """Absence is explicit; malformed candidate catalogs are rejected."""
        selected = self.entry_candidates if path is None else Path(path)
        if not selected.exists() and path is None:
            return None
        try:
            return CandidateCatalog.from_dict(json.loads(selected.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError(f"cannot load entry candidate catalog {selected}: {error}") from error


    def load_target_build(self, *, project_root: str | Path | None = None) -> Any | None:
        """Load an explicit target build recipe, preserving absence as unknown."""

        if not self.target_build.is_file():
            return None
        from .target_build import TargetBuildConfig

        try:
            document = json.loads(self.target_build.read_text(encoding="utf-8"))
            return TargetBuildConfig.from_dict(document, project_root=project_root)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError(
                f"cannot load target build config: {type(error).__name__}"
            ) from error


def _require_owned_path(path: Path, root: Path) -> None:
    path = Path(path).resolve()
    root = Path(root).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError("artifact path escapes the artifact root") from error
