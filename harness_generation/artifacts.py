"""Central artifact layout and atomic persistence for FT generation."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable

from .records import write_json
from .target_contract import TargetContract
from .triplet import FunctionTriplet, triplets_document


VALIDATION_KINDS = ("intermediate", "compiler", "linker", "runtime")
VALIDATION_STATUSES = frozenset({
    "passed", "failed", "skipped", "unavailable", "passed_with_limitations",
})


@dataclass(frozen=True)
class ArtifactStore:
    """Paths layered onto an existing Phase 1 artifact directory."""

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
    def triplets(self) -> Path:
        return self.root / "triplets.json"

    @property
    def protocol_ir(self) -> Path:
        return self.root / "protocol_ir.json"

    @property
    def protocol_contract(self) -> Path:
        return self.root / "protocol.json"

    @property
    def protocol_conventions(self) -> Path:
        return self.root / "protocol_conventions.json"

    @property
    def contract(self) -> Path:
        return self.root / "target_contract.json"

    @property
    def target_build(self) -> Path:
        return self.root / "target_build.json"

    @property
    def promotion(self) -> Path:
        return self.root / "promotion.json"

    @property
    def triplets_directory(self) -> Path:
        return self.root / "triplets"

    @property
    def generation_directory(self) -> Path:
        return self.root / "generation"

    @property
    def harnesses_directory(self) -> Path:
        return self.root / "harnesses"

    @property
    def build_directory(self) -> Path:
        return self.root / "build"

    @property
    def fuzz_directory(self) -> Path:
        return self.root / "fuzz"

    @property
    def coverage_directory(self) -> Path:
        return self.root / "coverage"

    def ensure_catalogs(self) -> "ArtifactStore":
        """Create additive catalogs without touching existing Phase 1 files."""

        self.root.mkdir(parents=True, exist_ok=True)
        self.triplets_directory.mkdir(exist_ok=True)
        self.generation_directory.mkdir(exist_ok=True)
        self.harnesses_directory.mkdir(exist_ok=True)
        self.build_directory.mkdir(exist_ok=True)
        self.fuzz_directory.mkdir(exist_ok=True)
        self.coverage_directory.mkdir(exist_ok=True)
        return self

    def for_triplet(self, ft_id: str) -> "TripletArtifacts":
        _validate_ft_id(ft_id)
        return TripletArtifacts(self, ft_id)

    def write_triplets(
        self,
        triplets: Iterable[FunctionTriplet],
        *,
        individual: bool = False,
    ) -> Path:
        self.ensure_catalogs()
        ordered = tuple(triplets)
        document = triplets_document(ordered)
        write_json(self.triplets, document, sort_keys=True, allow_nan=False)
        if individual:
            by_id = {triplet.id: triplet for triplet in ordered}
            for ft_id in sorted(by_id):
                write_json(
                    self.for_triplet(ft_id).triplet,
                    {
                        "schema_version": document["schema_version"],
                        "triplet": by_id[ft_id].to_dict(),
                    },
                    sort_keys=True,
                    allow_nan=False,
                )
        return self.triplets

    def write_target_contract(self, contract: TargetContract) -> Path:
        """Persist the additive target contract at the project artifact root."""

        if not isinstance(contract, TargetContract):
            raise TypeError("contract must be a TargetContract")
        self.ensure_catalogs()
        write_json(self.contract, contract.to_dict(), sort_keys=True, allow_nan=False)
        return self.contract

    def write_target_build(self, config: Any) -> Path:
        """Persist the explicit target build recipe used by later stages."""

        from .target_build import TargetBuildConfig

        if not isinstance(config, TargetBuildConfig):
            raise TypeError("config must be a TargetBuildConfig")
        self.ensure_catalogs()
        write_json(self.target_build, {
            "schema_version": 1,
            "provenance": config.provenance,
            "recipe": config.to_recipe().to_dict(),
        }, sort_keys=True, allow_nan=False)
        return self.target_build

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

    def load_target_contract(self) -> TargetContract | None:
        """Load a target contract, preserving absence as an explicit no-op."""

        if not self.contract.is_file():
            return None
        try:
            document = json.loads(self.contract.read_text(encoding="utf-8"))
            return TargetContract.from_dict(document)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError(
                f"cannot load target contract: {type(error).__name__}"
            ) from error

    def write_protocol_contract(self, document: Any) -> Path:
        """Persist a legacy protocol.json document without normalizing it."""

        if not isinstance(document, dict):
            raise TypeError("protocol contract must be an object")
        self.ensure_catalogs()
        write_json(self.protocol_contract, document, sort_keys=True, allow_nan=False)
        return self.protocol_contract

    def write_protocol(
        self, facts: Any, conventions: Any, ir: Any,
    ) -> tuple[Path, Path, Path]:
        """Persist protocol inputs, canonical IR, and the additive contract."""

        self.ensure_catalogs()
        facts_path = self.root / "protocol_facts.json"
        conventions_path = self.protocol_conventions
        write_json(facts_path, facts.to_json(), sort_keys=True, allow_nan=False)
        convention_document = (
            {"status": "not_inferred", "entry_function": ir.entry_function}
            if conventions is None else conventions.to_json()
        )
        write_json(conventions_path, convention_document, sort_keys=True, allow_nan=False)
        write_json(self.protocol_ir, ir.to_json(), sort_keys=True, allow_nan=False)
        self.write_protocol_contract(ir.to_protocol_contract())
        self.write_target_contract(TargetContract.from_protocol_ir(ir))
        return facts_path, conventions_path, self.protocol_ir


@dataclass(frozen=True)
class TripletArtifacts:
    store: ArtifactStore
    ft_id: str

    def __post_init__(self) -> None:
        _validate_ft_id(self.ft_id)

    @property
    def triplet(self) -> Path:
        return self.store.triplets_directory / f"{self.ft_id}.json"

    @property
    def generation(self) -> Path:
        return self.store.generation_directory / self.ft_id

    @property
    def harness(self) -> Path:
        return self.store.harnesses_directory / f"{self.ft_id}.c"

    @property
    def stable_harness_plan(self) -> Path:
        return self.store.harnesses_directory / f"{self.ft_id}.plan.json"

    @property
    def promotion(self) -> Path:
        return self.generation / "promotion.json"

    @property
    def build(self) -> Path:
        return self.store.build_directory / self.ft_id

    @property
    def fuzz(self) -> Path:
        return self.store.fuzz_directory / self.ft_id

    @property
    def coverage(self) -> Path:
        return self.store.coverage_directory / self.ft_id

    @property
    def stage1_docs(self) -> Path:
        return self.generation / "stage1_docs.json"

    @property
    def stage1(self) -> Path:
        return self.generation / "stage1"

    @property
    def stage1_scoped_docs(self) -> Path:
        return self.stage1 / "stage1_docs.json"

    @property
    def stage1_prompts(self) -> Path:
        return self.stage1 / "prompts"

    @property
    def stage1_raw(self) -> Path:
        return self.stage1 / "raw"

    @property
    def stage2_snippets(self) -> Path:
        return self.generation / "stage2_snippets.json"

    @property
    def stage2(self) -> Path:
        return self.generation / "stage2"

    @property
    def stage2_scoped_snippets(self) -> Path:
        return self.stage2 / "stage2_snippets.json"

    @property
    def stage2_prompts(self) -> Path:
        return self.stage2 / "prompts"

    @property
    def stage2_raw(self) -> Path:
        return self.stage2 / "raw"

    @property
    def stage2_code_snippets(self) -> Path:
        return self.stage2 / "snippets"

    @property
    def stage3_rough(self) -> Path:
        return self.generation / "stage3_rough.c"

    @property
    def stage3_metadata(self) -> Path:
        return self.generation / "stage3_metadata.json"

    @property
    def stage4_harness(self) -> Path:
        return self.generation / "stage4_harness.c"

    @property
    def stage4_harness_plan(self) -> Path:
        return self.generation / "stage4_harness_plan.json"

    @property
    def validation(self) -> Path:
        """Backward-compatible alias for the intermediate validation artifact."""

        return self.intermediate_validation

    @property
    def validation_directory(self) -> Path:
        return self.generation / "validation"

    @property
    def intermediate_validation(self) -> Path:
        return self.validation_directory / "intermediate.json"

    @property
    def compiler_validation(self) -> Path:
        return self.validation_directory / "compiler.json"

    @property
    def linker_validation(self) -> Path:
        return self.validation_directory / "linker.json"

    @property
    def runtime_validation(self) -> Path:
        return self.validation_directory / "runtime.json"

    @property
    def validation_summary(self) -> Path:
        return self.validation_directory / "summary.json"

    @property
    def pipeline_state(self) -> Path:
        return self.generation / "pipeline_state.json"

    @property
    def pipeline_result(self) -> Path:
        return self.generation / "pipeline_result.json"

    @property
    def prompts(self) -> Path:
        return self.generation / "prompts"

    @property
    def raw(self) -> Path:
        return self.generation / "raw"

    @property
    def snippets(self) -> Path:
        return self.generation / "snippets"

    @property
    def stage3_attempts(self) -> Path:
        return self.generation / "stage3"

    @property
    def stage4_attempts(self) -> Path:
        return self.generation / "stage4"

    def ensure_generation(self) -> "TripletArtifacts":
        self.store.root.mkdir(parents=True, exist_ok=True)
        self.store.generation_directory.mkdir(exist_ok=True)
        for directory in (
            self.generation,
            self.prompts,
            self.raw,
            self.snippets,
            self.stage1,
            self.stage1_prompts,
            self.stage1_raw,
            self.stage2,
            self.stage2_prompts,
            self.stage2_raw,
            self.stage2_code_snippets,
            self.validation_directory,
            self.stage3_attempts,
            self.stage4_attempts,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        return self

    def ensure_build(self) -> "TripletArtifacts":
        """Create only this FT's owned build directory."""

        self.store.root.mkdir(parents=True, exist_ok=True)
        self.store.build_directory.mkdir(exist_ok=True)
        self.build.mkdir(parents=True, exist_ok=True)
        return self

    def ensure_fuzz(self) -> "TripletArtifacts":
        """Create only this FT's owned fuzz artifact directory."""

        self.store.root.mkdir(parents=True, exist_ok=True)
        self.store.fuzz_directory.mkdir(exist_ok=True)
        self.fuzz.mkdir(parents=True, exist_ok=True)
        return self

    def ensure_coverage(self) -> "TripletArtifacts":
        """Create only this FT's owned target-only coverage artifact directory."""

        self.store.root.mkdir(parents=True, exist_ok=True)
        self.store.coverage_directory.mkdir(exist_ok=True)
        self.coverage.mkdir(parents=True, exist_ok=True)
        return self

    def next_fuzz_smoke(self) -> tuple[int, Path]:
        """Reserve an immutable, monotonically numbered fuzz smoke attempt."""

        self.ensure_fuzz()
        numbers = [
            int(match.group(1))
            for path in self.fuzz.iterdir()
            if path.is_dir()
            and (match := re.fullmatch(r"smoke_(\d{3,})", path.name)) is not None
        ]
        attempt = max(numbers, default=0) + 1
        destination = self.fuzz / f"smoke_{attempt:03d}"
        destination.mkdir()
        return attempt, destination

    def next_coverage_run(self) -> tuple[int, Path]:
        """Reserve an immutable, monotonically numbered target coverage run."""

        self.ensure_coverage()
        numbers = [
            int(match.group(1))
            for path in self.coverage.iterdir()
            if path.is_dir()
            and (match := re.fullmatch(r"run_(\d{3,})", path.name)) is not None
        ]
        attempt = max(numbers, default=0) + 1
        destination = self.coverage / f"run_{attempt:03d}"
        destination.mkdir()
        return attempt, destination

    def validation_path(self, validator: str) -> Path:
        if validator not in VALIDATION_KINDS:
            raise ValueError(f"unknown validator artifact: {validator}")
        return self.validation_directory / f"{validator}.json"

    def write_validation(self, validator: str, value: Any) -> Path:
        """Persist one isolated validator result and refresh summary.json."""

        if not isinstance(value, dict):
            raise ValueError("validation artifact must be an object")
        if value.get("validator") != validator:
            raise ValueError("validation artifact validator does not match its path")
        if value.get("status") not in VALIDATION_STATUSES:
            raise ValueError("validation artifact has an invalid status")
        if not isinstance(value.get("errors"), list):
            raise ValueError("validation artifact errors must be a list")
        if not isinstance(value.get("warnings"), list):
            raise ValueError("validation artifact warnings must be a list")
        if not isinstance(value.get("metadata"), dict):
            raise ValueError("validation artifact metadata must be an object")
        destination = self.validation_path(validator)
        self.write_json(destination, value)
        self._write_validation_summary()
        return destination

    def next_attempt(self, stage: str) -> tuple[int, Path]:
        """Reserve the next monotonically numbered Stage 3/4 attempt directory."""

        if stage not in {"stage3", "stage4"}:
            raise ValueError("generation attempt stage must be stage3 or stage4")
        root = self.stage3_attempts if stage == "stage3" else self.stage4_attempts
        root.mkdir(parents=True, exist_ok=True)
        numbers = [
            int(match.group(1))
            for path in root.iterdir()
            if path.is_dir()
            and (match := re.fullmatch(r"attempt_(\d{3,})", path.name)) is not None
        ]
        attempt = max(numbers, default=0) + 1
        destination = root / f"attempt_{attempt:03d}"
        destination.mkdir()
        return attempt, destination

    def _write_validation_summary(self) -> None:
        statuses = {}
        for validator in VALIDATION_KINDS:
            path = self.validation_path(validator)
            if not path.is_file():
                continue
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            status = document.get("status") if isinstance(document, dict) else None
            if status in VALIDATION_STATUSES:
                statuses[validator] = status
        values = set(statuses.values())
        if "failed" in values:
            overall = "failed"
        elif len(statuses) == len(VALIDATION_KINDS) and values == {"passed"}:
            overall = "passed"
        elif "passed_with_limitations" in values or "passed" in values:
            overall = "passed_with_limitations"
        elif values:
            overall = "unavailable"
        else:
            overall = "not_run"
        self.write_json(self.validation_summary, {
            "schema_version": 1,
            **statuses,
            "overall": overall,
        })

    def write_json(self, path: Path, value: Any) -> Path:
        _require_owned_path(path, self.store.root)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json(path, value, sort_keys=True, allow_nan=False)
        return path

    def write_text(self, path: Path, value: str) -> Path:
        _require_owned_path(path, self.store.root)
        if not isinstance(value, str):
            raise ValueError("artifact text must be a string")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(value, encoding="utf-8")
        temporary.replace(path)
        return path

    def write_json_copies(self, paths: Iterable[Path], value: Any) -> tuple[Path, ...]:
        """Atomically write equivalent JSON to scoped and legacy destinations."""

        destinations = tuple(dict.fromkeys(Path(path) for path in paths))
        if not destinations:
            raise ValueError("at least one JSON artifact destination is required")
        return tuple(self.write_json(path, value) for path in destinations)

    def write_text_copies(self, paths: Iterable[Path], value: str) -> tuple[Path, ...]:
        """Atomically write equivalent text to scoped and legacy destinations."""

        destinations = tuple(dict.fromkeys(Path(path) for path in paths))
        if not destinations:
            raise ValueError("at least one text artifact destination is required")
        return tuple(self.write_text(path, value) for path in destinations)

    def manifest(self) -> dict[str, Path]:
        return {
            "triplet": self.triplet,
            "generation": self.generation,
            "harness": self.harness,
            "build": self.build,
            "fuzz": self.fuzz,
            "coverage": self.coverage,
            "stage1_docs": self.stage1_docs,
            "stage1": self.stage1,
            "stage1_scoped_docs": self.stage1_scoped_docs,
            "stage1_prompts": self.stage1_prompts,
            "stage1_raw": self.stage1_raw,
            "stage2_snippets": self.stage2_snippets,
            "stage2": self.stage2,
            "stage2_scoped_snippets": self.stage2_scoped_snippets,
            "stage2_prompts": self.stage2_prompts,
            "stage2_raw": self.stage2_raw,
            "stage2_code_snippets": self.stage2_code_snippets,
            "stage3_rough": self.stage3_rough,
            "stage3_metadata": self.stage3_metadata,
            "stage4_harness": self.stage4_harness,
            "stage4_harness_plan": self.stage4_harness_plan,
            "validation": self.validation,
            "validation_directory": self.validation_directory,
            "intermediate_validation": self.intermediate_validation,
            "compiler_validation": self.compiler_validation,
            "linker_validation": self.linker_validation,
            "runtime_validation": self.runtime_validation,
            "validation_summary": self.validation_summary,
            "pipeline_state": self.pipeline_state,
            "pipeline_result": self.pipeline_result,
            "prompts": self.prompts,
            "raw": self.raw,
            "stage3_attempts": self.stage3_attempts,
            "stage4_attempts": self.stage4_attempts,
        }


def _validate_ft_id(ft_id: str) -> None:
    if (
        not isinstance(ft_id, str)
        or not ft_id.startswith("ft_")
        or Path(ft_id).name != ft_id
        or ft_id in {".", ".."}
    ):
        raise ValueError("ft_id must be a safe basename beginning with 'ft_'")


def _require_owned_path(path: Path, root: Path) -> None:
    path = Path(path).resolve()
    root = Path(root).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError("artifact path escapes the artifact root") from error
