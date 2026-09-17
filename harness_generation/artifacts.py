"""Central artifact layout and atomic persistence for FT generation."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from .protocol_conventions import (
    PROTOCOL_CONVENTION_SCHEMA_VERSION,
    ConventionInferenceResult,
)
from .protocol_ir import ProtocolIR
from .protocol_miner import ProtocolFacts
from .records import write_json
from .triplet import FunctionTriplet, triplets_document


VALIDATION_KINDS = ("intermediate", "compiler", "linker", "runtime")
VALIDATION_STATUSES = frozenset({
    "passed", "failed", "skipped", "unavailable", "passed_with_limitations",
})

#: Key set in ``protocol_conventions.json`` only when no inference was run at
#: all, alongside the human-readable :data:`PROTOCOL_CONVENTIONS_NOT_INFERRED`.
#: Spelled in the negative so that its absence means the C block *is* there:
#: ``document.get(PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY)`` then fails safe.
PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY = "not_inferred"

#: Recorded in ``protocol_conventions.json`` when no inference was run at all.
#: The C block is then *unknown*, which is a different statement from "the vote
#: produced nothing": ``infer_protocol_conventions`` raises rather than returning
#: an empty result, so only the first can actually be persisted.
PROTOCOL_CONVENTIONS_NOT_INFERRED = (
    "convention block was not inferred: no LLM samples were requested, so the "
    "command loop, context lifetime and stateful opcodes are unknown"
)


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
    def protocol_candidates(self) -> Path:
        """The statically mined A/B facts, evidence included."""

        return self.root / "protocol_candidates.json"

    @property
    def protocol_conventions(self) -> Path:
        """The voted C block, with the samples and metadata behind the vote."""

        return self.root / "protocol_conventions.json"

    @property
    def protocol_ir(self) -> Path:
        """The canonical A/B + C model every later stage reads."""

        return self.root / "protocol_ir.json"

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

    def write_protocol(
        self,
        facts: ProtocolFacts | Mapping[str, Any],
        conventions: ConventionInferenceResult | Mapping[str, Any] | None = None,
        ir: ProtocolIR | Mapping[str, Any] | None = None,
        *,
        default_max_steps: int | None = None,
    ) -> tuple[Path, Path, Path]:
        """Persist the three protocol artifacts and return their paths.

        The result is ``(candidates, conventions, ir)``.  ``facts`` and
        ``conventions`` may be either the dataclasses or the documents their
        ``to_json()`` already produced; whichever is passed is written as it is,
        so no second schema version gets layered on top.

        When ``ir`` is omitted the two halves are merged through
        :meth:`ProtocolIR.from_facts_and_conventions`.  That merge needs the
        dataclasses -- a serialised conventions document cannot be voted back
        into a :class:`~protocol_conventions.ProtocolConventions` -- so mixing a
        document with an implicit merge raises rather than writing an IR that
        claims the C block was never inferred.  ``default_max_steps`` applies to
        that merge only.

        What the conventions document is able to say about the vote, and what it
        cannot, is documented on :meth:`write_protocol_conventions`.
        """

        document = ir if ir is not None else _merged_protocol_ir(
            facts, conventions, default_max_steps=default_max_steps
        )
        # Merge before writing anything: a rejected merge leaves the root exactly
        # as it was, instead of a candidates file with no IR to match it.
        return (
            self.write_protocol_candidates(facts),
            self.write_protocol_conventions(
                conventions, entry_function=_facts_entry_function(facts)
            ),
            self.write_protocol_ir(document),
        )

    def write_protocol_candidates(
        self, facts: ProtocolFacts | Mapping[str, Any],
    ) -> Path:
        """Persist the statically mined A/B facts document."""

        if not isinstance(facts, (ProtocolFacts, Mapping)):
            raise ValueError(
                "protocol candidates must be ProtocolFacts or its JSON document"
            )
        document = facts.to_json() if isinstance(facts, ProtocolFacts) else dict(facts)
        return self._write_protocol_json(self.protocol_candidates, document)

    def write_protocol_conventions(
        self,
        conventions: ConventionInferenceResult | Mapping[str, Any] | None = None,
        *,
        entry_function: str = "",
    ) -> Path:
        """Persist the C block, marked explicitly when none was inferred.

        The vote leaves behind sample-level metadata (``prompt_version``,
        ``model``, ``provider``, ``samples_requested``, ``valid_samples``,
        ``rejected_samples``) and the accepted/rejected sample bodies, and that
        is all this file can record.  There are **no per-element tallies**:
        ``_vote_conventions`` reduces each element to a mode and drops the
        counts, and the IR derives its LLM confidence from the sample-level
        ratio rather than from per-field agreement.  Recomputing a threshold
        here would duplicate the vote and could silently disagree with the
        result it is meant to describe, so the gap is recorded rather than
        filled; real tallies are a change that belongs to ``protocol_conventions``.

        ``conventions=None`` writes that the block was never inferred, so a
        reader cannot mistake "not asked" for "the vote produced nothing" (the
        latter cannot be persisted at all: :func:`infer_protocol_conventions`
        raises when no sample is valid).

        The marker is :data:`PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY`, spelled in
        the negative and present *only* when nothing was inferred.  A positive
        ``inferred`` key would have to be absent from the inferred document --
        that document is written verbatim as ``ConventionInferenceResult.to_json()``
        produces it -- and an absent key reads as false to ``document.get``,
        so the obvious check would report a successful inference as a missing C
        block.  In the negative form the same check fails safe: a missing key
        means the block is there.  ``conventions is None`` remains the direct
        signal for consumers that would rather test the payload than the flag.
        """

        document = _conventions_document(conventions, entry_function)
        return self._write_protocol_json(self.protocol_conventions, document)

    def write_protocol_ir(self, ir: ProtocolIR | Mapping[str, Any]) -> Path:
        """Persist the canonical merged A/B + C document."""

        if not isinstance(ir, (ProtocolIR, Mapping)):
            raise ValueError("protocol IR must be ProtocolIR or its JSON document")
        document = ir.to_json() if isinstance(ir, ProtocolIR) else dict(ir)
        return self._write_protocol_json(self.protocol_ir, document)

    def _write_protocol_json(self, path: Path, document: dict[str, Any]) -> Path:
        """Canonically serialise one protocol document at the store root.

        The three protocol files are written the way ``write_triplets`` writes
        its catalog: sorted keys and no non-finite numbers, so two runs over the
        same target diff cleanly.  No other catalog directory is created --
        these files live at the root, and a stage that only mines protocols
        should not conjure up ``generation/`` or ``fuzz/``.
        """

        if not isinstance(document, Mapping):
            raise ValueError("protocol artifact must be a JSON object")
        self.root.mkdir(parents=True, exist_ok=True)
        write_json(path, dict(document), sort_keys=True, allow_nan=False)
        return path


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
        elif values <= {"passed"}:
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


def _merged_protocol_ir(
    facts: ProtocolFacts | Mapping[str, Any],
    conventions: ConventionInferenceResult | Mapping[str, Any] | None,
    *,
    default_max_steps: int | None,
) -> ProtocolIR:
    """Merge the two halves when the caller did not hand over an IR."""

    if not isinstance(facts, ProtocolFacts):
        raise ValueError(
            "merging a protocol IR needs ProtocolFacts; pass ir explicitly when "
            "the A/B facts are already a document"
        )
    if conventions is None:
        return ProtocolIR.from_facts_and_conventions(
            facts, default_max_steps=default_max_steps
        )
    if not isinstance(conventions, ConventionInferenceResult):
        raise ValueError(
            "merging a protocol IR needs a ConventionInferenceResult; pass ir "
            "explicitly when the C block is already a document"
        )
    return ProtocolIR.from_facts_and_conventions(
        facts, conventions.conventions, default_max_steps=default_max_steps
    )


def _conventions_document(
    conventions: ConventionInferenceResult | Mapping[str, Any] | None,
    entry_function: str,
) -> dict[str, Any]:
    """The C block document, or the marker that says it was never inferred."""

    if isinstance(conventions, ConventionInferenceResult):
        return conventions.to_json()
    if isinstance(conventions, Mapping):
        return dict(conventions)
    if conventions is not None:
        raise ValueError(
            "protocol conventions must be a ConventionInferenceResult or its "
            "JSON document"
        )
    return {
        "schema_version": PROTOCOL_CONVENTION_SCHEMA_VERSION,
        "entry_function": entry_function,
        PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY: True,
        "conventions": None,
        "generations": [],
        "accepted_samples": [],
        "rejected_samples": [],
        "reason": PROTOCOL_CONVENTIONS_NOT_INFERRED,
    }


def _facts_entry_function(facts: ProtocolFacts | Mapping[str, Any]) -> str:
    if isinstance(facts, ProtocolFacts):
        return facts.entry_function
    value = facts.get("entry_function") if isinstance(facts, Mapping) else None
    return value if isinstance(value, str) else ""


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
