"""Measure harness arms against one target, and answer a coverage question.

``docs/PROTOCOL_FORMAT_MINING.md`` §5.3 asks whether a spec-driven generic
harness reaches the hand-written reference harness's coverage of the target.
That is a claim about two artifacts, so it can only be settled by measuring
both on the same target, the same corpus and the same budget -- this module is
that measurement, and ``docs/COVERAGE_EQUIVALENCE.md`` is its report.

Three things about the measurement are load-bearing, and each is a way the
comparison is usually gotten wrong:

**Two layers, never conflated.**  ``cov``/``ft`` come out of libFuzzer and
count instrumented *program* coverage: the harness's own code is in the
denominator.  Target-source coverage comes from LLVM source-based coverage
exported by ``llvm-cov`` and filtered to the target's files.  The first is
telemetry, the second is the gate.  Every record here is labelled with its
scope for that reason.

**Equal work, which needs the sanitizers off.**  With address and undefined
sanitizers in the build, a harness that finds a bug stops at the bug: the
reference arm halts after a few dozen executions while a harness that finds
nothing runs the whole budget.  Coverage counted there is coverage-at-first-
crash, and comparing it across arms compares how quickly each one crashed.  So
the coverage layer builds without sanitizers, drops the byte budget to
executions rather than seconds, and every arm completes the same ``-runs``.
The sanitized build is still measured -- it is the pipeline's own telemetry --
but it is reported separately and never compared.

**Distinct seeds, not repeats.**  ``-seed`` is fixed in the rest of this repo
because bounding a *single* harness wants reproducibility; comparing harnesses
wants independent samples.  Repeating one arm at one seed replays one search,
so three repeats are one sample three times.  The campaign sweeps seeds, and
reports one deliberate same-seed repeat separately, as the determinism check
it is.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, Mapping, Sequence

from .artifacts import ArtifactStore
from .core import compile_harness, normalize_cpp_harness
from .fuzz import run_fuzzer
from .fuzzer_build import (
    DEFAULT_FUZZER_COMPILE_FLAGS,
    DEFAULT_FUZZER_LINK_FLAGS,
    FuzzerBuildValidator,
)
from .target_build import TargetBuildConfig
from .target_coverage import (
    TargetCoverageCollector,
    TargetCoverageConfig,
    tool_path,
)


COVERAGE_ARMS_SCHEMA_VERSION = 1

#: The manifest's arm paths are relative to the repository, not to the
#: manifest, so the pinned digests mean the same thing wherever it is read from.
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "fixtures" / "coverage_arms" / "manifest.json"
DEFAULT_REPORT = REPO_ROOT / "docs" / "COVERAGE_EQUIVALENCE.md"

#: The two layers, named by what their numbers are actually about.
ENGINE_LAYER = "instrumented_program"
TARGET_LAYER = "target_code"
LAYERS = (ENGINE_LAYER, TARGET_LAYER)

#: The metrics the gate reads.  ``functions`` is deliberately not among them:
#: at ``-O1`` a single-TU build can inline a target function into the harness,
#: leaving its own counter at zero while its regions are plainly covered, so
#: the function count measures the recipe as much as the reach.
GATE_METRICS = ("lines", "regions", "branches")

#: What each arm is.  The role decides which claims the arm's numbers support:
#: only a published role may be the subject of the gate, so a refused attempt
#: can be measured without ever becoming a candidate.
ROLE_REFERENCE = "accepted_reference"
ROLE_CONTRACTED = "published_contracted"
ROLE_FT_ONLY = "published_ft_only"
ROLE_BASELINE = "tracked_baseline"
ROLE_REJECTED = "diagnostic_rejected"
ROLES = (
    ROLE_REFERENCE, ROLE_CONTRACTED, ROLE_FT_ONLY, ROLE_BASELINE, ROLE_REJECTED,
)
#: A hand-written reference is a baseline, not a candidate; everything a
#: generation path published is a candidate.
CANDIDATE_ROLES = frozenset({ROLE_CONTRACTED, ROLE_FT_ONLY})

RECIPES = ("single_tu", "two_tu")

_HARNESS_ENTRY = re.compile(r'\bint\s+LLVMFuzzerTestOneInput\s*\(')
_INCLUDE_TARGET = re.compile(r'^\s*#\s*include\s*"target\.c"\s*$', re.MULTILINE)

# --- build recipes -----------------------------------------------------------
#
# Every arm is built by the repo's own canonical path for its shape, so the
# arms differ in shape and nothing else.  Layer A uses the sanitized sets the
# pipeline already uses verbatim; layer B drops the sanitizers and adds the
# profile flags, which is what makes equal work possible.

SANITIZED_TARGET_FLAGS = DEFAULT_FUZZER_COMPILE_FLAGS
SANITIZED_LINK_FLAGS = DEFAULT_FUZZER_LINK_FLAGS
COVERAGE_TARGET_FLAGS = (
    "-std=c11", "-g", "-O1", "-Werror=implicit-function-declaration",
    "-fsanitize=fuzzer-no-link",
    "-fprofile-instr-generate", "-fcoverage-mapping",
)
COVERAGE_HARNESS_FLAGS = (
    "-x", "c++", "-std=c++17", "-g", "-O1",
    "-fsanitize=fuzzer-no-link",
    "-fprofile-instr-generate", "-fcoverage-mapping",
)
COVERAGE_LINK_FLAGS = (
    "-g", "-O1", "-fsanitize=fuzzer",
    "-fprofile-instr-generate", "-fcoverage-mapping",
)


class CoverageArmsError(RuntimeError):
    """A campaign cannot be run as configured."""


# --- the manifest ------------------------------------------------------------


@dataclass(frozen=True)
class ArmSpec:
    """One arm, exactly as the manifest declares it and the file confirms."""

    name: str
    path: str
    sha256: str
    size: int
    recipe: str
    role: str
    provenance: str

    @property
    def is_diagnostic(self) -> bool:
        return self.role == ROLE_REJECTED

    def document(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "recipe": self.recipe,
            "role": self.role,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class ArmsManifest:
    path: Path
    root: Path
    note: str
    target_source: Mapping[str, Any]
    corpus: Mapping[str, Any]
    arms: tuple[ArmSpec, ...]

    def resolve(self, arm: ArmSpec) -> Path:
        return self.root / arm.path

    def arm(self, name: str) -> ArmSpec:
        for arm in self.arms:
            if arm.name == name:
                return arm
        raise CoverageArmsError(f"no arm named {name!r} in {self.path}")

    def selected(self, *, include_diagnostic: bool) -> tuple[ArmSpec, ...]:
        return tuple(
            arm for arm in self.arms
            if include_diagnostic or not arm.is_diagnostic
        )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest(path: str | Path) -> ArmsManifest:
    """Read the arm manifest and verify every file it points at.

    The verification is not a formality.  A generated arm exists nowhere else
    -- the recording it came from is gone -- so the digest is the only thing
    connecting the measured bytes to the run that published them, and an arm
    silently swapped for another would make the whole comparison a claim about
    a file nobody measured.
    """

    manifest_path = Path(path).resolve()
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CoverageArmsError(f"cannot read manifest {manifest_path}: {error}")
    if not isinstance(document, Mapping):
        raise CoverageArmsError("manifest must be a JSON object")

    root = REPO_ROOT
    note = document.get("note")
    if not isinstance(note, str) or not note.strip():
        raise CoverageArmsError("manifest needs a note saying where the arms came from")
    arms = tuple(_arm_spec(entry) for entry in document.get("arms", []))
    if not arms:
        raise CoverageArmsError("manifest declares no arms")
    names = [arm.name for arm in arms]
    if len(set(names)) != len(names):
        raise CoverageArmsError("arm names must be unique")

    manifest = ArmsManifest(
        path=manifest_path,
        root=root,
        note=note,
        target_source=document.get("target_source", {}),
        corpus=document.get("corpus", {}),
        arms=arms,
    )
    problems = verify_manifest(manifest)
    if problems:
        raise CoverageArmsError(
            "manifest does not match the files it names: " + "; ".join(problems)
        )
    return manifest


def _arm_spec(entry: Any) -> ArmSpec:
    if not isinstance(entry, Mapping):
        raise CoverageArmsError("each arm must be a JSON object")
    fields = {}
    for key in ("name", "path", "sha256", "size", "recipe", "role", "provenance"):
        value = entry.get(key)
        if key == "size":
            if type(value) is not int or value < 1:
                raise CoverageArmsError("arm size must be a positive integer")
        elif not isinstance(value, str) or not value.strip():
            raise CoverageArmsError(f"arm {key} must be non-empty text")
        fields[key] = value
    if fields["recipe"] not in RECIPES:
        raise CoverageArmsError(
            f"arm recipe must be one of {RECIPES}, not {fields['recipe']!r}"
        )
    if fields["role"] not in ROLES:
        raise CoverageArmsError(
            f"arm role must be one of {ROLES}, not {fields['role']!r}"
        )
    return ArmSpec(**fields)


def verify_manifest(manifest: ArmsManifest) -> tuple[str, ...]:
    """Every way the manifest and the files on disk can disagree."""

    problems: list[str] = []
    for arm in manifest.arms:
        path = manifest.resolve(arm)
        if not path.is_file():
            problems.append(f"{arm.name}: missing {arm.path}")
            continue
        raw = path.read_bytes()
        if len(raw) != arm.size:
            problems.append(
                f"{arm.name}: {arm.path} is {len(raw)} bytes, manifest says {arm.size}"
            )
        actual = hashlib.sha256(raw).hexdigest()
        if actual != arm.sha256:
            problems.append(
                f"{arm.name}: {arm.path} is {actual}, manifest says {arm.sha256}"
            )
        problems.extend(_recipe_problems(arm, raw))
    return tuple(problems)


def _recipe_problems(arm: ArmSpec, raw: bytes) -> list[str]:
    """The recipe is a claim about the source, so the source has to show it.

    ``single_tu`` means the harness textually absorbs the target and so is
    compiled with it as one translation unit; ``two_tu`` means it declares the
    target's entry points instead and is compiled beside it.  Deriving both
    from the text keeps a hand-edited manifest from turning one recipe into the
    other without the file changing.

    What the text cannot tell us is the entry point's linkage: the tracked
    harnesses are C and declare it plainly, and ``normalize_cpp_harness`` adds
    the ``extern "C"`` when the copy is staged.  So this checks that the entry
    point is declared at all, and each engine record carries whether that copy
    needed normalizing -- a measured fact rather than a claim here.
    """

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [f"{arm.name}: harness source is not UTF-8"]
    includes = bool(_INCLUDE_TARGET.search(text))
    expected = arm.recipe == "single_tu"
    if includes != expected:
        return [
            f"{arm.name}: recipe {arm.recipe} but "
            f"{'includes' if includes else 'does not include'} target.c"
        ]
    if not _HARNESS_ENTRY.search(text):
        return [f"{arm.name}: no LLVMFuzzerTestOneInput declaration"]
    return []


# --- the campaign ------------------------------------------------------------


@dataclass(frozen=True)
class CoverageArmsConfig:
    """One campaign.  Every arm gets the same corpus, budget and seed set."""

    runs: int = 20_000
    seeds: tuple[int, ...] = (1, 2, 3)
    seconds_cap: int = 300
    timeout: float = 300.0
    harness_compiler: str = "clang++"
    determinism_check: bool = True
    #: Extra budgets for the coverage layer only, because "equivalent" is a
    #: claim at a budget and the honest question is whether it survives one.
    #: A harness whose edge has to be found by the search needs executions to
    #: reach the same regions as one that constructs valid frames directly, so
    #: a verdict that holds at one budget and not another has to say so.
    sensitivity_runs: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if type(self.runs) is not int or self.runs < 1:
            raise ValueError("runs must be a positive integer")
        seeds = tuple(self.seeds)
        if not seeds or any(type(seed) is not int or seed < 0 for seed in seeds):
            raise ValueError("seeds must be non-negative integers")
        if len(set(seeds)) != len(seeds):
            raise ValueError("seeds must be distinct; repeating one is not a sample")
        object.__setattr__(self, "seeds", seeds)
        if type(self.seconds_cap) is not int or self.seconds_cap < 1:
            raise ValueError("seconds_cap must be a positive integer")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise ValueError("timeout must be positive")
        if (
            not isinstance(self.harness_compiler, str)
            or not self.harness_compiler.strip()
        ):
            raise ValueError("harness_compiler must be non-empty text")
        extra = tuple(self.sensitivity_runs)
        if any(type(value) is not int or value < 1 for value in extra):
            raise ValueError("sensitivity_runs must be positive integers")
        if self.runs in extra or len(set(extra)) != len(extra):
            raise ValueError(
                "sensitivity_runs must be distinct from runs and from each other"
            )
        object.__setattr__(self, "sensitivity_runs", extra)


def prepare_arm(spec: ArmSpec, source: Path, target_source: Path, work: Path) -> dict:
    """Stage one arm in a scratch directory, writing no tracked file.

    The tracked harness is copied rather than compiled in place for two
    reasons: ``normalize_cpp_harness`` rewrites the entry point declaration,
    and the target has to sit beside the harness for the single-TU arms'
    ``#include "target.c"`` to resolve.
    """

    work.mkdir(parents=True, exist_ok=True)
    target_copy = work / "target.c"
    shutil.copyfile(target_source, target_copy)
    harness = work / "harness.c"
    original = source.read_text(encoding="utf-8")
    normalized = normalize_cpp_harness(original)
    harness.write_text(normalized, encoding="utf-8")
    return {
        "harness": harness,
        "target": target_copy,
        "normalized": normalized != original,
    }


def _target_config(work: Path) -> TargetBuildConfig:
    return TargetBuildConfig(
        project_root=work,
        source_files=(work / "target.c",),
        header_files=(),
        include_paths=(work,),
        compiler_flags=("-std=c11",),
    )


def _arm_work(root: Path, name: str, seed: int, layer: str) -> Path:
    return root / "arms" / name / f"seed_{seed}" / layer


def _ft_id(name: str) -> str:
    """The artifact store's own naming rule: a safe basename beginning ``ft_``."""

    return f"ft_arms_{name}"


def measure_engine_arm(
    spec: ArmSpec,
    source: Path,
    target_source: Path,
    config: CoverageArmsConfig,
    *,
    root: Path,
    corpus: Path,
    seed: int,
) -> dict:
    """Layer A: build the sanitized fuzzer the pipeline itself would run.

    This is telemetry, not the gate.  A run that finds something stops at the
    finding, so its numbers are coverage-at-first-crash and are labelled that
    way rather than compared.
    """

    work = _arm_work(root, spec.name, seed, "engine")
    if work.exists():
        shutil.rmtree(work)
    staged = prepare_arm(spec, source, target_source, work)
    if spec.recipe == "single_tu":
        built = compile_harness(work)
        build_status = built["status"]
        built_by = "core.compile_harness"
        commands = [json.loads((work / "compile_command.json").read_text())]
    else:
        store = work / "store"
        result = FuzzerBuildValidator().validate(
            staged["harness"],
            _target_config(work),
            artifacts=store,
            ft_id=_ft_id(spec.name),
            stage="coverage_arms",
        )
        build_status = result.status
        built_by = "FuzzerBuildValidator"
        fuzzer = result.metadata.get("fuzzer")
        commands = _build_commands(store, _ft_id(spec.name))
        if fuzzer is not None and Path(fuzzer).is_file():
            # run_fuzzer runs ./fuzz_target from the output directory, so the
            # copy has to keep the executable bit: copyfile would leave a
            # non-executable file and every two-TU run would fail to start.
            shutil.copy(fuzzer, work / "fuzz_target")

    record: dict[str, Any] = {
        "scope": ENGINE_LAYER,
        "arm": spec.name,
        "role": spec.role,
        "seed": seed,
        "build_status": build_status,
        "built_by": built_by,
        "harness_normalized": staged["normalized"],
        "commands": commands,
    }
    if build_status != "passed":
        record["status"] = "build_failed"
        return record

    result = run_fuzzer(
        work, config.seconds_cap, corpus, runs=config.runs, seed=seed,
    )
    statistics = result.get("statistics", {})
    executed = statistics.get("number_of_executed_units")
    record.update(
        status=result["status"],
        coverage_edges_or_blocks=statistics.get("coverage_edges_or_blocks"),
        features=statistics.get("features"),
        executed_units=executed,
        requested_runs=result.get("requested_runs"),
        findings=list(result.get("findings", ())),
        # A finding ends the run early, so the two numbers below are what make
        # an arm's cov/ft readable as "at this many executions" rather than as
        # a result comparable to an arm that ran the whole budget.
        truncated_by_finding=result["status"] == "finding",
        crash_classification=result.get("crash_classification", {}).get("classification"),
    )
    return record


def measure_target_arm(
    spec: ArmSpec,
    source: Path,
    target_source: Path,
    config: CoverageArmsConfig,
    *,
    root: Path,
    corpus: Path,
    seed: int,
    runs: int | None = None,
) -> dict:
    """Layer B: LLVM source-based coverage, filtered to the target, at equal work."""

    budget = config.runs if runs is None else runs
    work = _arm_work(root, spec.name, seed, f"target{'' if runs is None else budget}")
    if work.exists():
        shutil.rmtree(work)
    staged = prepare_arm(spec, source, target_source, work)
    result = TargetCoverageCollector(TargetCoverageConfig(
        runs=budget,
        seed=seed,
        timeout=config.timeout,
        compiler_flags=COVERAGE_TARGET_FLAGS,
        link_flags=COVERAGE_LINK_FLAGS,
        harness_compiler=config.harness_compiler,
        harness_compiler_flags=COVERAGE_HARNESS_FLAGS,
        compile_target_sources=spec.recipe == "two_tu",
    )).measure(
        staged["harness"],
        _target_config(work),
        artifacts=work / "store",
        ft_id=_ft_id(spec.name),
        corpus=corpus,
    )
    summary = result.summary if isinstance(result.summary, Mapping) else {}
    target_only = summary.get("target_only", {})
    totals = target_only.get("totals", {}) if isinstance(target_only, Mapping) else {}
    record: dict[str, Any] = {
        "scope": TARGET_LAYER,
        "arm": spec.name,
        "role": spec.role,
        "seed": seed,
        "recipe": spec.recipe,
        "status": result.status,
        "runs": summary.get("runs"),
        "seed_recorded": summary.get("seed"),
        "compile_target_sources": summary.get("compile_target_sources"),
        "harness_compiler": summary.get("harness_compiler"),
        "totals": {
            metric: _metric(item)
            for metric, item in sorted(totals.items())
            if isinstance(item, Mapping)
        },
        "entered_functions": list(
            target_only.get("entered_functions", ())
            if isinstance(target_only, Mapping) else ()
        ),
        "errors": list(result.errors),
        "artifact": _relative(result.artifact_directory, root),
    }
    return record


def _metric(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "count": item.get("count"),
        "covered": item.get("covered"),
        "percent": item.get("percent"),
    }


def _relative(path: Path, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _build_commands(store: Path, ft_id: str) -> list[Any]:
    path = store / "build" / ft_id / "compile_commands.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    return document if isinstance(document, list) else []


def run_campaign(
    manifest: ArmsManifest,
    config: CoverageArmsConfig,
    *,
    artifacts: Path,
    include_diagnostic: bool = False,
) -> dict:
    """Every arm, every seed, both layers.  Returns the measurements document."""

    arms = manifest.selected(include_diagnostic=include_diagnostic)
    target_source = manifest.root / str(manifest.target_source.get("path", ""))
    corpus = manifest.root / str(manifest.corpus.get("path", ""))
    if not target_source.is_file():
        raise CoverageArmsError(f"target source is missing: {target_source}")
    if not corpus.is_dir():
        raise CoverageArmsError(f"corpus directory is missing: {corpus}")

    artifacts = Path(artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    engine: list[dict] = []
    target: list[dict] = []
    for arm in arms:
        source = manifest.resolve(arm)
        for seed in config.seeds:
            engine.append(measure_engine_arm(
                arm, source, target_source, config,
                root=artifacts, corpus=corpus, seed=seed,
            ))
            target.append(measure_target_arm(
                arm, source, target_source, config,
                root=artifacts, corpus=corpus, seed=seed,
            ))

    document: dict[str, Any] = {
        "schema_version": COVERAGE_ARMS_SCHEMA_VERSION,
        "generated_by": "harness_generation.coverage_arms",
        "note": manifest.note,
        "toolchain": toolchain_versions(),
        "target_source": dict(manifest.target_source),
        "corpus": {
            "path": manifest.corpus.get("path"),
            "policy": manifest.corpus.get("policy"),
            "digests": dict(manifest.corpus.get("digests", {})),
        },
        "config": {
            "runs": config.runs,
            "seeds": list(config.seeds),
            "seconds_cap": config.seconds_cap,
            "timeout": config.timeout,
            "recipe": {
                "engine_sanitized": {
                    "target": list(SANITIZED_TARGET_FLAGS),
                    "link": list(SANITIZED_LINK_FLAGS),
                },
                "target_coverage": {
                    "target": list(COVERAGE_TARGET_FLAGS),
                    "harness": list(COVERAGE_HARNESS_FLAGS),
                    "link": list(COVERAGE_LINK_FLAGS),
                },
            },
        },
        "arms": [arm.document() for arm in arms],
        "layers": {
            ENGINE_LAYER: {
                "scope": ENGINE_LAYER,
                "note": (
                    "libFuzzer cov/ft over the whole instrumented program, "
                    "harness included.  Not target-source coverage, and a run "
                    "that found something stopped at the finding."
                ),
                "runs": engine,
            },
            TARGET_LAYER: {
                "scope": TARGET_LAYER,
                "note": (
                    "LLVM source-based coverage filtered to the target's files, "
                    "sanitizers off, equal -runs.  The gate reads this layer."
                ),
                "runs": target,
            },
        },
    }
    document["recipe_control"] = recipe_control(document)
    if config.sensitivity_runs:
        document["budget_sensitivity"] = {}
        for budget in config.sensitivity_runs:
            records = [
                measure_target_arm(
                    arm, manifest.resolve(arm), target_source, config,
                    root=artifacts, corpus=corpus, seed=seed, runs=budget,
                )
                for arm in arms
                for seed in config.seeds
            ]
            document["budget_sensitivity"][str(budget)] = {
                "runs": budget,
                "note": (
                    "The coverage layer at a different budget.  A harness that "
                    "has to search for a valid frame needs executions to reach "
                    "what a harness that builds frames directly reaches at "
                    "once, so this is where a budget-relative verdict shows."
                ),
                "runs_records": records,
                "gate": evaluate_gate(document, records=records, budget=budget),
            }
    if config.determinism_check:
        document["determinism"] = determinism_check(
            manifest, config, artifacts=artifacts, corpus=corpus,
            target_source=target_source,
        )
    document["gate"] = evaluate_gate(document)
    return document


def toolchain_versions() -> dict[str, str]:
    """What actually built and read the numbers.

    Resolved the way the collector resolves its tools, versioned names
    included: `llvm-cov` is `llvm-cov-18` on this machine, and reporting the
    unversioned name as unavailable while the measurement used it would put a
    false statement in the reproducibility block.
    """

    versions: dict[str, str] = {}
    for name in ("clang", "clang++", "llvm-cov", "llvm-profdata"):
        executable = tool_path(name)
        if executable is None:
            versions[name] = "unavailable"
            continue
        try:
            completed = subprocess.run(
                [executable, "--version"], capture_output=True, text=True,
                timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            versions[name] = f"unavailable: {error}"
            continue
        first = completed.stdout.splitlines()
        versions[name] = first[0].strip() if first else "unknown"
    return versions


def determinism_check(
    manifest: ArmsManifest,
    config: CoverageArmsConfig,
    *,
    artifacts: Path,
    corpus: Path,
    target_source: Path,
) -> dict:
    """One same-seed repeat, reported as the determinism check it is.

    The campaign sweeps seeds because repeats at one seed are one sample.  That
    claim deserves evidence, so exactly one arm is run twice at one seed and
    the two records are compared: equal means a same-seed repeat is a replay,
    which is why the campaign does not count one twice.
    """

    arm = manifest.arm("reference")
    seed = config.seeds[0]
    repeat = measure_engine_arm(
        arm, manifest.resolve(arm), target_source, config,
        root=artifacts / "determinism", corpus=corpus, seed=seed,
    )
    fields = ("status", "coverage_edges_or_blocks", "features", "executed_units")
    first = {
        field: _engine_record(artifacts, arm.name, seed).get(field)
        for field in fields
    }
    return {
        "arm": arm.name,
        "seed": seed,
        "fields": list(fields),
        "identical": all(first.get(field) == repeat.get(field) for field in fields),
        "first": first,
        "repeat": {field: repeat.get(field) for field in fields},
    }


def _engine_record(root: Path, name: str, seed: int) -> dict[str, Any]:
    """The engine record one arm left behind in its scratch directory."""

    path = _arm_work(root, name, seed, "engine") / "fuzz_result.json"
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    statistics = result.get("statistics", {})
    return {
        "status": result.get("status"),
        "coverage_edges_or_blocks": statistics.get("coverage_edges_or_blocks"),
        "features": statistics.get("features"),
        "executed_units": statistics.get("number_of_executed_units"),
    }


def recipe_control(document: Mapping[str, Any]) -> dict:
    """Bound the recipe effect rather than argue it away.

    ``pass_through`` and ``ft_only`` are both one call on raw bytes; the first
    is single-TU and hand-written, the second two-TU and published.  Their gap
    is the combined effect of translation-unit count, ``target.c``'s language
    mode and inlining -- measured, not asserted.  It is a bound and not a
    correction, because the pair also differs in provenance.
    """

    pair = ("pass_through", "ft_only")
    runs = {
        (run.get("arm"), run.get("seed")): run
        for run in document.get("layers", {}).get(TARGET_LAYER, {}).get("runs", ())
    }
    seeds = document.get("config", {}).get("seeds", ())
    delta: dict[str, Any] = {}
    for metric in GATE_METRICS:
        values = []
        for seed in seeds:
            left = _percent(runs.get((pair[0], seed)), metric)
            right = _percent(runs.get((pair[1], seed)), metric)
            if left is None or right is None:
                continue
            values.append(round(right - left, 6))
        delta[metric] = values
    return {
        "pair": list(pair),
        "delta_percent": delta,
        "interpretation": (
            "ft_only minus pass_through, in target-coverage percentage points, "
            "one value per seed.  Both arms make the same one call on raw "
            "bytes, so this bounds the translation-unit/language-mode/inlining "
            "effect on the rest of the table."
        ),
    }


# --- the gate ----------------------------------------------------------------


def _percent(run: Mapping[str, Any] | None, metric: str) -> float | None:
    if not isinstance(run, Mapping):
        return None
    value = run.get("totals", {}).get(metric, {}).get("percent")
    return value if isinstance(value, (int, float)) else None


def seed_spread(
    records: Sequence[Mapping[str, Any]],
    metrics: Sequence[str] = GATE_METRICS,
) -> tuple[str, ...]:
    """Which arms' coverage moves when the seed does.

    A campaign is a seed sweep rather than a repeat only if the seeds can
    disagree.  At a budget where every arm saturates they cannot, and the
    three rows per arm are then one measurement printed three times -- worth
    saying, because a per-seed table otherwise reads as three independent
    confirmations of the same number.
    """

    varying: list[str] = []
    for arm in sorted({str(run.get("arm")) for run in records}):
        per_seed = [
            tuple(
                (run.get("totals") or {}).get(metric, {}).get("percent")
                for metric in metrics
            )
            for run in records
            if run.get("arm") == arm
        ]
        if len(set(per_seed)) > 1:
            varying.append(arm)
    return tuple(varying)


def percent_range(
    records: Sequence[Mapping[str, Any]],
    arm: str,
    metrics: Sequence[str] = GATE_METRICS,
) -> dict[str, tuple[float, float]]:
    """One arm's target-coverage percentages across the campaign's seeds."""

    values: dict[str, list[float]] = {metric: [] for metric in metrics}
    for run in records:
        if run.get("arm") != arm:
            continue
        for metric in metrics:
            value = (run.get("totals") or {}).get(metric, {}).get("percent")
            if isinstance(value, (int, float)):
                values[metric].append(float(value))
    return {
        metric: (min(found), max(found))
        for metric, found in values.items()
        if found
    }


def rejected_arm(document: Mapping[str, Any]) -> str | None:
    for arm in document.get("arms", ()):
        if arm.get("role") == ROLE_REJECTED:
            return arm.get("name")
    return None


def _range_text(bounds: Mapping[str, tuple[float, float]]) -> str:
    parts = []
    for metric in GATE_METRICS:
        found = bounds.get(metric)
        if found is None:
            continue
        low, high = found
        parts.append(f"{metric} {low}%" if low == high else f"{metric} {low}%–{high}%")
    return ", ".join(parts) or "nothing measured"


def evaluate_gate(
    document: Mapping[str, Any],
    *,
    reference: str = "reference",
    candidate: str = "contracted",
    metrics: Sequence[str] = GATE_METRICS,
    tolerance: float = 0.05,
    records: Sequence[Mapping[str, Any]] | None = None,
    budget: int | None = None,
) -> dict:
    """Operationalise "≈": per seed, per metric, does the candidate reach it?

    ``≈`` is not self-defining, so it is defined here twice and both answers
    are reported: ``passes_strict`` is ``candidate >= reference``, and
    ``passes_tolerance`` allows the candidate to fall ``tolerance`` short.  An
    arm-level verdict requires every seed to pass, because a metric that holds
    at one seed and not another has not been shown to hold.

    The verdict is scoped to a budget, so the budget is in the result: the
    same pair of harnesses can be level at one execution count and not at
    another, and a verdict that does not say which one it is cannot be read.
    """

    roles = {
        arm.get("name"): arm.get("role")
        for arm in document.get("arms", ())
    }
    subject = roles.get(candidate)
    admissible = subject in CANDIDATE_ROLES
    if records is None:
        records = document.get("layers", {}).get(TARGET_LAYER, {}).get("runs", ())
        budget = document.get("config", {}).get("runs")
    runs = {
        (run.get("arm"), run.get("seed")): run for run in records
    }
    seeds = list(document.get("config", {}).get("seeds", ()))
    metrics_report: dict[str, Any] = {}
    for metric in metrics:
        per_seed = []
        for seed in seeds:
            reference_percent = _percent(runs.get((reference, seed)), metric)
            candidate_percent = _percent(runs.get((candidate, seed)), metric)
            entry: dict[str, Any] = {
                "seed": seed,
                "reference_percent": reference_percent,
                "candidate_percent": candidate_percent,
            }
            if reference_percent is None or candidate_percent is None:
                entry.update(ratio=None, passes_strict=None, passes_tolerance=None)
            else:
                ratio = (
                    1.0 if reference_percent == 0 and candidate_percent == 0
                    else (None if reference_percent == 0
                          else round(candidate_percent / reference_percent, 6))
                )
                entry.update(
                    ratio=ratio,
                    passes_strict=candidate_percent >= reference_percent,
                    passes_tolerance=(
                        None if ratio is None else ratio >= 1.0 - tolerance
                    ),
                )
            per_seed.append(entry)
        ratios = [item["ratio"] for item in per_seed if item["ratio"] is not None]
        metrics_report[metric] = {
            "per_seed": per_seed,
            "min_ratio": min(ratios) if ratios else None,
            "max_ratio": max(ratios) if ratios else None,
            "passes_strict": all(
                item["passes_strict"] for item in per_seed
            ) and bool(per_seed),
            "passes_tolerance": all(
                item["passes_tolerance"] for item in per_seed
            ) and bool(per_seed),
        }
    strict = all(metrics_report[metric]["passes_strict"] for metric in metrics)
    within = all(metrics_report[metric]["passes_tolerance"] for metric in metrics)
    return {
        "reference": reference,
        "candidate": candidate,
        "candidate_role": subject,
        "admissible": admissible,
        "budget": budget,
        "tolerance": tolerance,
        "metrics": metrics_report,
        "verdict": (
            "not_admissible"
            if not admissible
            else "equivalent_strict"
            if strict
            else "equivalent_within_tolerance"
            if within
            else "below_reference"
        ),
    }


# --- offline verification ----------------------------------------------------


def check_measurements(
    manifest_path: str | Path,
    measurements: Mapping[str, Any],
    *,
    doc_path: str | Path | None = None,
) -> tuple[str, ...]:
    """Re-derive every verdict from the committed evidence, with no toolchain.

    This is the drift check.  It re-hashes the arms, re-derives each recipe
    from the source, recomputes the gate with the same function the campaign
    used, and re-asserts the properties the report leans on -- so an edited
    verdict, a swapped arm, or an unequal budget fails without a compiler.
    """

    problems: list[str] = []
    try:
        manifest = load_manifest(manifest_path)
    except CoverageArmsError as error:
        return (str(error),)

    recorded = {
        arm.get("name"): arm for arm in measurements.get("arms", ())
        if isinstance(arm, Mapping)
    }
    for arm in manifest.arms:
        entry = recorded.get(arm.name)
        if entry is None:
            if not arm.is_diagnostic:
                problems.append(f"{arm.name}: in the manifest but not measured")
            continue
        for field in ("path", "sha256", "size", "recipe", "role"):
            if entry.get(field) != getattr(arm, field):
                problems.append(
                    f"{arm.name}: {field} is {entry.get(field)!r} in the evidence, "
                    f"{getattr(arm, field)!r} in the manifest"
                )

    recomputed = evaluate_gate(measurements)
    if recomputed != measurements.get("gate"):
        problems.append("the recorded gate verdict is not the one this evidence gives")

    for budget, block in (measurements.get("budget_sensitivity") or {}).items():
        records = block.get("runs_records", ())
        if not records:
            problems.append(f"budget {budget}: no runs recorded")
            continue
        for run in records:
            if run.get("runs") != block.get("runs"):
                problems.append(
                    f"budget {budget}: {run.get('arm')} seed {run.get('seed')} "
                    f"ran {run.get('runs')} executions"
                )
        verdict = evaluate_gate(measurements, records=records, budget=block.get("runs"))
        if verdict != block.get("gate"):
            problems.append(
                f"budget {budget}: the recorded verdict is not the one this "
                "evidence gives"
            )

    seeds = list(measurements.get("config", {}).get("seeds", ()))
    runs = measurements.get("config", {}).get("runs")
    for layer in LAYERS:
        layer_runs = measurements.get("layers", {}).get(layer, {}).get("runs", ())
        if not layer_runs:
            problems.append(f"{layer}: no runs recorded")
            continue
        for run in layer_runs:
            if run.get("scope") != layer:
                problems.append(
                    f"{layer}: {run.get('arm')} seed {run.get('seed')} is "
                    f"labelled {run.get('scope')!r}"
                )
        seen = {(run.get("arm"), run.get("seed")) for run in layer_runs}
        for name in sorted(recorded):
            for seed in seeds:
                if (name, seed) not in seen:
                    problems.append(f"{layer}: {name} has no seed {seed}")
        if layer == ENGINE_LAYER:
            for run in layer_runs:
                if run.get("requested_runs") != runs:
                    problems.append(
                        f"{layer}: {run.get('arm')} seed {run.get('seed')} ran "
                        f"{run.get('requested_runs')} executions, campaign says {runs}"
                    )

    if len(set(seeds)) != len(seeds) or len(seeds) < 2:
        problems.append("the campaign is not a seed sweep")

    # The load-bearing negative: the refusal has to still bind, or "we only
    # ever present accepted artifacts" is a habit rather than a property.
    for arm in manifest.arms:
        if arm.is_diagnostic and arm.name in recorded:
            if evaluate_gate(measurements, candidate=arm.name).get("admissible"):
                problems.append(f"{arm.name}: a refused arm is admissible as the gate's subject")
    for arm in manifest.arms:
        is_candidate = arm.role in CANDIDATE_ROLES
        if evaluate_gate(measurements, candidate=arm.name).get("admissible") != is_candidate:
            problems.append(f"{arm.name}: admissibility does not follow its role")

    if doc_path is not None:
        expected = render_report(measurements)
        try:
            actual = Path(doc_path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            problems.append(f"cannot read {doc_path}: {error}")
        else:
            if actual != expected:
                problems.append(
                    f"{doc_path} is not what this evidence renders; re-run "
                    "coverage-arms --report"
                )
    return tuple(problems)


# --- the report --------------------------------------------------------------

#: Printed in every report this module renders.  It is inside the function
#: rather than a caller's argument so a report cannot be produced without it.
CAVEATS = """\
**(a) Two layers, never conflated.** `cov`/`ft` are `instrumented_program`
coverage: libFuzzer counts the instrumented program, the harness included.
Only the `llvm-cov` totals filtered to the target's files are called target
coverage. No sentence here may read `cov`/`ft` as coverage of the target.

**(b) Recipes are normalized where they can be and stated where they cannot.**
Every arm shares the compiler, `-O1` and its layer's flags. What remains is the
translation-unit count and `target.c`'s language mode: the single-TU arms
absorb it into a C++17 unit, the two-TU arms compile it as C11. That moves
inlining, which is why `functions` is not a gate metric and why the
`ft_only` − `pass_through` delta is printed next to the numbers: both make the
same one call, so their gap bounds the recipe effect. It bounds it and does not
remove it, because the pair also differs in provenance.

**(c) These are seeds, not repeats.** Three distinct seeds are three different
campaigns at one budget. This is a seed sweep, not a robustness claim: no
confidence interval, no significance test, nothing of the sort is computed
here over n=3. The one same-seed repeat in the evidence is labelled as the
determinism check it is. Where the spread section reports that the seeds do
not separate the arms, n=3 is not three samples but one number measured three
times, and the sweep is evidence that the number is stable, not that it is
typical.

**(d) The FT-only arm's provenance is not controlled.** Its run had no
`protocol_ir.json`, so it is a "no contract given" baseline from a *different*
generation run. Nothing here isolates the IR's causal contribution, and the
arm cannot be read as the same generator with one input withheld.

**(e) The gate is measured on a sanitizer-free build.** That is what makes
equal work meaningful, and it is why the sanitized numbers are reported
separately rather than compared. The gate therefore cannot be read as "the
pipeline's ASan build reached X".

**(f) Coverage equivalence is not bug-set equivalence.** The reference arm's
finding and the contracted arm's finding need not be the same bug, and the
gate says nothing about which bugs a harness finds. A coverage-equivalent
harness can exercise a different bug set.

**(g) The published arms restate the context struct by hand.** The contracted
and FT-only harnesses declare `mp_context`'s layout in their own translation
unit and pass a pointer across the boundary; nothing in the pipeline checks
that the layout matches `target.c`'s. It happens to. This is an observation
about the published artifacts, not something measured here.

**(h) The gate is only definable where a hand-written reference exists.** One
benchmark, one target function, one corpus, one budget. It closes
`docs/PROTOCOL_FORMAT_MINING.md` §5.3 as a benchmark-level acceptance metric,
not as a production validator: wiring it into Stage 4 would cost a full fuzz
campaign per attempt, and for an arbitrary target there is no `structured.c`
to compare against.

**(i) The verdict is budget-relative.** It is stated at one execution count,
and the sensitivity section gives the same arms at another. Where the two
disagree, the honest reading is that the contract path needs more executions
to reach what the reference reaches at once -- a property of the harness, not
a defect of the measurement -- and not that either number is wrong.

**(j) What is not claimed.** Not that the contract path outperforms the
FT-only path (provenance is uncontrolled, see (d)). Not that coverage
equivalence holds in general (one benchmark, one budget, see (h)). Not that an
accepted contract means the gates work -- acceptance and coverage equivalence
are different properties, and this measures only the second.
"""


def render_report(measurements: Mapping[str, Any]) -> str:
    """Render the whole document.  The report is generated, never hand-edited."""

    lines: list[str] = []
    add = lines.append
    arms = {
        arm.get("name"): arm for arm in measurements.get("arms", ())
        if isinstance(arm, Mapping)
    }
    config = measurements.get("config", {})
    gate = measurements.get("gate", {})
    engine = measurements.get("layers", {}).get(ENGINE_LAYER, {}).get("runs", ())
    target = measurements.get("layers", {}).get(TARGET_LAYER, {}).get("runs", ())
    seeds = list(config.get("seeds", ()))

    add("# Coverage equivalence: the contract path against the reference")
    add("")
    add(
        "`docs/PROTOCOL_FORMAT_MINING.md` §5.3 asks whether a spec-driven "
        "generic harness reaches the coverage the hand-written reference "
        "harness reaches. This document answers it for one benchmark, and it "
        "is generated from the measurement it reports: "
        "`harness_generation/coverage_arms.py` writes "
        "`tests/fixtures/coverage_arms/measurements.json`, and "
        "`python -m harness_generation coverage-arms --report "
        "docs/COVERAGE_EQUIVALENCE.md` renders that file into this one. No "
        "number below is typed by hand."
    )
    add("")
    add("## Arms")
    add("")
    add("| arm | role | recipe | sha256 | bytes | source |")
    add("| --- | --- | --- | --- | --- | --- |")
    for name, arm in arms.items():
        add(
            f"| `{name}` | `{arm.get('role')}` | `{arm.get('recipe')}` | "
            f"`{str(arm.get('sha256'))[:12]}` | {arm.get('size')} | "
            f"`{arm.get('path')}` |"
        )
    add("")
    add(
        "Only `published_contracted` and `published_ft_only` are candidates; "
        "the reference is a human baseline and `diagnostic_rejected` is the "
        "attempt the audit refused, measured to show what the refusal was "
        "worth. `--with-diagnostic-arm` is what includes it."
    )
    add("")
    add("## Budget and seeds")
    add("")
    add(
        f"`{config.get('runs')}` executions per arm per seed, seeds "
        f"{', '.join(str(seed) for seed in seeds)}, corpus "
        f"`{measurements.get('corpus', {}).get('path')}` copied by content "
        f"hash into every run. Coverage is measured with the sanitizers off "
        f"(`{_flag_summary(config, 'target_coverage', 'harness')}` for the "
        f"harness), so no arm is truncated by its own finding and equal "
        f"`-runs` is equal work."
    )
    add("")
    add(
        "```\n"
        + "\n".join(
            f"{name}: {version}"
            for name, version in sorted(measurements.get("toolchain", {}).items())
        )
        + "\n```"
    )
    add("")
    add("## Layer A — `instrumented_program` (telemetry, not the gate)")
    add("")
    add(
        "libFuzzer `cov`/`ft` over the whole instrumented program, harness "
        "included, built with the sanitizers the pipeline uses. A run that "
        "found something stopped at the finding, so its numbers are "
        "coverage-at-first-crash and are not comparable across arms."
    )
    add("")
    add("| arm | seed | status | cov | ft | executed | truncated | findings |")
    add("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for run in engine:
        add(
            f"| `{run.get('arm')}` | {run.get('seed')} | `{run.get('status')}` | "
            f"{run.get('coverage_edges_or_blocks')} | {run.get('features')} | "
            f"{run.get('executed_units')} | "
            f"{'yes' if run.get('truncated_by_finding') else 'no'} | "
            f"{', '.join(run.get('findings', ())) or '—'} |"
        )
    add("")
    add("## Layer B — `target_code` (the gate)")
    add("")
    add(
        "LLVM source-based coverage filtered to `target.c`, sanitizers off, "
        "every arm at the same `-runs`. `functions` is reported and not gated: "
        "a single-TU build can inline a target function into the harness and "
        "leave its own counter at zero while its regions are covered."
    )
    add("")
    add("| arm | seed | status | lines | regions | branches | functions | entered |")
    add("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for run in target:
        totals = run.get("totals", {})
        add(
            f"| `{run.get('arm')}` | {run.get('seed')} | `{run.get('status')}` | "
            f"{_cell(totals, 'lines')} | {_cell(totals, 'regions')} | "
            f"{_cell(totals, 'branches')} | {_cell(totals, 'functions')} | "
            f"{', '.join(run.get('entered_functions', ())) or '—'} |"
        )
    add("")
    add("### Seed spread")
    add("")
    varying = seed_spread(target)
    if varying:
        add(
            "The seed changes the target coverage of "
            + ", ".join(f"`{name}`" for name in varying)
            + ". Every other arm measures the same at every seed, so for "
            "those the rows above are one measurement."
        )
    else:
        add(
            f"Every arm's target coverage is identical at every one of the "
            f"{len(seeds)} seeds, so the sweep corroborates one measurement "
            f"rather than three: at this budget the search saturates and the "
            f"seeds do not separate the arms. That is a fact about the budget "
            f"rather than a defect of the seeds, and it is why the budget "
            f"sensitivity section below is where the verdict's dependence on "
            f"executions shows. An arm that stops short of the reference "
            f"stops short at all three seeds."
        )
    add("")
    refused = rejected_arm(measurements)
    if refused:
        add("### The refused attempt")
        add("")
        refused_bounds = percent_range(target, refused)
        published_bounds = percent_range(target, gate.get("candidate"))
        add(
            f"`{refused}` is the attempt Stage 4 refused, measured here only as "
            f"a diagnostic. Its target coverage is "
            f"{_range_text(refused_bounds)}; `{gate.get('candidate')}`'s is "
            f"{_range_text(published_bounds)}."
        )
        add("")
        add(
            "Target coverage does not separate them."
            if refused_bounds == published_bounds else
            "The two differ on at least one metric, on at least one seed."
        )
        add("")
        add(
            "Either way the audit was not a coverage filter. It refused this "
            "harness for reimplementing one of the project's own algorithms, "
            "which is a judgement about the harness rather than about how much "
            "of the target it reaches -- so its target coverage says nothing "
            "about whether the refusal was right, and this arm is here only to "
            "show what the refusal cost in coverage terms. Nothing above "
            "endorses it: it stays what the gates made it, which is not a "
            "product, and it is not a candidate for the gate."
        )
        add("")
    control = measurements.get("recipe_control", {})
    add("### Recipe control")
    add("")
    add(
        f"`{control.get('pair', ['', ''])[1]}` minus "
        f"`{control.get('pair', ['', ''])[0]}`, in percentage points per seed:"
    )
    add("")
    add("| metric | " + " | ".join(f"seed {seed}" for seed in seeds) + " |")
    add("| --- | " + " | ".join("---" for _ in seeds) + " |")
    for metric, values in sorted(control.get("delta_percent", {}).items()):
        add(f"| `{metric}` | " + " | ".join(str(value) for value in values) + " |")
    add("")
    add(control.get("interpretation", ""))
    add("")
    determ = measurements.get("determinism")
    if isinstance(determ, Mapping):
        add("### Determinism")
        add("")
        add(
            f"`{determ.get('arm')}` at seed {determ.get('seed')}, run twice: "
            f"identical = `{determ.get('identical')}` over "
            f"{', '.join(determ.get('fields', ()))}. A same-seed repeat is a "
            f"replay, which is why the campaign counts distinct seeds instead."
        )
        add("")
    add("## Gate")
    add("")
    add(
        f"Candidate `{gate.get('candidate')}` (role "
        f"`{gate.get('candidate_role')}`) against `{gate.get('reference')}`, "
        f"tolerance {gate.get('tolerance')}, verdict **`{gate.get('verdict')}`**."
    )
    add("")
    add("| metric | seed | reference % | candidate % | ratio | strict | within tolerance |")
    add("| --- | --- | --- | --- | --- | --- | --- |")
    for metric, report in sorted(gate.get("metrics", {}).items()):
        for item in report.get("per_seed", ()):
            add(
                f"| `{metric}` | {item.get('seed')} | {item.get('reference_percent')} | "
                f"{item.get('candidate_percent')} | {item.get('ratio')} | "
                f"{item.get('passes_strict')} | {item.get('passes_tolerance')} |"
            )
    add("")
    add(
        "An arm-level verdict requires every seed to pass: a metric that holds "
        "at one seed and not another has not been shown to hold."
    )
    add("")
    sensitivity = measurements.get("budget_sensitivity")
    if isinstance(sensitivity, Mapping) and sensitivity:
        add("## Budget sensitivity")
        add("")
        add(
            "The same arms at other budgets, coverage layer only. A harness "
            "that has to search for an input the target accepts needs "
            "executions to reach what a harness that constructs a valid frame "
            "directly reaches at once, so this is where a verdict that is "
            "really a statement about one budget shows itself."
        )
        add("")
        for budget in sorted(sensitivity, key=int):
            block = sensitivity[budget]
            records = block.get("runs_records", ())
            add(f"### `-runs={block.get('runs')}`")
            add("")
            add("| arm | seed | status | lines | regions | branches |")
            add("| --- | --- | --- | --- | --- | --- |")
            for run in records:
                totals = run.get("totals", {})
                add(
                    f"| `{run.get('arm')}` | {run.get('seed')} | "
                    f"`{run.get('status')}` | {_cell(totals, 'lines')} | "
                    f"{_cell(totals, 'regions')} | {_cell(totals, 'branches')} |"
                )
            add("")
            verdict = evaluate_gate(
                measurements, records=records, budget=block.get("runs"),
            )
            add(
                f"Verdict at this budget: **`{verdict.get('verdict')}`** "
                f"(min ratios "
                + ", ".join(
                    f"`{metric}` {report.get('min_ratio')}"
                    for metric, report in sorted(verdict.get("metrics", {}).items())
                )
                + ")"
            )
            add("")
    add("## Caveats")
    add("")
    add(CAVEATS)
    add("## Reproduce")
    add("")
    add("```bash")
    add("python -m harness_generation coverage-arms \\")
    add("    --artifacts artifacts/coverage_arms \\")
    add(f"    --runs {config.get('runs')} \\")
    add(f"    --seeds {','.join(str(seed) for seed in seeds)} \\")
    add("    --with-diagnostic-arm \\")
    add("    --record tests/fixtures/coverage_arms/measurements.json")
    add("python -m harness_generation coverage-arms --report docs/COVERAGE_EQUIVALENCE.md")
    add("python -m harness_generation coverage-arms --check")
    add("```")
    add("")
    return "\n".join(lines)


def _cell(totals: Mapping[str, Any], metric: str) -> str:
    item = totals.get(metric)
    if not isinstance(item, Mapping):
        return "—"
    return f"{item.get('covered')}/{item.get('count')} ({item.get('percent')}%)"


def _flag_summary(config: Mapping[str, Any], layer: str, part: str) -> str:
    flags = config.get("recipe", {}).get(layer, {}).get(part, ())
    return " ".join(str(flag) for flag in flags) or "the target's flags"


# --- entry point -------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="harness-generation coverage-arms",
        description=(
            "Measure harness arms against one target and report whether the "
            "contract path reaches the reference's target coverage."
        ),
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--artifacts", type=Path, default=Path("artifacts") / "coverage_arms",
    )
    parser.add_argument("--runs", type=int, default=20_000)
    parser.add_argument("--seeds", default="1,2,3", help="Comma-separated seeds.")
    parser.add_argument("--seconds-cap", type=int, default=300)
    parser.add_argument(
        "--sensitivity-runs",
        default="",
        help=(
            "Comma-separated extra execution budgets for the coverage layer "
            "only, so a budget-relative verdict shows itself."
        ),
    )
    parser.add_argument(
        "--with-diagnostic-arm",
        action="store_true",
        help="Also measure the refused attempt, as a labelled diagnostic.",
    )
    parser.add_argument("--record", type=Path, help="Write the measurements here.")
    parser.add_argument("--report", type=Path, help="Render a report from --record.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Re-derive every verdict offline; needs no compiler and no LLM.",
    )
    args = parser.parse_args(argv)

    try:
        if args.check:
            return _check_main(args)
        if args.report is not None:
            return _report_main(args)
        return _run_main(args)
    except CoverageArmsError as error:
        print(f"Coverage arms failed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f"Coverage arms failed: {error}", file=sys.stderr)
        return 1


def _seeds(text: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in text.split(",") if part.strip())
    except ValueError:
        raise CoverageArmsError(f"--seeds must be integers, not {text!r}")


def _run_main(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    config = CoverageArmsConfig(
        runs=args.runs,
        seeds=_seeds(args.seeds),
        seconds_cap=args.seconds_cap,
        sensitivity_runs=_seeds(args.sensitivity_runs) if args.sensitivity_runs else (),
    )
    document = run_campaign(
        manifest, config,
        artifacts=args.artifacts,
        include_diagnostic=args.with_diagnostic_arm,
    )
    gate = document["gate"]
    print(f"Arms: {len(document['arms'])}  runs/arm/seed: {config.runs}")
    for metric, report in sorted(gate["metrics"].items()):
        print(
            f"{metric}: min ratio {report['min_ratio']} "
            f"(strict {report['passes_strict']}, "
            f"within tolerance {report['passes_tolerance']})"
        )
    print(f"Verdict: {gate['verdict']}")
    if args.record is not None:
        args.record.parent.mkdir(parents=True, exist_ok=True)
        args.record.write_text(
            json.dumps(document, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        print(f"Measurements: {args.record}")
    return 0


def _report_main(args: argparse.Namespace) -> int:
    if args.record is None or not Path(args.record).is_file():
        raise CoverageArmsError("--report needs --record pointing at existing evidence")
    measurements = json.loads(Path(args.record).read_text(encoding="utf-8"))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_report(measurements), encoding="utf-8")
    print(f"Report: {args.report}")
    return 0


def _check_main(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest)
    record = args.record or (manifest_path.parent / "measurements.json")
    if not Path(record).is_file():
        raise CoverageArmsError(f"no measurements to check at {record}")
    measurements = json.loads(Path(record).read_text(encoding="utf-8"))
    problems = check_measurements(
        manifest_path, measurements,
        doc_path=DEFAULT_REPORT if DEFAULT_REPORT.is_file() else None,
    )
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(f"OK: {record} matches {manifest_path}")
    return 0
