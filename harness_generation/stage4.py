"""Stage 4: transform Stage 3 rough code into an audited libFuzzer harness."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .artifacts import ArtifactStore
from .generation_output import normalize_c_response
from .generation_context import (bounded_validation_feedback,
                                 project_type_context)
from .llm import LLMClient, LLMGeneration
# The policy sets live in one place; see :mod:`harness_generation.policy`.
from .policy import (
    DEFAULT_ALLOWED_FUNCTIONS,
    FORBIDDEN_IO_FUNCTIONS,
    FORBIDDEN_LOGGING_FUNCTIONS,
)
from .prompts import stage4_harness_plan, stage4_harness_transform
from .protocol_ir import ProtocolIR, ProtocolIRError
from .protocol_ir_helpers import ProtocolHelperSet, collect_protocol_helpers
from .protocol_plan_validation import (
    protocol_contract_projection,
    validate_plan_contract,
)
from .sfg_adapter import is_null_node
from .source_paths import SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS
from .stage4_outcome import record_parse_result
from .triplet import FunctionTriplet
from .validation import select_language


FUZZ_ENTRY = "LLVMFuzzerTestOneInput"
#: The only copies the repaired-frame connection recognises, and it recognises
#: them by the callee name alone -- see :func:`_isf_input_connection`.
_COPY_CALLS = {"memcpy", "memmove"}
#: A parameter name that says "this integer is the length of the frame".
_LENGTH_PARAMETER_NAMES = {
    "size", "len", "length", "n", "data_size", "buffer_size",
}
#: A bare C identifier and nothing else: ``frame``, never ``frame + 8``.
_BARE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class Stage4Error(ValueError):
    """The Stage 4 input or generated harness violates the frozen contract."""


@dataclass(frozen=True)
class HarnessPlan:
    """Structured Stage 4 plan that constrains final C harness generation."""

    triplet_id: str
    entrypoint: str
    input_strategy: Mapping[str, Any]
    state_objects: tuple[Mapping[str, Any], ...]
    call_sequence: tuple[Mapping[str, Any], ...]
    cleanup_sequence: tuple[Mapping[str, Any], ...]
    constraints: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    generation_metadata: Mapping[str, Any] = field(default_factory=dict)
    #: The plan's structured promise to the mined protocol contract.  ``None``
    #: on the FT-only path, and then ``to_dict()`` omits the key entirely, so a
    #: run with no ``protocol_ir.json`` writes the plan.json it always did.
    protocol_contract_bindings: Mapping[str, Any] | None = None
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        document = {
            "schema_version": self.schema_version,
            "triplet_id": self.triplet_id,
            "entrypoint": self.entrypoint,
            "input_strategy": dict(self.input_strategy),
            "state_objects": [dict(item) for item in self.state_objects],
            "call_sequence": [dict(item) for item in self.call_sequence],
            "cleanup_sequence": [dict(item) for item in self.cleanup_sequence],
            "constraints": list(self.constraints),
            "notes": list(self.notes),
            "generation_metadata": dict(self.generation_metadata),
        }
        if self.protocol_contract_bindings is not None:
            document["protocol_contract_bindings"] = dict(
                self.protocol_contract_bindings
            )
        return document


@dataclass(frozen=True)
class Stage4Result:
    triplet_id: str
    harness_code: str
    harness_path: Path
    stable_path: Path | None
    generation_metadata: Mapping[str, Any]
    attempt_directory: Path
    harness_plan: Mapping[str, Any] = field(default_factory=dict)
    #: How the accepted harness was judged to feed the fuzzer's bytes to the
    #: ISF, or ``None`` when nothing was recorded.  Kept out of
    #: ``generation_metadata``, whose key set is pinned by the existing tests.
    input_connection: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class _Parameter:
    name: str | None
    base_type: str
    qualifiers: tuple[str, ...]
    pointer_depth: int


@dataclass(frozen=True)
class _Argument:
    text: str
    identifiers: tuple[str, ...]
    has_string_literal: bool


@dataclass(frozen=True)
class _Call:
    name: str
    arguments: tuple[_Argument, ...]
    start_byte: int


@dataclass(frozen=True)
class _CopyRegion:
    """A stretch of a local buffer that an earlier statement filled from ``data``.

    Recorded per function by :func:`_copy_regions`, before the ISF call it might
    feed.  ``kind`` is ``"call"`` for a ``memcpy``/``memmove`` and ``"loop"`` for
    a byte-at-a-time ``for`` loop.
    """

    kind: str
    destination_identifiers: tuple[str, ...]
    destination_text: str
    source: _Argument
    length: _Argument
    text: str
    start_byte: int


@dataclass(frozen=True)
class _FunctionDefinition:
    name: str
    return_type: str
    parameters: tuple[_Parameter, ...]
    calls: tuple[_Call, ...]
    identifiers: tuple[str, ...]
    #: Names this function binds exactly once, with the identifiers that one
    #: binding mentions.  See :func:`_unique_local_aliases`.
    local_aliases: tuple[tuple[str, tuple[str, ...]], ...] = ()
    #: Regions of local buffers this function fills from ``data``.  See
    #: :func:`_copy_regions`.
    copy_regions: tuple[_CopyRegion, ...] = ()


@dataclass(frozen=True)
class _HarnessAnalysis:
    functions: tuple[_FunctionDefinition, ...]
    calls: tuple[_Call, ...]


@dataclass(frozen=True)
class _InputConnection:
    """How one ISF call was judged to consume the fuzzer's bytes."""

    kind: str
    isf: str
    buffer_argument: str
    size_argument: str
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "isf": self.isf,
            "buffer_argument": self.buffer_argument,
            "size_argument": self.size_argument,
            "evidence": list(self.evidence),
        }


class Stage4Generator:
    """Generate, validate, and publish one FT-specific libFuzzer harness."""

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def run(
        self,
        triplet: FunctionTriplet,
        *,
        rough_code: str | Path,
        functions_json: str | Path,
        artifacts: str | Path,
        publish: bool = True,
        rollback_source: str | None = None,
        retry_reason: str | None = None,
        retry_context: Mapping[str, Any] | None = None,
    ) -> Stage4Result:
        rough_source = _load_rough_code(rough_code)
        (function_metadata, all_project_functions, project_context,
         static_project_functions) = _load_function_metadata(
            Path(functions_json), triplet
        )
        isf_metadata = function_metadata[triplet.isf.function_id]
        validation_feedback = _stage4_validation_feedback(
            retry_context,
            triplet_id=triplet.id,
            unique_isf_function_id=str(isf_metadata.get("id", "")),
        )
        protocol_ir = load_protocol_ir(artifacts)
        # The helpers the audit may accept are read out of the IR's own
        # provenance.  With no IR this is the empty set, so the audit is byte
        # for byte the FT-only one it was before any of this existed.
        protocol_helpers = collect_protocol_helpers(protocol_ir)
        # The same intersection the harness audit uses, so a helper the plan
        # is allowed to name is exactly one the audit will accept the call to.
        declared_helpers = _declared_helpers(protocol_helpers, all_project_functions)
        protocol = _protocol_contract(artifacts, protocol_ir)
        protocol_contract = None if protocol is None else protocol[0]
        # The typed digest of the IR that the plan has to declare it preserves.
        # ``None`` with no IR, and then no plan carries bindings at all.
        projection = protocol_contract_projection(
            protocol_ir, project_functions=all_project_functions
        )
        plan_prompt = stage4_harness_plan(
            triplet_id=triplet.id,
            rough_code=rough_source,
            unique_isf={
                **isf_metadata,
                "structural_edges": [
                    edge.to_dict()
                    for edge in triplet.edges
                    if edge.function_id == triplet.isf.function_id
                ],
            },
            function_metadata=[
                function_metadata[function.function_id]
                for function in triplet.functions
            ],
            bypass_semantics=[
                semantic.to_dict() for semantic in triplet.bypass_semantics
            ],
            project_context=project_context,
            protocol_contract=protocol_contract,
            protocol_contract_bindings=(
                None if projection is None else projection.renderable()
            ),
            validation_feedback=validation_feedback,
        )
        layout = ArtifactStore(Path(artifacts)).for_triplet(triplet.id)
        layout.ensure_generation()
        attempt, attempt_directory = layout.next_attempt("stage4")
        layout.write_text(attempt_directory / "plan_prompt.txt", plan_prompt.content)
        try:
            plan_generation = self.llm.generate(plan_prompt)
            harness_plan = parse_harness_plan(
                plan_generation.content,
                triplet=triplet,
                isf_metadata=isf_metadata,
                declared_helpers=declared_helpers,
            )
            # The gate sits here, not after the harness audit: a plan that moved
            # the payload offset, dropped a repair or invented a helper must not
            # be allowed to shape the C source in the first place.  Failing now
            # makes the attempt a plan failure, so the existing retry loop hands
            # the violations back as validation feedback.
            conformance = validate_plan_contract(
                harness_plan.protocol_contract_bindings,
                projection=projection,
                input_strategy=harness_plan.input_strategy,
            )
            if not conformance.ok:
                raise Stage4Error(
                    "HarnessPlan does not preserve the protocol contract: "
                    + "; ".join(conformance.violations)
                )
            plan_metadata = _generation_metadata(plan_generation)
            if protocol is not None:
                # Record where the contract came from, so a plan.json can be
                # traced back to the protocol_ir.json that conditioned it.
                # Absent when there is no IR: the fallback run's plan.json must
                # stay byte-for-byte what it was before this path existed.
                plan_metadata["protocol_ir"] = protocol[1]
            harness_plan = replace(
                harness_plan,
                generation_metadata=plan_metadata,
            )
        except Exception as error:
            response = (
                "" if "plan_generation" not in locals()
                else plan_generation.content
            )
            layout.write_text(attempt_directory / "plan_response.txt", response)
            layout.write_json(attempt_directory / "metadata.json", _attempt_metadata(
                triplet.id, attempt, None, rollback_source, retry_reason,
                retry_context, client=self.llm,
                prompt_version=plan_prompt.prompt_version,
                plan_prompt_version=plan_prompt.prompt_version,
            ))
            record_parse_result(layout, attempt_directory, {
                "status": "failed",
                "phase": "harness_plan",
                "error_type": type(error).__name__,
                "error": str(error),
            })
            raise
        layout.write_text(
            attempt_directory / "plan_response.txt", plan_generation.content
        )
        layout.write_json(attempt_directory / "plan.json", harness_plan.to_dict())

        prompt = stage4_harness_transform(
            harness_plan=harness_plan.to_dict(),
            rough_code=rough_source,
            unique_isf={
                **isf_metadata,
                "structural_edges": [
                    edge.to_dict()
                    for edge in triplet.edges
                    if edge.function_id == triplet.isf.function_id
                ],
            },
            function_metadata=[
                function_metadata[function.function_id]
                for function in triplet.functions
            ],
            project_context=project_context,
            protocol_contract=protocol_contract,
            validation_feedback=validation_feedback,
        )
        layout.write_text(attempt_directory / "prompt.txt", prompt.content)
        try:
            generation = self.llm.generate(prompt)
        except Exception as error:
            layout.write_text(attempt_directory / "response.txt", "")
            layout.write_json(attempt_directory / "metadata.json", _attempt_metadata(
                triplet.id, attempt, None, rollback_source, retry_reason,
                retry_context, client=self.llm,
                prompt_version=prompt.prompt_version,
                plan_prompt_version=plan_prompt.prompt_version,
            ))
            record_parse_result(layout, attempt_directory, {
                "status": "failed",
                "phase": "harness_code",
                "error_type": type(error).__name__,
                "error": str(error),
            })
            raise
        harness = normalize_cpp_harness(normalize_c_response(generation.content))
        layout.write_text(attempt_directory / "response.txt", generation.content)
        layout.write_text(attempt_directory / "harness.c", harness + "\n")
        layout.write_json(attempt_directory / "metadata.json", _attempt_metadata(
            triplet.id, attempt, generation, rollback_source, retry_reason,
            retry_context, plan_prompt_version=plan_prompt.prompt_version,
            plan_generation=plan_generation,
        ))
        try:
            analysis = _analyze_c(harness)
            input_connection = _validate_harness(
                analysis,
                triplet,
                isf_metadata,
                all_project_functions,
                protocol_helpers=protocol_helpers,
                static_project_functions=static_project_functions,
                # An IR is what asks for a frame to be built; without one the
                # repaired-frame rule stays exactly the rule it always was.
                structured_frame=protocol_ir is not None,
            )
        except Exception as error:
            record_parse_result(layout, attempt_directory, {
                "status": "failed",
                "phase": "harness_code",
                "error_type": type(error).__name__,
                "error": str(error),
            })
            raise

        harness_path = layout.stage4_harness
        persisted = harness + "\n"
        layout.write_json(layout.stage4_harness_plan, harness_plan.to_dict())
        layout.write_text(harness_path, persisted)
        stable_path = None
        if publish:
            stable_path = layout.harness
            layout.write_text(stable_path, persisted)
        connection_record = (
            None if input_connection is None else input_connection.to_dict()
        )
        passed_record: dict[str, Any] = {
            "status": "passed",
            "harness_plan": harness_plan.to_dict(),
            "definitions": [function.name for function in analysis.functions],
            "calls": sorted({call.name for call in analysis.calls}),
            "input_connection": connection_record,
        }
        if projection is not None:
            # What the plan was measured against, and what the comparison
            # deliberately could not decide.  Absent without an IR, so an
            # FT-only attempt record stays exactly what it was.
            passed_record["protocol_contract_conformance"] = conformance.to_dict()
        record_parse_result(layout, attempt_directory, passed_record)
        return Stage4Result(
            triplet_id=triplet.id,
            harness_code=harness,
            harness_path=harness_path,
            stable_path=stable_path,
            generation_metadata=_generation_metadata(generation),
            attempt_directory=attempt_directory,
            harness_plan=harness_plan.to_dict(),
            input_connection=connection_record,
        )


def generate_stage4_harness(
    triplet: FunctionTriplet,
    llm: LLMClient,
    *,
    rough_code: str | Path,
    functions_json: str | Path,
    artifacts: str | Path,
    publish: bool = True,
) -> Stage4Result:
    return Stage4Generator(llm).run(
        triplet,
        rough_code=rough_code,
        functions_json=functions_json,
        artifacts=artifacts,
        publish=publish,
    )


def load_protocol_contract(
    artifacts: str | Path,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """The mined protocol contract at ``<artifacts>/protocol_ir.json``, if any.

    Returns ``(contract, provenance)``, or ``None`` when the file is not there.
    The contract is :meth:`~protocol_ir.ProtocolIR.to_protocol_contract`, the
    same ``protocol.json`` shaped document ``load_protocol_spec`` accepts, so
    the prompt sees one projection of the IR and not a second one invented here.
    ``provenance`` is what gets recorded next to the plan: the file the contract
    came from, the entry function it describes, and how stable the C-block
    inference behind it was.

    This is the *only* discovery location: the root ``protocol-mine --output``
    wrote, which is the root Stage 4 was already handed.  There is deliberately
    no second one and no flag -- a stage that can silently look elsewhere is a
    stage whose input cannot be read off the command line.

    A file that is present but unreadable or invalid is a hard
    :class:`Stage4Error`, never a fallback to the contract-free prompt.  The
    fallback would produce a harness that looks like it was built from the
    protocol while having been told nothing about it, which is a much worse
    failure than stopping: the run would *pass* and the resulting harness would
    be quietly wrong about frame layout, length repair and context lifetime.
    """

    return _protocol_contract(artifacts, load_protocol_ir(artifacts))


def load_protocol_ir(artifacts: str | Path) -> ProtocolIR | None:
    """The mined IR itself, or ``None`` when no ``protocol_ir.json`` is there.

    ``run()`` needs the IR and not only its contract projection, because the
    audit reads the helper names out of the IR's own provenance, and the
    pipeline reads the same names back when it re-validates the published
    harness.  The public :func:`load_protocol_contract` is a view over this: it
    discards the IR and returns exactly the pair, with exactly the error
    messages, it always did.
    """

    path = ArtifactStore(Path(artifacts)).protocol_ir
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Stage4Error(
            f"cannot read protocol IR {path}: {type(error).__name__}: {error}"
        ) from error
    try:
        return ProtocolIR.from_json(document)
    except ProtocolIRError as error:
        raise Stage4Error(f"invalid protocol IR {path}: {error}") from error


def _protocol_contract(
    artifacts: str | Path,
    ir: ProtocolIR | None,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """``(contract, provenance)`` for an already-loaded IR, or ``None``."""

    if ir is None:
        return None
    return ir.to_protocol_contract(), {
        "path": str(ArtifactStore(Path(artifacts)).protocol_ir),
        "entry_function": ir.entry_function,
        "llm_confidence": ir.llm_confidence,
    }


def _load_rough_code(value: str | Path) -> str:
    if isinstance(value, Path):
        try:
            source = value.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise Stage4Error(f"cannot load Stage 3 rough code: {type(error).__name__}") from error
    elif isinstance(value, str):
        source = value
    else:
        raise Stage4Error("rough_code must be C source text or a Path")
    if not source.strip():
        raise Stage4Error("Stage 3 rough code is empty")
    return source


def normalize_cpp_harness(source: str) -> str:
    """Constrain Stage 4 output to a C++ libFuzzer translation unit.

    LLMs often emit the right body but omit the standard integer/size headers
    or the C linkage required when a C target is linked with a C++ harness.  This
    normalization is intentionally mechanical and auditable: it does not invent
    target calls or alter function ordering.
    """

    harness = source.strip()
    harness = _ensure_cpp_standard_headers(harness)
    harness = _wrap_project_header_includes_for_c_linkage(harness)
    harness = _ensure_extern_c_fuzzer_entry(harness)
    return harness.strip()


def _ensure_cpp_standard_headers(source: str) -> str:
    required = []
    if not re.search(r'^\s*#\s*include\s*[<"](?:stddef\.h|cstddef)[>"]',
                     source, re.MULTILINE):
        required.append("#include <stddef.h>")
    if not re.search(r'^\s*#\s*include\s*[<"](?:stdint\.h|cstdint)[>"]',
                     source, re.MULTILINE):
        required.append("#include <stdint.h>")
    if not required:
        return source
    return "\n".join((*required, source))


def _wrap_project_header_includes_for_c_linkage(source: str) -> str:
    lines = source.splitlines()
    wrapped: list[str] = []
    extern_depth = 0
    extern_opener = re.compile(r'^\s*extern\s+"C"\s*\{')
    quoted_include = re.compile(r'^(\s*)#\s*include\s*"([^"]+)"\s*$')
    for line in lines:
        in_extern_block = extern_depth > 0
        if extern_opener.search(line):
            extern_depth += line.count("{") - line.count("}")
            wrapped.append(line)
            continue
        match = quoted_include.match(line)
        if match and not in_extern_block:
            indent = match.group(1)
            wrapped.append(f'{indent}extern "C" {{')
            wrapped.append(line)
            wrapped.append(f"{indent}}}")
        else:
            wrapped.append(line)
        if in_extern_block:
            extern_depth += line.count("{") - line.count("}")
            if extern_depth < 0:
                extern_depth = 0
    return "\n".join(wrapped)


def _ensure_extern_c_fuzzer_entry(source: str) -> str:
    if re.search(r'extern\s+"C"\s+int\s+LLVMFuzzerTestOneInput\s*\(', source):
        return source
    return re.sub(
        r'(?m)^(\s*)int\s+LLVMFuzzerTestOneInput\s*\(',
        r'\1extern "C" int LLVMFuzzerTestOneInput(',
        source,
        count=1,
    )


def parse_harness_plan(
    content: str,
    *,
    triplet: FunctionTriplet,
    isf_metadata: Mapping[str, Any],
    declared_helpers: Iterable[str] = (),
) -> HarnessPlan:
    """Parse and validate the strict JSON HarnessPlan returned by the LLM.

    ``declared_helpers`` are the contract-declared helpers the project really
    defines (see ``_declared_helpers``); they may be planned alongside the FT
    without being FT members.  The default empty sequence makes every caller
    that does not supply one behave as it did before the protocol IR could
    reach this validator at all.
    """

    if not isinstance(content, str) or not content.strip():
        raise Stage4Error("HarnessPlan response is empty")
    if "```" in content:
        raise Stage4Error("HarnessPlan must be strict JSON without Markdown fences")
    try:
        document = json.loads(content)
    except json.JSONDecodeError as error:
        raise Stage4Error(f"HarnessPlan is not valid JSON: {error}") from error
    if not isinstance(document, Mapping):
        raise Stage4Error("HarnessPlan must be a JSON object")
    if document.get("schema_version") != 1:
        raise Stage4Error("HarnessPlan requires schema_version 1")
    if document.get("triplet_id") != triplet.id:
        raise Stage4Error("HarnessPlan triplet_id does not match the FT")
    if document.get("entrypoint") != FUZZ_ENTRY:
        raise Stage4Error(f"HarnessPlan entrypoint must be {FUZZ_ENTRY}")
    forbidden_keys = {"harness_code", "c_source", "source_code", "final_code"}
    if forbidden_keys & set(document):
        raise Stage4Error("HarnessPlan must not contain final C source fields")
    serialized = json.dumps(document, sort_keys=True)
    if "#include" in serialized or f"{FUZZ_ENTRY}(" in serialized:
        raise Stage4Error("HarnessPlan must not embed final C harness source")

    input_strategy = document.get("input_strategy")
    if not isinstance(input_strategy, Mapping):
        raise Stage4Error("HarnessPlan input_strategy must be an object")
    if input_strategy.get("data_identifier") != "data" or \
            input_strategy.get("size_identifier") != "size":
        raise Stage4Error("HarnessPlan must bind fuzzer data and size identifiers")

    call_sequence = _plan_object_list(document, "call_sequence")
    cleanup_sequence = _plan_object_list(document, "cleanup_sequence")
    state_objects = _plan_object_list(document, "state_objects")
    constraints = _plan_string_list(document, "constraints")
    notes = _plan_string_list(document, "notes")

    expected = {function.function for function in triplet.functions}
    # Contract-declared helpers may be planned alongside the FT, but they are
    # not FT members: they are exempt from the exactly-once rule and from the
    # completeness and duplication counts below.
    helpers = frozenset(declared_helpers)
    planned_calls = [_plan_function(item, "call_sequence") for item in call_sequence]
    planned_cleanup = [
        _plan_function(item, "cleanup_sequence") for item in cleanup_sequence
    ]
    all_planned = planned_calls + planned_cleanup
    unknown = sorted(set(all_planned) - expected - helpers)
    if unknown:
        message = ("HarnessPlan references functions outside the FT: "
                   + ", ".join(unknown))
        if helpers:
            message += (" (declared helpers are exempt: "
                        + ", ".join(sorted(helpers)) + ")")
        raise Stage4Error(message)
    ft_planned = [name for name in all_planned if name in expected]
    missing = sorted(expected - set(ft_planned))
    if missing:
        raise Stage4Error("HarnessPlan omits FT functions: " + ", ".join(missing))
    duplicated = sorted(
        name for name in set(ft_planned) if ft_planned.count(name) > 1
    )
    if duplicated:
        raise Stage4Error(
            "HarnessPlan duplicates FT functions: " + ", ".join(duplicated)
        )
    if triplet.isf.function not in planned_calls:
        raise Stage4Error("HarnessPlan must place the unique ISF in call_sequence")
    if triplet.isf.function in planned_cleanup:
        raise Stage4Error("HarnessPlan must not place the unique ISF in cleanup_sequence")

    isf_step = next(
        item for item in call_sequence
        if item.get("function") == triplet.isf.function
    )
    if _isf_requires_stream_size(isf_metadata) and (
        isf_step.get("uses_fuzzer_data") is not True
        or isf_step.get("uses_fuzzer_size") is not True
    ):
        raise Stage4Error(
            "HarnessPlan ISF step must use both fuzzer data and fuzzer size"
        )

    prf_names = {function.function for function in triplet.prfs}
    for function in triplet.functions:
        if "PRF" in function.roles and "HPF" in function.roles:
            if function.function not in planned_calls:
                raise Stage4Error(
                    "HarnessPlan must keep PRF+HPF functions in call_sequence: "
                    + function.function
                )
        elif "HPF" in function.roles and function.function_id != triplet.isf.function_id:
            if function.function not in prf_names and function.function not in planned_cleanup:
                raise Stage4Error(
                    "HarnessPlan must place pure HPF cleanup in cleanup_sequence: "
                    + function.function
                )

    # The bindings are only type-checked here.  Whether they *match* the mined
    # contract is a question about the IR, which this function never sees; see
    # protocol_plan_validation.validate_plan_contract.
    bindings = document.get("protocol_contract_bindings")
    if bindings is not None and not isinstance(bindings, Mapping):
        raise Stage4Error(
            "HarnessPlan protocol_contract_bindings must be an object"
        )

    return HarnessPlan(
        triplet_id=triplet.id,
        entrypoint=FUZZ_ENTRY,
        input_strategy=dict(input_strategy),
        state_objects=tuple(dict(item) for item in state_objects),
        call_sequence=tuple(dict(item) for item in call_sequence),
        cleanup_sequence=tuple(dict(item) for item in cleanup_sequence),
        constraints=tuple(constraints),
        notes=tuple(notes),
        protocol_contract_bindings=None if bindings is None else dict(bindings),
    )


def _plan_object_list(document: Mapping[str, Any], field: str) -> tuple[Mapping[str, Any], ...]:
    value = document.get(field)
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise Stage4Error(f"HarnessPlan {field} must be an array of objects")
    return tuple(value)


def _plan_string_list(document: Mapping[str, Any], field: str) -> tuple[str, ...]:
    value = document.get(field, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise Stage4Error(f"HarnessPlan {field} must be an array of strings")
    return tuple(value)


def _plan_function(item: Mapping[str, Any], field: str) -> str:
    function = item.get("function")
    if not isinstance(function, str) or not function.strip():
        raise Stage4Error(f"HarnessPlan {field} item requires function")
    arguments = item.get("arguments", [])
    if not isinstance(arguments, list) or any(not isinstance(value, str)
                                             for value in arguments):
        raise Stage4Error(f"HarnessPlan {field} arguments must be strings")
    return function


def _isf_requires_stream_size(metadata: Mapping[str, Any]) -> bool:
    parameters = metadata.get("parameters", [])
    if not isinstance(parameters, list):
        return False
    has_stream = any(
        isinstance(parameter, Mapping)
        and parameter.get("is_pointer") is True
        and parameter.get("is_struct_like") is not True
        and parameter.get("base_type") in {
            "void", "char", "unsigned char", "int8_t", "uint8_t"
        }
        for parameter in parameters
    )
    has_length = any(
        isinstance(parameter, Mapping)
        and parameter.get("is_pointer") is not True
        and str(parameter.get("name", "")).lower() in _LENGTH_PARAMETER_NAMES
        for parameter in parameters
    )
    return has_stream and has_length


def _load_function_metadata(
    path: Path,
    triplet: FunctionTriplet,
) -> tuple[dict[str, dict[str, Any]], set[str], dict[str, Any], frozenset[str]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Stage4Error(f"cannot load functions.json: {type(error).__name__}") from error
    if (not isinstance(document, Mapping)
            or document.get("schema_version") not in SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS):
        raise Stage4Error("functions.json requires schema_version 1 or 2")
    records = document.get("functions")
    if not isinstance(records, list) or any(not isinstance(item, Mapping)
                                            for item in records):
        raise Stage4Error("functions.json functions must be an array of objects")

    by_id = {}
    all_names = set()
    static_names = set()
    for record in records:
        function_id = _required_string(record, "id", "functions.json")
        name = _required_string(record, "name", function_id)
        if function_id in by_id:
            raise Stage4Error(f"duplicate functions.json function id: {function_id}")
        by_id[function_id] = record
        all_names.add(name)
        storage = record.get("storage", [])
        # Internal linkage, so no other translation unit can call it.  The
        # miner has always recorded this; only Stage 4 used to drop it, which
        # is why the audit could promise a call the linker cannot resolve.
        if isinstance(storage, list) and any(
            str(item).strip().lower() == "static" for item in storage
        ):
            static_names.add(name)

    selected = {}
    for function in triplet.functions:
        record = by_id.get(function.function_id)
        if record is None or record.get("name") != function.function:
            raise Stage4Error(
                f"FT function is missing or mismatched in functions.json: {function.function_id}"
            )
        parameters = record.get("parameters", [])
        if not isinstance(parameters, list) or any(not isinstance(item, Mapping)
                                                   for item in parameters):
            raise Stage4Error(f"invalid parameters for {function.function_id}")
        selected[function.function_id] = {
            "id": function.function_id,
            "name": function.function,
            "roles": list(function.roles),
            "signature": record.get("signature"),
            "return_type": record.get("return_type"),
            "parameters": [dict(parameter) for parameter in parameters],
            "file": record.get("file"),
            "start_line": record.get("start_line"),
        }
    return selected, all_names, project_type_context(document), frozenset(static_names)


def _analyze_c(source: str) -> _HarnessAnalysis:
    if not source:
        raise Stage4Error("LLM returned an empty Stage 4 harness")
    if "```" in source:
        raise Stage4Error("Stage 4 harness must not contain Markdown fences")
    try:
        import tree_sitter
    except ImportError as error:
        raise Stage4Error("tree-sitter C dependencies are required for Stage 4") from error

    # The harness is a C++ translation unit -- Stage 4 normalized it that way --
    # so it is parsed as one.  Reading it as C is what reported ``std::vector``
    # as "invalid C syntax" and filed a well-formed harness under a parse
    # failure.  The same chooser the intermediate validator uses, so the two
    # audits cannot disagree about what language a harness is written in.
    try:
        parser_name, language = select_language(source, tree_sitter)
    except ImportError as error:
        raise Stage4Error(
            "tree-sitter grammar dependencies are required for Stage 4"
        ) from error

    try:
        parser = tree_sitter.Parser(language)
    except TypeError:
        parser = tree_sitter.Parser()
        if hasattr(parser, "set_language"):
            parser.set_language(language)
        else:
            parser.language = language
    encoded = source.encode("utf-8")
    tree = parser.parse(encoded)
    if tree.root_node.has_error:
        raise Stage4Error(f"LLM returned invalid {parser_name} syntax")

    functions = []
    all_calls = []
    for node in _walk(tree.root_node):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        function_declarator = _find_function_declarator(declarator)
        name = _declarator_identifier(declarator, encoded)
        if name is None or function_declarator is None:
            raise Stage4Error("could not inspect a generated function definition")
        body = node.child_by_field_name("body")
        calls = tuple(_calls(body, encoded))
        all_calls.extend(calls)
        functions.append(_FunctionDefinition(
            name=name,
            return_type=_node_text(encoded, node.child_by_field_name("type")),
            parameters=tuple(_parameters(function_declarator, encoded)),
            calls=calls,
            identifiers=tuple(sorted({
                _node_text(encoded, current)
                for current in _walk(body)
                if current.type == "identifier"
            })) if body is not None else (),
            local_aliases=(_unique_local_aliases(body, encoded)
                           if body is not None else ()),
            copy_regions=(_copy_regions(body, encoded, calls)
                          if body is not None else ()),
        ))
    return _HarnessAnalysis(tuple(functions), tuple(all_calls))


def _identifier_names(node: Any, source: bytes) -> tuple[str, ...]:
    return tuple(sorted({
        _node_text(source, current)
        for current in _walk(node)
        if current.type == "identifier"
    }))


#: Node types whose value is not a plain expression over the identifiers it
#: mentions, so expanding a name bound to one of them would be a guess.
_OPAQUE_ALIAS_VALUE_TYPES = frozenset({
    "call_expression", "subscript_expression", "conditional_expression",
    "field_expression", "pointer_expression", "initializer_list",
    "string_literal", "concatenated_string",
})


def _unique_local_aliases(
    body: Any, source: bytes
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Names this function initialises once and never writes again.

    A repaired frame is usually sized by a local the harness computes first --
    ``size_t frame_len = MP_HEADER_SIZE + payload_len;`` -- and the ISF is then
    handed that name, so the copy's length and the ISF's length argument share
    no identifier even though they are the same number.  Expanding the name
    closes that gap without any flow analysis: a name whose only write is its
    own initialiser holds that one value wherever it is read, so expanding it can
    never invent a value.

    Two ways a name fails to qualify, both of them conservative:

    * it is written more than once -- ``payload_len`` under a clamp, or a
      ``frame_len`` clamped to ``sizeof(frame)`` afterwards.  The initialiser no
      longer describes what the call site sees, so it is not expanded;
    * its initialiser is not a plain arithmetic expression.  ``x = f(a, b)``
      mentions ``f``, ``a`` and ``b``, but ``x`` is not any of them, so
      expanding it would inject identifiers that are not part of the value.

    Either refusal can only ever leave a connection refused that the copy rule
    would otherwise have had to guess at.
    """

    candidates: dict[str, tuple[str, ...]] = {}
    written: dict[str, int] = {}
    for node in _walk(body):
        if node.type == "init_declarator":
            target = node.child_by_field_name("declarator")
            value = node.child_by_field_name("value")
            if target is None or target.type != "identifier":
                continue
            name = _node_text(source, target)
            written[name] = written.get(name, 0) + 1
            if value is None:
                continue
            if any(current.type in _OPAQUE_ALIAS_VALUE_TYPES for current in _walk(value)):
                continue
            candidates[name] = _identifier_names(value, source)
        elif node.type in {"assignment_expression", "update_expression"}:
            target = node.child_by_field_name(
                "left" if node.type == "assignment_expression" else "argument"
            )
            if target is not None and target.type == "identifier":
                name = _node_text(source, target)
                written[name] = written.get(name, 0) + 1
    return tuple(
        (name, identifiers)
        for name, identifiers in sorted(candidates.items())
        if written.get(name) == 1
    )


def _resolved_identifiers(
    identifiers: Iterable[str],
    aliases: Mapping[str, tuple[str, ...]],
) -> frozenset[str]:
    """``identifiers`` plus, transitively, what their local aliases name.

    Only :func:`_unique_local_aliases` decides what may be expanded, so this is
    a bounded rewrite rather than a data-flow walk.  Each name is expanded at
    most once, which makes the result the unique fixed point of the alias edges
    -- independent of the order they are visited in -- and terminates because the
    identifiers in a function are a finite set.
    """

    resolved = set(identifiers)
    if not aliases:
        return frozenset(resolved)
    pending = list(resolved)
    while pending:
        name = pending.pop()
        for target in aliases.get(name, ()):
            if target not in resolved:
                resolved.add(target)
                pending.append(target)
    return frozenset(resolved)


def _copy_regions(body: Any, source: bytes, calls: Iterable[_Call]) -> tuple[_CopyRegion, ...]:
    """Every copy out of ``data`` this function makes into a local buffer.

    Two spellings, both recognised purely by shape: a ``memcpy``/``memmove``
    call, and a byte-at-a-time ``for`` loop that stores into the buffer.  See
    :func:`_repaired_frame_connection` for how these are matched against an ISF
    call and for what this deliberately still misses.
    """

    regions = []
    for call in calls:
        if call.name not in _COPY_CALLS or len(call.arguments) < 3:
            continue
        destination, copied, length = call.arguments[:3]
        regions.append(_CopyRegion(
            kind="call",
            destination_identifiers=destination.identifiers,
            destination_text=destination.text,
            source=copied,
            length=length,
            text=_call_text(call),
            start_byte=call.start_byte,
        ))
    for node in _walk(body):
        region = _loop_copy_region(node, source)
        if region is not None:
            regions.append(region)
    # Source order, so the first matching region is the one a reader would name
    # -- and, for calls, exactly the one the pre-region rule used to pick.
    return tuple(sorted(regions, key=lambda region: region.start_byte))


def _loop_copy_region(node: Any, source: bytes) -> _CopyRegion | None:
    """The copy a single ``for`` loop performs, or ``None``.

    ``for (i = 0; i < len; ++i) buf[off + i] = data[base + i];`` is a copy just
    as ``memcpy`` is, and it is how most of the real harnesses under a mined
    contract write the payload into the frame.

    The load-bearing discriminator is the subscript index: it must mention the
    loop's own induction variable.  A header field written from ``data`` at a
    constant index (``buf[3] = data[offset + 3];``) is a repair of one byte, not
    a copy of a frame, and it sits inside the very same loop -- so matching on
    "reads from data into buf" alone would accept a harness that never copies
    the payload at all.
    """

    if node.type != "for_statement":
        return None
    condition = node.child_by_field_name("condition")
    if condition is None or condition.type != "binary_expression":
        return None
    operator = condition.child_by_field_name("operator")
    if operator is None or operator.type not in {"<", "<="}:
        return None
    counter = condition.child_by_field_name("left")
    bound = condition.child_by_field_name("right")
    # A compound condition (``step < max_steps && offset < size``) has no single
    # induction variable to bind the index to, so it is not this shape.
    if counter is None or counter.type != "identifier" or bound is None:
        return None
    counter_name = _node_text(source, counter)
    loop_body = node.child_by_field_name("body")
    if loop_body is None:
        return None
    for statement in _walk(loop_body):
        if statement.type != "assignment_expression":
            continue
        target = statement.child_by_field_name("left")
        value = statement.child_by_field_name("right")
        if target is None or value is None or target.type != "subscript_expression":
            continue
        base = target.child_by_field_name("argument")
        index = _subscript_index(target)
        if base is None or base.type != "identifier" or index is None:
            continue
        if counter_name not in _identifier_names(index, source):
            continue
        # The stored byte has to *be* this iteration's byte of ``data``, not a
        # per-iteration digest of it -- see _reads_data_element.
        if any(current.type == "call_expression" for current in _walk(value)):
            continue
        if not _reads_data_element(value, source, counter_name):
            continue
        return _CopyRegion(
            kind="loop",
            destination_identifiers=(_node_text(source, base),),
            destination_text=_node_text(source, target),
            source=_argument(value, source),
            length=_argument(bound, source),
            text=_node_text(source, statement),
            start_byte=statement.start_byte,
        )
    return None


def _subscript_index(node: Any) -> Any | None:
    """The index expression of a ``subscript_expression``, in either grammar.

    The two grammars spell it differently: tree-sitter-c puts it in an
    ``index`` field, and tree-sitter-cpp wraps it in a ``subscript_argument_list``
    reachable through ``indices``.  Asking only for ``index`` does not raise --
    the caller gets ``None`` and stops matching -- which is the dangerous shape:
    a harness that copies its payload byte by byte stops being recognised as a
    copy at all, and the audit blames the connection instead of the grammar.
    """

    index = node.child_by_field_name("index")
    if index is not None:
        return index
    indices = node.child_by_field_name("indices")
    if indices is None:
        return None
    named = [child for child in indices.children if child.is_named]
    return named[0] if named else None


def _reads_data_element(node: Any, source: bytes, counter_name: str) -> bool:
    """Whether ``node`` reads a byte of ``data`` at the counter's own index.

    ``data[i]``, ``data[offset + MP_HEADER_SIZE + i]``: the payload byte for this
    iteration of the loop.  Both halves are load-bearing.  The base being
    ``data`` keeps the frame tied to the fuzzer's bytes rather than to a local
    table, and the index mentioning the induction variable is what stops the
    outer loop of a real harness from being read as a copy: those loops write
    their header fields from ``data`` too, but always at a constant index
    (``frame_buf[3] = data[offset + 3];``), one byte at a time.
    """

    for current in _walk(node):
        if current.type != "subscript_expression":
            continue
        base = current.child_by_field_name("argument")
        index = _subscript_index(current)
        if base is None or index is None:
            continue
        if "data" not in _identifier_names(base, source):
            continue
        if counter_name in _identifier_names(index, source):
            return True
    return False



def _declared_helpers(protocol_helpers: ProtocolHelperSet,
                      all_project_functions: Iterable[str]) -> frozenset[str]:
    """The contract-declared helpers that really exist in this project.

    An FT is built from the structural edges its ISF shares with other
    functions, not from its call closure, so a helper the ISF genuinely calls
    (a checksum, a context constructor) can sit outside it forever.  A helper is
    allowed only when the mined protocol's own provenance names it -- a name
    Stage 4 has never heard of stays forbidden, and prose in the IR's
    requirements or notes (``helpers.weak``) can never authorise anything.

    The declared name must also *exist* in the project.  The IR's evidence
    quotes real source, so a name with no definition behind it is a broken
    claim rather than a licence -- and allowing it would silently disable the
    unknown-API check for that name, which is weaker than the audit this
    relaxation is required to leave otherwise intact.

    The plan validator and the C audit both widen their allowance by exactly
    this set, so the two cannot drift apart.
    """

    return protocol_helpers.allowed & frozenset(all_project_functions)


def declared_contract_helpers(
    artifacts: str | Path,
    all_project_functions: Iterable[str],
) -> frozenset[str]:
    """The helper names ``<artifacts>/protocol_ir.json`` declares, from the file.

    The audit in :func:`_validate_harness` and the pipeline's own re-validation
    of the published harness both widen their allow-set by these names, and they
    have to widen it by exactly the same ones -- a harness one accepts and the
    other refuses is a run that publishes nothing while reporting a failure
    about code it already checked.  This is that one intersection, for callers
    that do not already hold the IR; with no IR it is empty, so the FT-only path
    is unchanged on both sides.

    A ``protocol_ir.json`` that is present but unreadable raises, rather than
    quietly returning nothing: the empty set is the *contract-free* allowance,
    and handing it to a validator is what would let a harness that was built
    from a contract be judged as if it never saw one.
    """

    ir = load_protocol_ir(artifacts)
    if ir is None:
        return frozenset()
    return _declared_helpers(collect_protocol_helpers(ir), all_project_functions)


def _validate_harness(
    analysis: _HarnessAnalysis,
    triplet: FunctionTriplet,
    isf_metadata: Mapping[str, Any],
    all_project_functions: set[str],
    protocol_helpers: ProtocolHelperSet = ProtocolHelperSet(),
    *,
    static_project_functions: frozenset[str] = frozenset(),
    structured_frame: bool = False,
) -> _InputConnection | None:
    """Raise unless the harness is one Stage 4 may publish.

    ``protocol_helpers`` are the helpers the mined protocol's own provenance
    declares.  They widen exactly one rule -- which project calls are inside the
    harness's allowance -- and nothing else in this audit.  The default empty
    set makes every caller that does not supply one behave as it did before the
    protocol IR could reach the audit at all.

    ``static_project_functions`` names the project functions with internal
    linkage.  A contract may still evidence one (``le16`` decodes the frame's
    length), but the harness is linked against the target's objects rather than
    compiled beside them, so a call to it cannot resolve; it widens nothing.

    ``structured_frame`` says a protocol IR is in play, which is what lets
    :func:`_isf_input_connection` recognise the frames that IR asks the harness
    to build.  Without it the repaired-frame rule is the one it always was.

    On success the connection the ISF check accepted is returned, so the record
    persisted next to the attempt is the one the audit actually made.
    """

    definitions = [function.name for function in analysis.functions]
    if definitions.count(FUZZ_ENTRY) != 1:
        raise Stage4Error(f"Stage 4 requires exactly one {FUZZ_ENTRY} definition")
    if "main" in definitions:
        raise Stage4Error("Stage 4 harness must not contain a demo main")
    # See _declared_helpers: only a name the IR's own provenance declares *and*
    # the project actually defines may widen this audit.  The split is computed
    # here, before any check that mentions a helper, so the order in which this
    # audit refuses things is unchanged.
    declared_helpers = _declared_helpers(protocol_helpers, all_project_functions)
    evidence_only = declared_helpers & static_project_functions
    callable_helpers = declared_helpers - evidence_only
    redefined = sorted((set(definitions) - {FUZZ_ENTRY}) & all_project_functions)
    if redefined:
        message = "Stage 4 redefines project APIs: " + ", ".join(redefined)
        alternatives = sorted(set(redefined) & callable_helpers)
        if alternatives:
            # A same-named local helper does not replace the project's own: the
            # two are separate symbols, so whatever the harness computes with it
            # is not what the target computes with its own.  The retry loop
            # feeds this back to the model, which has no other way to learn that
            # the name it just reimplemented was callable all along.
            message += (" (callable from the harness: " + ", ".join(alternatives)
                        + "; call it instead of redefining it)")
        raise Stage4Error(message)

    entry = next(function for function in analysis.functions if function.name == FUZZ_ENTRY)
    _validate_entry_signature(entry)
    if not {"data", "size"} <= set(entry.identifiers):
        raise Stage4Error("Stage 4 harness must use both external data and size")

    calls = {call.name for call in analysis.calls}
    forbidden_logging = sorted(calls & FORBIDDEN_LOGGING_FUNCTIONS)
    if forbidden_logging:
        raise Stage4Error("Stage 4 harness contains logging calls: " +
                          ", ".join(forbidden_logging))
    forbidden_file_io = sorted(calls & FORBIDDEN_IO_FUNCTIONS)
    if forbidden_file_io:
        raise Stage4Error("Stage 4 harness contains unnecessary file I/O: " +
                          ", ".join(forbidden_file_io))

    local_functions = set(definitions)
    expected = {function.function for function in triplet.functions}
    allowed_project_calls = expected | declared_helpers
    outside_ft = sorted(calls & (all_project_functions - allowed_project_calls))
    if outside_ft:
        raise Stage4Error("Stage 4 harness calls project APIs outside the FT: " +
                          ", ".join(outside_ft))
    unlinkable = sorted(calls & evidence_only)
    if unlinkable:
        # The contract evidences these for what they compute, and the harness is
        # free to compute the same thing -- but under its own name.  Calling the
        # project's own static definition does not link, and declaring it here
        # would not change that, because the definition stays internal to the
        # target's translation unit.
        raise Stage4Error(
            "Stage 4 harness calls static project helpers it cannot link: "
            + ", ".join(unlinkable)
            + " (the contract evidences them for their algorithm: reimplement it "
              "under a local name that is not a project API)"
        )
    allowed = expected | local_functions | DEFAULT_ALLOWED_FUNCTIONS | declared_helpers
    unknown = sorted(calls - allowed)
    if unknown:
        raise Stage4Error("Stage 4 harness calls unknown APIs: " + ", ".join(unknown))

    entry_calls = tuple(entry.calls)
    invoked_in_entry = {call.name for call in entry_calls}
    missing = sorted(expected - invoked_in_entry)
    if missing:
        raise Stage4Error("Stage 4 harness omits FT functions: " + ", ".join(missing))

    isf_calls = [call for call in entry_calls if call.name == triplet.isf.function]
    if not isf_calls:
        raise Stage4Error("Stage 4 harness does not invoke the unique ISF")
    input_connection = None
    for call in isf_calls:
        input_connection = _isf_input_connection(
            call, entry, isf_metadata, structured_frame=structured_frame
        )
        if input_connection is not None:
            break
    if input_connection is None:
        raise Stage4Error("Stage 4 ISF call is not connected to external data/size")

    first_isf = min(call.start_byte for call in isf_calls)
    prf_names = {function.function for function in triplet.prfs}
    cleanup_names = {
        function.function
        for function in triplet.hpfs
        if function.function_id != triplet.isf.function_id
        and function.function not in prf_names
        and any(
            edge.function_id == function.function_id and is_null_node(edge.dst)
            for edge in triplet.edges
        )
    }
    cleanup_before_entry = sorted({
        call.name for call in entry_calls
        if call.name in cleanup_names and call.start_byte < first_isf
    })
    if cleanup_before_entry:
        raise Stage4Error("Stage 4 cleanup occurs before ISF initialization: " +
                          ", ".join(cleanup_before_entry))
    _validate_cleanup_order(entry_calls, cleanup_names, triplet)
    return input_connection


def _validate_cleanup_order(calls: tuple[_Call, ...], cleanup_names: set[str],
                            triplet: FunctionTriplet) -> None:
    positions: dict[str, list[int]] = {}
    for call in calls:
        positions.setdefault(call.name, []).append(call.start_byte)
    outgoing: dict[str, set[str]] = {}
    for edge in triplet.edges:
        if not is_null_node(edge.src) and not is_null_node(edge.dst):
            outgoing.setdefault(edge.src, set()).add(edge.dst)

    for cleanup in sorted(cleanup_names):
        cleanup_positions = positions.get(cleanup, [])
        if not cleanup_positions:
            continue
        sources = {
            edge.src for edge in triplet.edges
            if edge.function == cleanup and is_null_node(edge.dst)
        }
        relevant_structures = set(sources)
        pending = list(sources)
        while pending:
            current = pending.pop()
            for target in outgoing.get(current, ()):
                if target not in relevant_structures:
                    relevant_structures.add(target)
                    pending.append(target)
        processing = {
            edge.function for edge in triplet.edges
            if edge.function not in cleanup_names and edge.src in relevant_structures
        }
        downstream_cleanup = {
            edge.function for edge in triplet.edges
            if edge.function in cleanup_names
            and edge.function != cleanup
            and edge.src in (relevant_structures - sources)
        }
        required_before = processing | downstream_cleanup
        late = sorted(
            function for function in required_before
            if positions.get(function)
            and max(positions[function]) > min(cleanup_positions)
        )
        if late:
            raise Stage4Error(
                f"Stage 4 cleanup {cleanup} occurs before downstream processing: "
                + ", ".join(late)
            )


def _validate_entry_signature(entry: _FunctionDefinition) -> None:
    if entry.return_type != "int" or len(entry.parameters) != 2:
        raise Stage4Error("invalid LLVMFuzzerTestOneInput signature")
    data, size = entry.parameters
    if (data.name != "data" or data.base_type != "uint8_t"
            or data.pointer_depth != 1 or "const" not in data.qualifiers):
        raise Stage4Error("first fuzzer parameter must be const uint8_t *data")
    if size.name != "size" or size.base_type != "size_t" or size.pointer_depth != 0:
        raise Stage4Error("second fuzzer parameter must be size_t size")


def _isf_input_connection(
    call: _Call,
    entry: _FunctionDefinition,
    metadata: Mapping[str, Any],
    *,
    structured_frame: bool = False,
) -> _InputConnection | None:
    """How ``call`` is fed the fuzzer's bytes, or ``None`` if it is not.

    Two kinds are accepted:

    ``direct``
        The original rule, unchanged: an argument sitting on a stream parameter
        carries ``data`` in its expression, and -- when the ISF has any length
        parameter -- a length argument carries ``size``.  This is what
        ``mp_parse(&ctx, data, size)`` satisfies.

    ``repaired_frame``
        The ISF is handed a local buffer instead of the fuzzer's own bytes,
        because the frame envelope has to be assembled and ``data`` is const.
        The buffer must be a *bare local identifier* that an earlier statement in
        the same function filled from ``data``, and the ISF's length argument
        must be tied to that copy's length.

    Two things widen the repaired-frame rule, and both need ``structured_frame``
    -- that is, a protocol IR, whose whole point is to ask for a frame to be
    built.  The copy may be a byte-at-a-time ``for`` loop rather than a
    ``memcpy`` call, and the length may be tied through a single-assignment local
    alias (``size_t frame_len = MP_HEADER_SIZE + payload_len;``).  Without an IR
    neither applies and this is exactly the rule it was before.

    Even so, this is a syntactic approximation, not taint analysis.  It
    recognises a copy only when it is written as a ``memcpy``/``memmove`` call, a
    byte-at-a-time store loop, directly in the entry function, before the ISF
    call.  A copy inside a helper function (however it is named), ``read(...)``,
    a pointer that reaches ``data`` through an intermediate variable, a store
    loop whose index is constant, and a copy that reaches ``data`` through a
    call or a table lookup are all missed, and the ISF is then reported as
    unconnected.  It is an under-approximation in that direction -- it never
    claims a connection that is not really written down -- but it is not sound:
    it does not track the copied bytes afterwards, so a frame copied from
    ``data`` and then entirely overwritten from a constant still passes, and a
    buffer is matched to a copy by name, so a same-named inner block could stand
    in for a frame that was never filled.
    """

    parameters = metadata.get("parameters", [])
    if len(call.arguments) != len(parameters):
        return None
    stream_indexes = [
        index for index, parameter in enumerate(parameters)
        if parameter.get("is_pointer") is True
        and parameter.get("is_struct_like") is not True
        and parameter.get("base_type") in {
            "void", "char", "unsigned char", "int8_t", "uint8_t"
        }
    ]
    length_indexes = [
        index for index, parameter in enumerate(parameters)
        if parameter.get("is_pointer") is not True
        and str(parameter.get("name", "")).lower() in _LENGTH_PARAMETER_NAMES
    ]
    if not stream_indexes:
        return None

    direct = _direct_connection(call, stream_indexes, length_indexes)
    if direct is not None:
        return direct
    return _repaired_frame_connection(
        call, entry, stream_indexes, length_indexes,
        structured_frame=structured_frame,
    )


def _direct_connection(
    call: _Call,
    stream_indexes: list[int],
    length_indexes: list[int],
) -> _InputConnection | None:
    """The fuzzer's own buffer, passed straight to the ISF."""

    streams = [
        index for index in stream_indexes
        if "data" in call.arguments[index].identifiers
        and not call.arguments[index].has_string_literal
    ]
    if not streams:
        return None
    sizes = [
        index for index in length_indexes
        if "size" in call.arguments[index].identifiers
    ]
    if length_indexes and not sizes:
        return None
    buffer_index = streams[0]
    evidence = (call.arguments[buffer_index].text,)
    if sizes:
        evidence += (call.arguments[sizes[0]].text,)
    return _InputConnection(
        kind="direct",
        isf=call.name,
        buffer_argument=call.arguments[buffer_index].text,
        size_argument=call.arguments[sizes[0]].text if sizes else "",
        evidence=evidence,
    )


def _repaired_frame_connection(
    call: _Call,
    entry: _FunctionDefinition,
    stream_indexes: list[int],
    length_indexes: list[int],
    *,
    structured_frame: bool = False,
) -> _InputConnection | None:
    """A local frame an earlier copy in the same function filled from ``data``.

    The copies come from :func:`_copy_regions`; only the ``memcpy``/``memmove``
    spelling is considered unless ``structured_frame`` says a protocol IR asked
    for the frame, in which case store loops count too.  The length tie is the
    other half: the ISF's length argument has to mention the same name the copy's
    length does, and under an IR a name whose only write is its own initialiser
    is expanded to what that initialiser mentions -- see
    :func:`_unique_local_aliases`.
    """

    buffers = [
        index for index in stream_indexes
        if _BARE_IDENTIFIER.match(call.arguments[index].text)
    ]
    if not buffers:
        return None
    aliases = dict(entry.local_aliases) if structured_frame else {}
    regions = [
        region for region in entry.copy_regions
        if region.start_byte < call.start_byte
        and (structured_frame or region.kind == "call")
    ]
    for index in buffers:
        buffer = call.arguments[index].text
        for region in regions:
            if buffer not in region.destination_identifiers:
                continue
            if "data" not in region.source.identifiers:
                continue
            if region.source.has_string_literal:
                continue
            tied = []
            for position in length_indexes:
                names = _resolved_identifiers(
                    call.arguments[position].identifiers, aliases
                )
                if "size" in names or names & set(region.length.identifiers):
                    tied.append(position)
            # No length parameter at all: there is no frame length to tie, so
            # the copy alone has to carry the claim.
            if length_indexes and not tied:
                continue
            evidence = [region.text]
            if region.destination_text != buffer:
                # The copy fills a *region* of the buffer (``frame +
                # MP_HEADER_SIZE``, or a store loop's subscript), so the bytes
                # before it are written by the harness itself rather than copied
                # through.  That is the observable repair: the envelope is
                # assembled, not aliased.
                evidence.append(f"frame length/checksum repaired before {call.name}")
            return _InputConnection(
                kind="repaired_frame",
                isf=call.name,
                buffer_argument=buffer,
                size_argument=call.arguments[tied[0]].text if tied else "",
                evidence=tuple(evidence),
            )
    return None


def _call_text(call: _Call) -> str:
    return f"{call.name}({', '.join(argument.text for argument in call.arguments)})"


def _parameters(function_declarator: Any, source: bytes) -> Iterable[_Parameter]:
    parameters = function_declarator.child_by_field_name("parameters")
    if parameters is None:
        return
    for node in parameters.named_children:
        if node.type != "parameter_declaration":
            continue
        type_node = node.child_by_field_name("type")
        declarator = node.child_by_field_name("declarator")
        yield _Parameter(
            name=_declarator_identifier(declarator, source),
            base_type=_node_text(source, type_node),
            qualifiers=tuple(
                _node_text(source, child)
                for child in node.named_children
                if child.type == "type_qualifier"
            ),
            pointer_depth=sum(
                current.type == "pointer_declarator"
                for current in _walk(declarator)
            ) if declarator is not None else 0,
        )


def _calls(body: Any, source: bytes) -> Iterable[_Call]:
    if body is None:
        return
    for node in _walk(body):
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "identifier":
            continue
        arguments_node = node.child_by_field_name("arguments")
        arguments = []
        if arguments_node is not None:
            for argument in arguments_node.named_children:
                arguments.append(_argument(argument, source))
        yield _Call(
            name=_node_text(source, callee),
            arguments=tuple(arguments),
            start_byte=node.start_byte,
        )


def _argument(node: Any, source: bytes) -> _Argument:
    return _Argument(
        text=_node_text(source, node),
        identifiers=tuple(sorted({
            _node_text(source, current)
            for current in _walk(node)
            if current.type == "identifier"
        })),
        has_string_literal=any(
            current.type in {"string_literal", "concatenated_string"}
            for current in _walk(node)
        ),
    )


def _find_function_declarator(node: Any) -> Any:
    if node is None:
        return None
    if node.type == "function_declarator":
        return node
    child = node.child_by_field_name("declarator")
    if child is not None:
        found = _find_function_declarator(child)
        if found is not None:
            return found
    return next(
        (current for current in _walk(node)
         if current.type == "function_declarator"),
        None,
    )


def _declarator_identifier(node: Any, source: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return _node_text(source, node)
    child = node.child_by_field_name("declarator")
    if child is not None:
        name = _declarator_identifier(child, source)
        if name is not None:
            return name
    return next(
        (_node_text(source, current) for current in _walk(node)
         if current.type == "identifier"),
        None,
    )


def _walk(node: Any) -> Iterable[Any]:
    if node is None:
        return
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.children))


def _node_text(source: bytes, node: Any) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""


def _required_string(value: Mapping[str, Any], field: str, owner: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        raise Stage4Error(f"{field} must be non-empty text for {owner}")
    return item


def _generation_metadata(generation: LLMGeneration) -> dict[str, Any]:
    metadata = {
        "model": generation.model,
        "provider": generation.provider,
        "prompt_version": generation.prompt_version,
        "usage": dict(generation.usage),
    }
    if generation.response_id is not None:
        metadata["response_id"] = generation.response_id
    if generation.finish_reason is not None:
        metadata["finish_reason"] = generation.finish_reason
    return metadata


def _attempt_metadata(
    ft_id: str,
    attempt: int,
    generation: LLMGeneration | None,
    rollback_source: str | None,
    retry_reason: str | None,
    retry_context: Mapping[str, Any] | None,
    *,
    client: LLMClient | None = None,
    prompt_version: str | None = None,
    plan_prompt_version: str | None = None,
    plan_generation: LLMGeneration | None = None,
) -> dict[str, Any]:
    metadata = {} if generation is None else dict(generation.metadata)
    context = dict(retry_context or {})
    plan_metadata = {} if plan_generation is None else _generation_metadata(plan_generation)
    return {
        "schema_version": 1,
        "stage": "stage4",
        "attempt": attempt,
        "ft_id": ft_id,
        "prompt_version": (
            prompt_version if generation is None else generation.prompt_version
        ),
        "plan_prompt_version": plan_prompt_version,
        "plan_generation_metadata": plan_metadata,
        "model": (
            getattr(client, "model", None) if generation is None else generation.model
        ),
        "provider": (
            getattr(client, "provider", None)
            if generation is None else generation.provider
        ),
        "temperature": metadata.get("temperature"),
        "max_tokens": metadata.get("max_tokens"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rollback_source": rollback_source,
        "retry_reason": retry_reason,
        "failed_stage": context.get("failed_stage"),
        "validator": context.get("validator"),
        "failure_type": context.get("failure_type"),
        "rollback_target": context.get("rollback_target"),
        "rollback_attempt": context.get("attempt"),
    }


def _stage4_validation_feedback(
    retry_context: Mapping[str, Any] | None,
    *,
    triplet_id: str,
    unique_isf_function_id: str,
) -> dict[str, Any]:
    """Add Stage4-specific repair instructions to bounded retry feedback."""

    feedback = bounded_validation_feedback(retry_context)
    if not feedback:
        return {}
    correction = {
        "required_triplet_id": triplet_id,
        "instruction": (
            "For HarnessPlan JSON, set triplet_id exactly to "
            f"{triplet_id!r}. Do not use a function id, source path, line "
            "number, or unique_isf.id as triplet_id."
        ),
    }
    if unique_isf_function_id:
        correction["do_not_use_as_triplet_id"] = unique_isf_function_id
    feedback["stage4_triplet_id_correction"] = correction
    return feedback
