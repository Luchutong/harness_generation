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
from .prompts import stage4_harness_plan, stage4_harness_transform
from .protocol_ir import ProtocolIR, ProtocolIRError
from .protocol_ir_helpers import ProtocolHelperSet, collect_protocol_helpers
from .protocol_plan_validation import (
    protocol_contract_projection,
    validate_plan_contract,
)
from .sfg_adapter import is_null_node
from .source_paths import SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS
from .triplet import FunctionTriplet


FUZZ_ENTRY = "LLVMFuzzerTestOneInput"
_LOGGING_CALLS = {"printf", "fprintf"}
_FILE_IO_CALLS = {
    "fopen", "freopen", "fdopen", "fclose", "fread", "fwrite",
    "fseek", "ftell", "fgetpos", "fsetpos", "rewind", "tmpfile",
}
_STANDARD_C_CALLS = {
    "abort", "assert", "calloc", "free", "malloc", "memcmp", "memcpy",
    "memmove", "memset", "realloc", "strchr", "strcmp", "strlen",
    "strncmp", "strnlen", "strrchr",
}
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
class _FunctionDefinition:
    name: str
    return_type: str
    parameters: tuple[_Parameter, ...]
    calls: tuple[_Call, ...]
    identifiers: tuple[str, ...]


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
        function_metadata, all_project_functions, project_context = _load_function_metadata(
            Path(functions_json), triplet
        )
        isf_metadata = function_metadata[triplet.isf.function_id]
        validation_feedback = _stage4_validation_feedback(
            retry_context,
            triplet_id=triplet.id,
            unique_isf_function_id=str(isf_metadata.get("id", "")),
        )
        protocol_ir = _load_protocol(artifacts)
        # The helpers the audit may accept are read out of the IR's own
        # provenance.  With no IR this is the empty set, so the audit is byte
        # for byte the FT-only one it was before any of this existed.
        protocol_helpers = collect_protocol_helpers(protocol_ir)
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
            layout.write_json(attempt_directory / "parsed.json", {
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
            layout.write_json(attempt_directory / "parsed.json", {
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
            )
        except Exception as error:
            layout.write_json(attempt_directory / "parsed.json", {
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
        layout.write_json(attempt_directory / "parsed.json", passed_record)
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

    return _protocol_contract(artifacts, _load_protocol(artifacts))


def _load_protocol(artifacts: str | Path) -> ProtocolIR | None:
    """The mined IR itself, or ``None`` when no ``protocol_ir.json`` is there.

    ``run()`` needs the IR and not only its contract projection, because the
    audit reads the helper names out of the IR's own provenance.  The public
    :func:`load_protocol_contract` is a view over this: it discards the IR and
    returns exactly the pair, with exactly the error messages, it always did.
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
) -> HarnessPlan:
    """Parse and validate the strict JSON HarnessPlan returned by the LLM."""

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
    planned_calls = [_plan_function(item, "call_sequence") for item in call_sequence]
    planned_cleanup = [
        _plan_function(item, "cleanup_sequence") for item in cleanup_sequence
    ]
    all_planned = planned_calls + planned_cleanup
    unknown = sorted(set(all_planned) - expected)
    if unknown:
        raise Stage4Error(
            "HarnessPlan references functions outside the FT: " + ", ".join(unknown)
        )
    missing = sorted(expected - set(all_planned))
    if missing:
        raise Stage4Error("HarnessPlan omits FT functions: " + ", ".join(missing))
    duplicated = sorted(
        name for name in set(all_planned) if all_planned.count(name) > 1
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
        and str(parameter.get("name", "")).lower() in {
            "size", "len", "length", "n", "data_size", "buffer_size"
        }
        for parameter in parameters
    )
    return has_stream and has_length


def _load_function_metadata(
    path: Path,
    triplet: FunctionTriplet,
) -> tuple[dict[str, dict[str, Any]], set[str], dict[str, Any]]:
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
    for record in records:
        function_id = _required_string(record, "id", "functions.json")
        name = _required_string(record, "name", function_id)
        if function_id in by_id:
            raise Stage4Error(f"duplicate functions.json function id: {function_id}")
        by_id[function_id] = record
        all_names.add(name)

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
    return selected, all_names, project_type_context(document)


def _analyze_c(source: str) -> _HarnessAnalysis:
    if not source:
        raise Stage4Error("LLM returned an empty Stage 4 harness")
    if "```" in source:
        raise Stage4Error("Stage 4 harness must not contain Markdown fences")
    try:
        import tree_sitter
        import tree_sitter_c
    except ImportError as error:
        raise Stage4Error("tree-sitter C dependencies are required for Stage 4") from error

    language_value = tree_sitter_c.language()
    language = (language_value if isinstance(language_value, tree_sitter.Language)
                else tree_sitter.Language(language_value))
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
        raise Stage4Error("LLM returned invalid C syntax")

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
        ))
    return _HarnessAnalysis(tuple(functions), tuple(all_calls))


def _validate_harness(
    analysis: _HarnessAnalysis,
    triplet: FunctionTriplet,
    isf_metadata: Mapping[str, Any],
    all_project_functions: set[str],
    protocol_helpers: ProtocolHelperSet = ProtocolHelperSet(),
) -> _InputConnection | None:
    """Raise unless the harness is one Stage 4 may publish.

    ``protocol_helpers`` are the helpers the mined protocol's own provenance
    declares.  They widen exactly one rule -- which project calls are inside the
    harness's allowance -- and nothing else in this audit.  The default empty
    set makes every caller that does not supply one behave as it did before the
    protocol IR could reach the audit at all.

    On success the connection the ISF check accepted is returned, so the record
    persisted next to the attempt is the one the audit actually made.
    """

    definitions = [function.name for function in analysis.functions]
    if definitions.count(FUZZ_ENTRY) != 1:
        raise Stage4Error(f"Stage 4 requires exactly one {FUZZ_ENTRY} definition")
    if "main" in definitions:
        raise Stage4Error("Stage 4 harness must not contain a demo main")
    redefined = sorted((set(definitions) - {FUZZ_ENTRY}) & all_project_functions)
    if redefined:
        raise Stage4Error("Stage 4 redefines project APIs: " + ", ".join(redefined))

    entry = next(function for function in analysis.functions if function.name == FUZZ_ENTRY)
    _validate_entry_signature(entry)
    if not {"data", "size"} <= set(entry.identifiers):
        raise Stage4Error("Stage 4 harness must use both external data and size")

    calls = {call.name for call in analysis.calls}
    forbidden_logging = sorted(calls & _LOGGING_CALLS)
    if forbidden_logging:
        raise Stage4Error("Stage 4 harness contains logging calls: " +
                          ", ".join(forbidden_logging))
    forbidden_file_io = sorted(calls & _FILE_IO_CALLS)
    if forbidden_file_io:
        raise Stage4Error("Stage 4 harness contains unnecessary file I/O: " +
                          ", ".join(forbidden_file_io))

    local_functions = set(definitions)
    expected = {function.function for function in triplet.functions}
    # An FT is built from the structural edges its ISF shares with other
    # functions, not from its call closure, so a helper the ISF genuinely calls
    # (a checksum, a context constructor) can sit outside it forever.  A helper
    # is allowed here only when the mined protocol's own provenance names it --
    # a name Stage 4 has never heard of stays forbidden, and prose in the IR's
    # requirements or notes (`helpers.weak`) can never authorise anything.
    #
    # The declared name must also *exist* in the project.  The IR's evidence
    # quotes real source, so a name with no definition behind it is a broken
    # claim rather than a licence -- and allowing it would silently disable the
    # unknown-API check below for that name, which is weaker than the audit
    # this relaxation is required to leave otherwise intact.
    declared_helpers = protocol_helpers.allowed & all_project_functions
    allowed_project_calls = expected | declared_helpers
    outside_ft = sorted(calls & (all_project_functions - allowed_project_calls))
    if outside_ft:
        raise Stage4Error("Stage 4 harness calls project APIs outside the FT: " +
                          ", ".join(outside_ft))
    allowed = expected | local_functions | _STANDARD_C_CALLS | declared_helpers
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
        input_connection = _isf_input_connection(call, entry, isf_metadata)
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
        The buffer must be a *bare local identifier* that a ``memcpy`` or
        ``memmove`` **earlier in the same function** filled from ``data``, and
        the ISF's length argument must be tied to that copy's length.

    The repaired-frame rule is a syntactic approximation, not taint analysis.
    It recognises a copy only when it is written as a call named ``memcpy`` or
    ``memmove``, directly in the entry function, before the ISF call.  A
    byte-at-a-time copy loop, a helper function that fills the frame (however it
    is named), ``read(...)``, or a pointer that reaches ``data`` through an
    intermediate variable are all missed, and the ISF is then reported as
    unconnected.  It is an under-approximation in that direction -- it never
    claims a connection that is not really written down -- but it is not sound:
    it does not track the copied bytes afterwards, so a frame copied from
    ``data`` and then entirely overwritten from a constant still passes.
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
    return _repaired_frame_connection(call, entry, stream_indexes, length_indexes)


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
) -> _InputConnection | None:
    """A local frame a preceding ``memcpy``/``memmove`` filled from ``data``."""

    buffers = [
        index for index in stream_indexes
        if _BARE_IDENTIFIER.match(call.arguments[index].text)
    ]
    if not buffers:
        return None
    copies = [
        copy for copy in entry.calls
        if copy.name in _COPY_CALLS
        and copy.start_byte < call.start_byte
        and len(copy.arguments) >= 3
    ]
    for index in buffers:
        buffer = call.arguments[index].text
        for copy in copies:
            destination, source, length = copy.arguments[:3]
            if buffer not in destination.identifiers:
                continue
            if "data" not in source.identifiers or source.has_string_literal:
                continue
            tied = [
                position for position in length_indexes
                if "size" in call.arguments[position].identifiers
                or set(call.arguments[position].identifiers) & set(length.identifiers)
            ]
            # No length parameter at all: there is no frame length to tie, so
            # the copy alone has to carry the claim.
            if length_indexes and not tied:
                continue
            evidence = [_call_text(copy)]
            if destination.text != buffer:
                # The copy fills a *region* of the buffer (``frame +
                # MP_HEADER_SIZE``), so the bytes before it are written by the
                # harness itself rather than copied through.  That is the
                # observable repair: the envelope is assembled, not aliased.
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
                arguments.append(_Argument(
                    text=_node_text(source, argument),
                    identifiers=tuple(sorted({
                        _node_text(source, current)
                        for current in _walk(argument)
                        if current.type == "identifier"
                    })),
                    has_string_literal=any(
                        current.type in {"string_literal", "concatenated_string"}
                        for current in _walk(argument)
                    ),
                ))
        yield _Call(
            name=_node_text(source, callee),
            arguments=tuple(arguments),
            start_byte=node.start_byte,
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
