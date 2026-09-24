"""Versioned prompt templates for the harness generation stages.

This module only owns prompt construction.  It deliberately does not execute a
stage or call an LLM provider.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from string import Formatter
from typing import Any, Mapping

from .records import write_json


@dataclass(frozen=True)
class RenderedPrompt:
    """A concrete, auditable prompt produced from a versioned template."""

    name: str
    prompt_version: str
    content: str
    parameters: Mapping[str, Any]

    def __str__(self) -> str:
        return self.content

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "prompt_version": self.prompt_version,
            "content": self.content,
            "parameters": dict(self.parameters),
        }

    def save(self, path: str | Path) -> None:
        """Save the rendered prompt and its version as stable JSON."""

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_json(destination, self.to_dict(), sort_keys=True, allow_nan=False)


@dataclass(frozen=True)
class PromptTemplate:
    """A named prompt template with an immutable experiment version."""

    name: str
    version: str
    template: str

    @property
    def parameter_names(self) -> tuple[str, ...]:
        names = {
            field_name
            for _, field_name, _, _ in Formatter().parse(self.template)
            if field_name
        }
        return tuple(sorted(names))

    def render(self, **parameters: Any) -> RenderedPrompt:
        required = set(self.parameter_names)
        supplied = set(parameters)
        missing = sorted(required - supplied)
        unexpected = sorted(supplied - required)
        if missing:
            raise ValueError(f"missing prompt parameters: {', '.join(missing)}")
        if unexpected:
            raise ValueError(f"unexpected prompt parameters: {', '.join(unexpected)}")

        printable = {key: _printable(value) for key, value in parameters.items()}
        return RenderedPrompt(
            name=self.name,
            prompt_version=self.version,
            content=self.template.format_map(printable),
            parameters=dict(parameters),
        )


STAGE1_FUNCTION_DOC = PromptTemplate(
    name="stage1_function_doc",
    version="stage1-function-doc-v3",
    template="""You are documenting a C function for a later harness-generation pass.
Use only the supplied source and context. Do not redefine the function or invent
functions, types, APIs, or semantics that cannot be supported by the source.
Inspect referenced struct definitions. If a parameter struct contains callback
fields, explain which callbacks the API requires and initialize them in the
example with concrete safe functions. A comment saying callbacks should be set
is not a runnable example. Keep documented optional callbacks null when useful.
The later validation build can expose file-local FT functions, so do not avoid a
direct call merely because the supplied source marks the function static.
example_code must include a direct call expression to the documented function
name, such as target_function(...), using the exact function name being
documented.

Function signature:
{function_signature}

Function source:
{function_source}

Usage context:
{usage_context}

Analyze the function's functionality and provide an example call according to
its usage scenario. Return only one JSON object with exactly this schema:
{{"function":"...","signature":"...","functionality":"...",
"application_scenario":"...","example_code":"...",
"parameter_notes":["..."],"return_semantics":null,
"resource_lifecycle_notes":["..."],"notes":["..."]}}
Use null or an empty list for facts that cannot be reliably inferred.""",
)

STAGE2_STRUCTURE_SNIPPET = PromptTemplate(
    name="stage2_structure_snippet",
    version="stage2-structure-snippet-v3",
    template="""Produce a focused C snippet for one structural-flow step.
Call the supplied function that carries out this step. When several functions are
supplied they are alternative implementations of the same step, so call exactly
one of them; do not call the others, and release each acquired resource exactly
once. Preserve dependencies and use only the provided functions. Do not
reimplement target functions, invent APIs, or add a final LLVMFuzzerTestOneInput
wrapper. Output C only, never C++. Dependency identifiers describe ordering only;
never call them as functions.

Input structure:
{input_structure}

Output structure:
{output_structure}

Functions:
{functions}

Dependencies:
{dependencies}

Ownership relations relevant to these functions are descriptive lifecycle
constraints only; they do not authorize unrelated APIs. A cleanup relation must
remain bound to the declared producer return, out parameter, or existing
reference argument and execute after every declared consumer.

Function documentation:
{documentation}""",
)

STAGE3_ROUGH_ASSEMBLY = PromptTemplate(
    name="stage3_rough_assembly",
    version="stage3-rough-assembly-v3",
    template="""Assemble the supplied C snippets into one coherent rough C program.
Order operations by structural dependencies, reconcile shared variables and
cleanup, pass output structures into their downstream inputs, and preserve all
necessary function calls. Do not merely concatenate, redefine project APIs, or
invent APIs. Return only C source without Markdown fences. This is a rough code
sequence, not a standalone demo program: do not emit main,
LLVMFuzzerTestOneInput, or any other driver entry point.
Use the listed project header instead of redeclaring project functions or types.
Typedef aliases must retain their exact spelling; never turn an anonymous typedef
such as T into struct T.

Snippets:
{snippets}

Structural dependencies:
{structural_dependencies}

Function metadata:
{function_metadata}

Project headers and exact type declarations:
{project_context}

Previous validation feedback (empty on the first attempt):
{validation_feedback}""",
)

STAGE4_HARNESS_TRANSFORM = PromptTemplate(
    name="stage4_harness_transform",
    version="stage4-harness-transform-v10",
    template="""Implement the supplied HarnessPlan as a C++ libFuzzer harness.
The final harness is a C++ translation unit, but it fuzzes the C target through
C-compatible declarations. It must include <stddef.h> and <stdint.h> explicitly
so size_t and uint8_t are available in the global namespace. The entry point
must be exactly:
 #include <stddef.h>
 #include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)

The unique ISF is
the external-input entry. Connect data and size, remove fixed inputs, demo main,
irrelevant logging, and unnecessary file I/O. Preserve required initialization,
downstream behavior, bounds checks, and cleanup. Do not redefine project
functions or invent APIs.
Include the listed project header for complete type/API declarations. Because
the target project is C, include project headers inside an extern "C" block when
the header declares target functions. Do not redeclare project functions or
project types. Preserve typedef aliases exactly; never replace an anonymous
typedef T with a nonexistent struct T tag.
If project_context lists cplusplus_unsafe_headers, those headers are evidence
only and must not be included by the final C++ harness. Use the supplied
portable_abi_declarations for FT functions whose public project headers are
missing or unsafe in C++. When a portable ABI declaration maps a callback typedef
to void*, define a local helper with the real typedef signature and pass it
through the required ABI cast; do not replace FT callback parameters with
nullptr just because the portable declaration says void*. When enum constants
are available only from unsafe headers, use their
documented integer value instead of including the unsafe header.
When the ISF takes a callback table, read project_context.callback_tables and
assign every field marked "required" a static function whose parameters and
return type match that field's declaration exactly. A zero-initialized table left
that way is a null dereference inside the target, not a safe default. Fields not
marked "required" may stay null. When the ISF takes a parameter listed in
project_context.callback_typedefs or in a declarations callback_parameters, pass
either nullptr or a function matching that typedef exactly; a helper of a
different arity is undefined behavior when the target calls through the typedef.
For FT functions themselves, prefer a real matching callback over nullptr.
This is mandatory for write/close/escape style callback parameters such as
iowrite, ioclose, and escaping: define local helpers, store observable state in
ioctx when applicable, and let fuzzer bytes choose helper behavior such as
partial writes, close status, escaping output length, and conversion status.
Do not model FT callback variation by selecting nullptr in a ternary or fallback;
the callback argument itself must stay non-null, and fuzzer-controlled variation
belongs inside the helper or its context.
When an FT function accepts an encoder/encoding-handler pointer and the type is
declared, build a non-null local encoder object instead of passing nullptr.
Initialize its output conversion member with a matching helper when available,
and derive at least one encoder behavior choice from the fuzzer input.

Use only the supplied project functions plus necessary standard C/C++ library
utilities. Emit only C++ source without Markdown fences. Do not use using
namespace std. You may use straightforward C++ helpers such as std::array,
std::vector, std::min/std::max, lambdas, and scoped local helpers when they make
the input model clearer, but do not use lambdas or function-object variables for
operations called like functions because the static validator treats those calls
as unknown APIs. Use ordinary local variables, direct expressions, loops, or
named static helper functions instead. Avoid complex classes or unrelated
abstractions.
Do not call project APIs outside the Function Triplet unless they are explicitly
listed as FT-scoped ownership cleanup or protocol helpers. Treat the functions
named by HarnessPlan.call_sequence and cleanup_sequence as the ft_functions
allowlist for project API calls. If a required struct type is publicly declared,
construct a local instance and backing storage directly instead of calling non-FT
allocators/free functions. For example, when an FT needs an xmlBuffer input and
xmlBuffer is declared, initialize a local xmlBuffer plus a bounded xmlChar
backing array; do not call xmlBufferCreate or xmlBufferFree unless those
functions are part of the FT.
Do not open, create, or close real files to satisfy FILE* or fd parameters.
For FT functions whose purpose is to create an output buffer from FILE* or fd,
use a guarded nullptr FILE* or invalid/sentinel fd value when no FT-provided
producer exists; the structural obligation is the FT call itself, not successful
OS file I/O. Do not call std::tmpfile, std::fclose, fopen, fclose, open, close,
or similar helper I/O APIs.
Pass the external data and size into the unique ISF according to its signature,
retain downstream FT calls, initialize writable objects before use, and perform
cleanup after processing. Ownership cleanup is permitted only for an exact
FT-scoped ownership relation in HarnessPlan.cleanup_sequence, bound according
to producer_binding and producer_argument_index, and placed after every declared consumer. Nullable owned
pointers require an explicit null-safe cleanup condition. Do not treat lifecycle
prose, null structural endpoints, or a global allowlist as cleanup authority.
If a protocol contract is supplied, implement its input model directly. For
framed command protocols, build a bounded multi-frame command loop, keep one
stateful context alive for the whole libFuzzer iteration, and populate declared
magic/version/opcode/length/checksum/payload fields exactly.
When a known target contract declares a grammar, construct bounded inputs from
its start symbol and rules. Keep depth and output size bounded as specified by
the HarnessPlan, and preserve fuzzer-controlled choices at grammar branches.
When no protocol or known grammar contract is supplied, use raw byte/text
passthrough plus an aggressive control prefix. Do not invent a length prefix,
magic, checksum, padding, or multi-frame framing. Instead, consume a few leading
bytes as branch selectors, small lengths, callback behavior flags, encoder
choices, compression/status knobs, and API variant choices; use the remaining
bytes as payload. For explicit-length APIs, pass fuzzer-controlled buffers and
lengths directly, using casts only when declared types require them.

HarnessPlan JSON:
{harness_plan}

Rough program:
{rough_code}

Unique ISF:
{unique_isf}

Function metadata:
{function_metadata}

Project headers and exact type declarations:
{project_context}

FT-scoped ownership relations:
{ownership_relations}

Project headers and exact type declarations:
{project_context}

Protocol contract, if supplied:
{protocol_contract}

Typed protocol contract bindings, if supplied:
{protocol_contract_bindings}

Target input and resource contract, if supplied:
{target_contract}

Target contract identity for schema_version 2:
{contract_id}

Contract fact IDs bound by schema_version 2:
{contract_fact_ids}

Previous validation feedback (empty on the first attempt):
{validation_feedback}""",
)

STAGE4_HARNESS_PLAN = PromptTemplate(
    name="stage4_harness_plan",
    version="stage4-harness-plan-v11",
    template="""Create a structured HarnessPlan before any final C harness is
written. Use the rough program, Function Triplet, and exact project declarations
to decide state objects, fuzzer-input decoding, call order, data/size binding,
required constraints, and cleanup. Do not output C source. Do not invent project
APIs or redefine project types.
The plan may use only project functions listed in ft_functions, FT-scoped
ownership cleanup relations, and supplied protocol helpers. If setup needs a
declared project struct, plan local stack/storage initialization rather than
calling project allocators or frees outside ft_functions. For example, when an
xmlBuffer input is needed and xmlBuffer is declared, use a local xmlBuffer and a
bounded xmlChar backing array; do not plan xmlBufferCreate/xmlBufferFree unless
they are listed in ft_functions.
Do not plan real OS file creation or cleanup for FILE* or fd arguments. Use
nullptr FILE* or invalid/sentinel fd values when no FT function produces the
handle, and still call the relevant FT constructor under a guard. Never plan
std::tmpfile, std::fclose, fopen, fclose, open, close, or similar helper I/O APIs.

Exact FunctionTriplet identity:
The HarnessPlan JSON field triplet_id MUST be exactly this string, byte-for-byte:
{triplet_id}
Do not use a function id, source location, path, line number, or unique_isf.id as
triplet_id. In particular, values like "src/file.c:line:function" are function
identifiers, not FunctionTriplet ids.

Return only one strict JSON object with exactly this shape. Use schema_version 1 for
legacy plans. For schema_version 2, retain every field below and additionally include
"contract_id":"{contract_id}",
"contract_fact_ids":[],
"immutable_fields":["triplet_id","entrypoint","contract_fact_ids","state_objects","call_sequence","cleanup_sequence","constraints"],
"tunable_fields":["input_strategy","notes"]. The v2 field classifications are
closed: immutable_fields and tunable_fields must be disjoint and must contain exactly
those names.{{"schema_version":1,"triplet_id":"{triplet_id}","entrypoint":"LLVMFuzzerTestOneInput",
"input_strategy":{{"description":"...","data_identifier":"data",
"size_identifier":"size","bounded_steps":0,"notes":["..."]}},
"state_objects":[{{"name":"...","type":"...","initialization":"..."}}],
"call_sequence":[{{"function":"...","roles":["ISF"],"purpose":"...",
"arguments":["..."],"uses_fuzzer_data":true,"uses_fuzzer_size":true,
"outputs":["..."],"conditions":["..."]}}],
"cleanup_sequence":[{{"function":"...","purpose":"...",
"arguments":["..."],"relation_id":"...","producer_function":"...",
"resource_type":"...","producer_binding":{{"kind":"return_value",
"identifier":"..."}},"after":["..."],"conditions":["..."]}}],
"constraints":["..."],"notes":["..."]}}

cleanup_sequence is only for FT-scoped ownership_relations supplied below.
If ownership_relations is empty, cleanup_sequence must be [] even when an HPF
function semantically closes or releases a value. FT functions that carry HPF
or cleanup-like behavior still belong in call_sequence exactly once to satisfy
their structural step. Never duplicate an FT function in cleanup_sequence with
an empty relation_id.

Every listed structural step must be realized. A step with multiple functions
contains proven alternatives, so call one of them. Satisfying a step means
calling a function it names, once: one call satisfies every step that names
that function, even when those steps have different sources and targets, so
never add a second call to answer a second step. The step count is not a call
count. When an ownership relation supplies observed_sequence, preserve its
order and repeat a function at most as many times as that sequence records;
otherwise use it once.
The unique ISF must appear in call_sequence and must use both fuzzer data and
fuzzer size when the signature has a byte stream and length parameter. If a
function is both PRF and HPF, keep it in call_sequence and mention cleanup
responsibility in purpose or notes. Cleanup must happen after downstream
processing. Ownership cleanup is a scoped exception: use it only when the
supplied FunctionTriplet ownership_relations contains the exact relation, keep
it in cleanup_sequence, bind it using the relation's producer_binding and
producer_argument_index, and include every declared consumer in after. A
cleanup whose relation records "nullable":true, or whose path_kind is
"conditional" or "error", must additionally carry a non-empty conditions list
naming the explicit null-safe guard. A relation whose producer the plan never
calls is not owed a cleanup. Never infer cleanup permission from prose, a null
structural endpoint, or a global API allowlist.
If a protocol contract is supplied, the plan must explicitly preserve its input
model. For framed command protocols, use a bounded multi-frame command loop,
set input_strategy.bounded_steps to a positive cap, keep state_objects alive
across commands, and include exact protocol fields such as magic, version,
opcode, length endianness, checksum, and payload offset in constraints or call
arguments.
When a known target contract declares a grammar, select input_strategy.mode
"grammar", supply positive max_depth and max_output_bytes, and name the
grammar start symbol in the strategy. The grammar may coexist with frame or
sequence facts; preserve all supplied facts.
When no protocol or known grammar contract is supplied, the plan must use raw
byte/text passthrough with an aggressive control prefix:
do not invent a length prefix, magic, checksum, padding, or multi-frame framing.
Instead, reserve a few leading bytes for branch selectors, small lengths,
callback behavior flags, encoder choices, compression/status knobs, and API
variant choices; bind the remaining bytes as content payload. The plan must not
send the whole fuzzer input only as the same string argument to several write
functions when the FT exposes callbacks, encoders, compression/status arguments,
or alternative output-buffer constructors.
For explicit-length APIs, bind fuzzer-controlled buffers and sizes directly.
Read project_context.callback_tables. Every field marked "required" is called by
the target through that table and must be given a concrete function of the
declared signature, which must be listed as a constraint or a call argument.
Fields not marked "required" may stay null. The table itself must never be
passed zero-initialized and untouched.
Read project_context.callback_typedefs and the callback_parameters of the
portable ABI declarations. For FT functions, a parameter typed by one of those
typedefs must use a concrete local function whose parameters and return type
match the typedef exactly; use a cast only when the portable ABI declaration has
erased the callback type to void*. This applies to write/close/escape style
parameters such as iowrite, ioclose, and escaping. Null callbacks are acceptable
only for callback table fields explicitly marked optional or for non-FT helper
APIs whose source proves null disables an unrelated optional path.
Do not use callback ? helper : nullptr patterns for FT callback parameters; use
a non-null helper and let that helper inspect fuzzer-derived state.
When a function has an encoder or encoding-handler pointer parameter and the
type declaration is available, plan a non-null local encoder object. Initialize
its output conversion member with a matching helper when the structure exposes
one, and make at least one encoder behavior decision depend on fuzzer bytes.

Rough program:
{rough_code}

Unique ISF:
{unique_isf}

Function metadata:
{function_metadata}

Project headers and exact type declarations:
{project_context}

FT bypass semantics (non-SFG sidecar evidence; use these for scalar guards,
byte-stream/length binding, constants, return status, and struct access hints):
{bypass_semantics}

FT-scoped ownership relations (the only authority for external cleanup calls):
{ownership_relations}

Evidence-backed structural steps:
{structural_steps}

Coverage obligations, derived from the structural steps above (this is what the
plan validator enforces, item by item):
{coverage_obligations}

Protocol contract, if supplied:
{protocol_contract}

Typed protocol contract bindings, if supplied:
{protocol_contract_bindings}

Target input and resource contract, if supplied:
{target_contract}

Target contract identity for schema_version 2:
{contract_id}

Contract fact IDs bound by schema_version 2:
{contract_fact_ids}

Previous validation feedback (empty on the first attempt):
{validation_feedback}

Parent HarnessPlan for refinement (empty on initial generation):
{parent_plan}

Measured optimization feedback (empty on initial generation):
{optimization_feedback}

When refining, preserve the parent's triplet, call and cleanup sequence,
state objects, constraints, contract identity and contract fact IDs exactly.
Change only input_strategy and notes, and ground each change in the measured
feedback. Do not treat missing measurements as a low score.""",
)

PROTOCOL_CONVENTION_REFINEMENT = PromptTemplate(
    name="protocol_convention_refinement",
    version="protocol-convention-refinement-v1",
    template="""Infer the convention block for a structured fuzzing protocol contract.
Use only the supplied static protocol facts and source context. Do not invent
project APIs, enum names, helpers, context types, or source evidence. The static
facts already cover frame fields and constants; focus only on:
command_loop, context lifetime, stateful opcodes, requirements, and notes.

Return exactly one strict JSON object and no Markdown fences. Every non-empty
claim must be backed by evidence from the supplied context or explicitly marked
as an engineering_choice. Use this schema:
{{"schema_version":1,
"sequence_model":{{"multi_frame":true,"reason":"...",
"evidence":["..."],
"max_steps":{{"value":32,"source":"engineering_choice","evidence":["..."]}}}},
"context":{{"type":"...","init":"...","destroy":"...",
"lifetime":"one per fuzz iteration","evidence":["..."]}},
"stateful_operations":[{{"opcode":"...","reason":"...","evidence":["..."]}}],
"requirements":["..."],"notes":["..."]}}

Guidelines:
- multi_frame means the harness should decode one fuzz input as a bounded
  sequence of frames/commands while keeping relevant state alive within one
  LLVMFuzzerTestOneInput iteration.
- max_steps is usually a harness policy; if it is not explicitly in source,
  set source to "engineering_choice".
- If checksum/length/magic fields are present, requirements should say which
  envelope fields should be repaired and which payload bytes should remain
  fuzz-controlled.
- Stateful operations must name real opcodes/cases from the protocol facts or
  source context, and each item must include evidence.
- If a fact cannot be inferred, use an empty string/list rather than guessing.

Entry function:
{entry_function}

Static protocol facts:
{protocol_facts}

Source context:
{source_context}""",
)


PROMPT_TEMPLATES: Mapping[str, PromptTemplate] = {
    template.name: template
    for template in (
        STAGE1_FUNCTION_DOC,
        STAGE2_STRUCTURE_SNIPPET,
        STAGE3_ROUGH_ASSEMBLY,
        PROTOCOL_CONVENTION_REFINEMENT,
        STAGE4_HARNESS_PLAN,
        STAGE4_HARNESS_TRANSFORM,
    )
}


def get_prompt_template(name: str) -> PromptTemplate:
    try:
        return PROMPT_TEMPLATES[name]
    except KeyError as error:
        raise KeyError(f"unknown prompt template: {name}") from error


def stage1_function_doc(*, function_signature: Any, function_source: Any,
                        usage_context: Any) -> RenderedPrompt:
    return STAGE1_FUNCTION_DOC.render(
        function_signature=function_signature,
        function_source=function_source,
        usage_context=usage_context,
    )


def stage2_structure_snippet(*, input_structure: Any, output_structure: Any,
                             functions: Any, dependencies: Any,
                             documentation: Any) -> RenderedPrompt:
    return STAGE2_STRUCTURE_SNIPPET.render(
        input_structure=input_structure,
        output_structure=output_structure,
        functions=functions,
        dependencies=dependencies,
        documentation=documentation,
    )


def stage3_rough_assembly(*, snippets: Any, structural_dependencies: Any,
                          function_metadata: Any, project_context: Any = (),
                          validation_feedback: Any = None) -> RenderedPrompt:
    return STAGE3_ROUGH_ASSEMBLY.render(
        snippets=snippets,
        structural_dependencies=structural_dependencies,
        function_metadata=function_metadata,
        project_context=project_context,
        validation_feedback=validation_feedback or {},
    )


def coverage_obligations(structural_steps: Any, ft_functions: Any) -> str:
    """Render the step-by-step coverage checklist the plan validator enforces.

    The validator (``stage4.py``) checks two separate things: every structural
    step is satisfied by one of its own candidate functions, and every FT
    function is invoked at least once.  A large FT can declare more steps than
    functions -- ``xmlOutputBufferCreateBuffer`` carries both the
    ``xmlBuffer -> xmlOutputBuffer`` and the
    ``xmlCharEncodingHandler -> xmlOutputBuffer`` step -- so a plan built to
    the step count over-calls and a plan built to the function count looks
    short.  Spelling out both numbers, and which steps share a function, is
    what keeps the two readings from being confused.
    """

    def _count(count: int, noun: str) -> str:
        return f"{count} {noun}" if count == 1 else f"{count} {noun}s"

    def _strings(value: Any) -> list[str]:
        if not isinstance(value, (list, tuple)):
            return []
        return [name for name in value if isinstance(name, str)]

    steps: list[tuple[str, str, list[str]]] = []
    for step in structural_steps if isinstance(structural_steps, (list, tuple)) else ():
        if not isinstance(step, Mapping):
            continue
        source = step.get("source")
        target = step.get("target")
        steps.append((
            source if isinstance(source, str) else "?",
            target if isinstance(target, str) else "?",
            _strings(step.get("functions")),
        ))
    functions = sorted(set(_strings(ft_functions)))

    lines = [
        f"Structural steps declared: {len(steps)}. Distinct FT functions: "
        f"{len(functions)}. These are two different numbers, and your plan must "
        "be built from the functions, not from the steps.",
        "",
        "Structural steps (each must be satisfied: at least one function listed "
        "for it appears in call_sequence or cleanup_sequence):",
    ]
    for index, (source, target, candidates) in enumerate(steps, start=1):
        described = ", ".join(candidates) if candidates else "(no candidate function)"
        lines.append(f"  {index}. {source} -> {target}: {described}")

    claims: dict[str, list[int]] = {}
    for index, (_, _, candidates) in enumerate(steps, start=1):
        for name in candidates:
            claims.setdefault(name, []).append(index)
    shared = sorted(
        (name, indexes) for name, indexes in claims.items() if len(indexes) > 1
    )
    lines.append("")
    if shared:
        lines.append(
            "Functions claimed by more than one step -- one call each satisfies "
            "all of them:"
        )
        lines.extend(
            f"  - {name}: satisfies steps "
            + ", ".join(str(index) for index in indexes)
            for name, indexes in shared
        )
    else:
        lines.append("No function is claimed by more than one step.")

    uncovered = [name for name in functions
                 if not any(name in candidates for _, _, candidates in steps)]
    lines.append("")
    if uncovered:
        lines.append(
            "Functions declared by no structural step (no step depends on them, "
            "but every FT function must still be called):"
        )
        lines.extend(f"  - {name}" for name in uncovered)
    else:
        lines.append("Every FT function is claimed by at least one step above.")

    lines.extend([
        "",
        "Invariants the validator checks after parsing your plan:",
        f"  1. Every structural step above ({_count(len(steps), 'step')}) is "
        "satisfied by at least one of its own candidate functions.",
        f"  2. Every FT function ({_count(len(functions), 'function')}) appears at "
        "least once across call_sequence and cleanup_sequence.",
        "  3. No function appears more than once across call_sequence and "
        "cleanup_sequence. The only exception is a function an ownership "
        "relation's observed_sequence records more than once; repeat it at most "
        "as many times as that sequence records.",
        "",
        "One call satisfies every step that names its function. Steps listing the "
        "same function are one obligation realised by one call, never one call "
        "each, and never a second call to balance the step count against the "
        "function count.",
    ])
    if shared:
        lines.append(
            "A complete plan for this FT therefore invokes each of the "
            f"{_count(len(functions), 'function')} once, not each of the "
            f"{_count(len(steps), 'step')} once."
        )
    return "\n".join(lines)


def stage4_harness_plan(*, triplet_id: Any, rough_code: Any, unique_isf: Any,
                        function_metadata: Any, bypass_semantics: Any = (),
                        ownership_relations: Any = (),
                        structural_steps: Any = (),
                        ft_functions: Any = (),
                        project_context: Any = (),
                        protocol_contract: Any = None,
                        protocol_contract_bindings: Any = None,
                        contract_id: Any = None,
                        contract_fact_ids: Any = (),
                        target_contract: Any = None,
                        validation_feedback: Any = None,
                        parent_plan: Any = None,
                        optimization_feedback: Any = None) -> RenderedPrompt:
    return STAGE4_HARNESS_PLAN.render(
        triplet_id=triplet_id,
        rough_code=rough_code,
        unique_isf=unique_isf,
        function_metadata=function_metadata,
        bypass_semantics=bypass_semantics,
        ownership_relations=ownership_relations,
        structural_steps=structural_steps,
        coverage_obligations=coverage_obligations(structural_steps, ft_functions),
        project_context=project_context,
        protocol_contract=protocol_contract or {},
        protocol_contract_bindings=protocol_contract_bindings,
        contract_id=contract_id,
        contract_fact_ids=contract_fact_ids,
        target_contract=target_contract or {},
        validation_feedback=validation_feedback or {},
        parent_plan=parent_plan or {},
        optimization_feedback=optimization_feedback or {},
    )


def stage4_harness_transform(*, harness_plan: Any, rough_code: Any,
                             unique_isf: Any, function_metadata: Any,
                             ownership_relations: Any = (),
                             project_context: Any = (),
                             protocol_contract: Any = None,
                             protocol_contract_bindings: Any = None,
                             contract_id: Any = None,
                             contract_fact_ids: Any = (),
                             validation_feedback: Any = None,
                             target_contract: Any = None) -> RenderedPrompt:
    return STAGE4_HARNESS_TRANSFORM.render(
        harness_plan=harness_plan,
        rough_code=rough_code,
        unique_isf=unique_isf,
        function_metadata=function_metadata,
        ownership_relations=ownership_relations,
        project_context=project_context,
        protocol_contract=protocol_contract or {},
        protocol_contract_bindings=protocol_contract_bindings,
        contract_id=contract_id,
        contract_fact_ids=contract_fact_ids,
        validation_feedback=validation_feedback or {},
        target_contract=target_contract or {},
    )


def protocol_convention_refinement(*, entry_function: Any, protocol_facts: Any,
                                   source_context: Any) -> RenderedPrompt:
    return PROTOCOL_CONVENTION_REFINEMENT.render(
        entry_function=entry_function,
        protocol_facts=protocol_facts,
        source_context=source_context,
    )


def _printable(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True,
                          allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("prompt parameters must be strings or JSON-serializable values") from error
