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
    version="stage1-function-doc-v1",
    template="""You are documenting a C function for a later harness-generation pass.
Use only the supplied source and context. Do not redefine the function or invent
functions, types, APIs, or semantics that cannot be supported by the source.

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
    version="stage2-structure-snippet-v2",
    template="""Produce a focused C snippet for one structural-flow step.
Explicitly call every supplied function, preserve dependencies, and use only the
provided functions. Do not reimplement target functions, invent APIs, or add a
final LLVMFuzzerTestOneInput wrapper. Output C only, never C++.
Dependency identifiers describe ordering only; never call them as functions.

Input structure:
{input_structure}

Output structure:
{output_structure}

Functions:
{functions}

Dependencies:
{dependencies}

Function documentation:
{documentation}""",
)

STAGE3_ROUGH_ASSEMBLY = PromptTemplate(
    name="stage3_rough_assembly",
    version="stage3-rough-assembly-v2",
    template="""Assemble the supplied C snippets into one coherent rough C program.
Order operations by structural dependencies, reconcile shared variables and
cleanup, pass output structures into their downstream inputs, and preserve all
necessary function calls. Do not merely concatenate, redefine project APIs, or
invent APIs. Return only C source without Markdown fences. This is a rough code
sequence, not the final harness: do not emit LLVMFuzzerTestOneInput.
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
    version="stage4-harness-transform-v7",
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

Use only the supplied project functions plus necessary standard C/C++ library
utilities. Emit only C++ source without Markdown fences. Do not use using
namespace std. You may use straightforward C++ helpers such as std::array,
std::vector, std::min/std::max, lambdas, and scoped local helpers when they make
the input model clearer, but avoid complex classes or unrelated abstractions.
Pass the external data and size into the unique ISF according to its signature,
retain downstream FT calls, initialize writable objects before use, and perform
cleanup after processing.
If a protocol contract is supplied, implement its input model directly. For
framed command protocols, build a bounded multi-frame command loop, keep one
stateful context alive for the whole libFuzzer iteration, and populate declared
magic/version/opcode/length/checksum/payload fields exactly.
When input_model.requires_length_sampling is true, derive each frame's payload
length from a bounded fuzz-byte expression named by the plan. Use that sampled
length for the payload copy and the repaired length field; taking all remaining
input bytes as the payload length can collapse a multi-frame loop to one frame.

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

Protocol contract, if supplied:
{protocol_contract}

Previous validation feedback (empty on the first attempt):
{validation_feedback}""",
)

STAGE4_HARNESS_PLAN = PromptTemplate(
    name="stage4_harness_plan",
    version="stage4-harness-plan-v8",
    template="""Create a structured HarnessPlan before any final C harness is
written. Use the rough program, Function Triplet, and exact project declarations
to decide state objects, fuzzer-input decoding, call order, data/size binding,
required constraints, and cleanup. Do not output C source. Do not invent project
APIs or redefine project types.

Exact FunctionTriplet identity:
The HarnessPlan JSON field triplet_id MUST be exactly this string, byte-for-byte:
{triplet_id}
Do not use a function id, source location, path, line number, or unique_isf.id as
triplet_id. In particular, values like "src/file.c:line:function" are function
identifiers, not FunctionTriplet ids.

Return only one strict JSON object with exactly this shape:
{{"schema_version":1,"triplet_id":"{triplet_id}","entrypoint":"LLVMFuzzerTestOneInput",
"input_strategy":{{"description":"...","data_identifier":"data",
"size_identifier":"size","bounded_steps":0,
"payload_length_strategy":"fuzz_byte_bounded",
"payload_length_expression":"data[pos++] % (MAX_PAYLOAD + 1u)","notes":["..."]}},
"state_objects":[{{"name":"...","type":"...","initialization":"..."}}],
"call_sequence":[{{"function":"...","roles":["ISF"],"purpose":"...",
"arguments":["..."],"uses_fuzzer_data":true,"uses_fuzzer_size":true,
"outputs":["..."],"conditions":["..."]}}],
"cleanup_sequence":[{{"function":"...","purpose":"...",
"arguments":["..."],"after":["..."]}}],
"constraints":["..."],"notes":["..."],
"protocol_contract_bindings":{protocol_contract_bindings}}}

Every FT function must appear exactly once in call_sequence or cleanup_sequence.
The unique ISF must appear in call_sequence and must use both fuzzer data and
fuzzer size when the signature has a byte stream and length parameter. If a
function is both PRF and HPF, keep it in call_sequence and mention cleanup
responsibility in purpose or notes. Cleanup must happen after downstream
processing.
If a protocol contract is supplied, the plan must explicitly preserve its
structured input model. For framed command protocols, address these six
concerns:
1. bounded multi-frame command loop: use a bounded multi-frame command loop and
   set input_strategy.bounded_steps to a positive cap.
2. context lifetime across frames: name the context object, its init and destroy
   calls, and keep it alive across commands within one libFuzzer iteration.
3. exact frame fields: for every header field (magic, version, opcode, length,
   checksum) state its exact offset, width and endianness, and how the harness
   computes that value in C.
4. length/checksum repair: the length and checksum fields must be filled in by
   the harness while it assembles a frame, never left to whatever the fuzz input
   happens to contain.
5. payload remains fuzzer-controlled: the payload region, from
   frame.payload_offset up to frame.max_payload, must be driven by fuzz bytes
   and must not be filled with constants.
6. stateful opcodes and cleanup: trigger opcodes whose behavior depends on state
   left by an earlier command in order, after the command that establishes that
   state, and clean up within the iteration.
When input_model.requires_length_sampling is true, declare
input_strategy.payload_length_strategy as fuzz_byte_bounded and give a concrete
payload_length_expression that bounds a byte sampled from data. Follow any
stateful_dependencies pairs in their declared order. These are typed contract
facts; a description or opcode set cannot replace them.
protocol_contract_bindings carries the same facts as structured values, and it
is checked field by field against the contract: every leaf must equal the
contract's leaf, or the plan is rejected before any C is written.
- The object above is shown filled in when a contract was supplied, and null
  when one was not. Copy it exactly: same keys, same offsets, same widths, same
  values, same lists. Do not paraphrase a value and do not add a key.
- frame must repeat the contract's header_size, payload_offset, max_payload and
  every field's role, offset, width, endianness and literal value verbatim.
- input_model must state the contract's policy: a bounded multi-frame loop with
  the same positive bounded_steps as input_strategy.bounded_steps, the payload
  left fuzz-controlled, and length/checksum repair declared whenever the
  contract has those fields. Claiming less than the contract requires is a
  rejection.
- context must name the contract's type, init and destroy, and set lifetime to
  "per_iteration" -- the context carries state between commands, so it is
  created once per LLVMFuzzerTestOneInput call, never per frame.
- stateful_operations must list exactly the contract's opcodes and helpers must
  name only helpers the contract evidences. An extra name is an invented API.
If no protocol contract is supplied, fall back to FT-only harness planning: use
the unique ISF, required PRF/HPF calls, available function metadata, and
validation feedback. Do not invent a framed protocol. Leave
protocol_contract_bindings null: with no contract there is nothing to bind.

Rough program:
{rough_code}

Unique ISF:
{unique_isf}

Function metadata:
{function_metadata}

FT bypass semantics (non-SFG sidecar evidence; use these for scalar guards,
byte-stream/length binding, constants, return status, and struct access hints):
{bypass_semantics}

Project headers and exact type declarations:
{project_context}

Protocol contract, if supplied:
{protocol_contract}

Previous validation feedback (empty on the first attempt):
{validation_feedback}""",
)

PROTOCOL_CONVENTION_REFINEMENT = PromptTemplate(
    name="protocol_convention_refinement",
    version="protocol-convention-refinement-v2",
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
  source context. For context-member reads, writes and guards, cite the exact
  source statements (for example, `ctx->saved = p;`), not a prose summary.
  Each item must include evidence; statements absent from source are not evidence.
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


def stage4_harness_plan(*, triplet_id: Any, rough_code: Any, unique_isf: Any,
                        function_metadata: Any, bypass_semantics: Any = (),
                        project_context: Any = (),
                        protocol_contract: Any = None,
                        protocol_contract_bindings: Any = None,
                        validation_feedback: Any = None) -> RenderedPrompt:
    return STAGE4_HARNESS_PLAN.render(
        triplet_id=triplet_id,
        rough_code=rough_code,
        unique_isf=unique_isf,
        function_metadata=function_metadata,
        bypass_semantics=bypass_semantics,
        project_context=project_context,
        protocol_contract=protocol_contract or {},
        # ``None`` renders as JSON null, which is the instruction to the
        # FT-only run: carry no bindings at all.
        protocol_contract_bindings=protocol_contract_bindings,
        validation_feedback=validation_feedback or {},
    )


def stage4_harness_transform(*, harness_plan: Any, rough_code: Any,
                             unique_isf: Any, function_metadata: Any,
                             project_context: Any = (),
                             protocol_contract: Any = None,
                             validation_feedback: Any = None) -> RenderedPrompt:
    return STAGE4_HARNESS_TRANSFORM.render(
        harness_plan=harness_plan,
        rough_code=rough_code,
        unique_isf=unique_isf,
        function_metadata=function_metadata,
        project_context=project_context,
        protocol_contract=protocol_contract or {},
        validation_feedback=validation_feedback or {},
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
