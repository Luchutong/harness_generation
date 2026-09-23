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
passthrough. Do not invent a length prefix, magic, checksum, padding, or
multi-frame framing. For explicit-length APIs, pass the fuzzer-controlled
buffer and length directly, using casts only when declared types require them.

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
    version="stage4-harness-plan-v5",
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
"identifier":"..."}},"after":["..."]}}],
"constraints":["..."],"notes":["..."]}}

Every FT function must appear in call_sequence or cleanup_sequence. When an
ownership relation supplies observed_sequence, preserve its order and repeat a
function exactly as many times as that sequence records; otherwise use it once.
The unique ISF must appear in call_sequence and must use both fuzzer data and
fuzzer size when the signature has a byte stream and length parameter. If a
function is both PRF and HPF, keep it in call_sequence and mention cleanup
responsibility in purpose or notes. Cleanup must happen after downstream
processing. Ownership cleanup is a scoped exception: use it only when the
supplied FunctionTriplet ownership_relations contains the exact relation, keep
it in cleanup_sequence, bind it using the relation's producer_binding and
producer_argument_index, and include every declared consumer in after. A
conditional, error-path, or nullable cleanup requires an explicit
null-safe condition. Never infer cleanup permission from prose, a null structural
endpoint, or a global API allowlist.
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
byte/text passthrough:
do not invent a length prefix, magic, checksum, padding, or multi-frame framing.
For explicit-length APIs, bind the fuzzer-controlled buffer and size directly.

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


def stage4_harness_plan(*, triplet_id: Any, rough_code: Any, unique_isf: Any,
                        function_metadata: Any, bypass_semantics: Any = (),
                        ownership_relations: Any = (),
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
