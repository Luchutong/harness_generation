# FT authority and lifecycle closure

An FT is useful for harness generation only when it is closed over the values
that must exist before the target call and the actions required after it. Graph
reachability alone cannot establish this property.

## Authority levels

The framework treats authority as accumulated evidence:

| Level | Required evidence | Use |
| --- | --- | --- |
| A0 structural candidate | ISF classification and local SFG slice | Inspection only |
| A1 type closed | Resolved parameters, returns, typedef indirection and ABI macros | May enter lifecycle analysis |
| A2 lifecycle closed | Producer, consumer and cleanup agree on a resource type and value flow | Eligible for generation |
| A3 build validated | Harness compiles, links and passes runtime smoke | Eligible for fuzzing |
| A4 reachability validated | Target-scoped coverage proves the intended target executed | Preferred long-running harness |

`triplets rank` now rejects an A1 FT when its ISF consumes an opaque handle but
no ownership relation closes that handle. Compile success does not upgrade an FT
to A4; target coverage is separate evidence.

## Opaque handle recovery

For a declaration such as:

```c
typedef struct ParserImpl *Parser;
```

the parser records `Parser` as an opaque handle and restores the hidden pointer
depth in every function signature. Return type macros such as `API(Parser)` are
unwrapped before type resolution. These facts are persisted in functions schema
v3 as:

- top-level `opaque_handles` declarations;
- `is_opaque_handle` on parameters;
- `return_is_opaque_handle` on functions;
- effective pointer depth after typedef expansion.

## Lifecycle relation inference

An inferred relation requires all of the following:

1. The resource type comes from an opaque struct or union pointer typedef.
2. A producer returns that exact handle type.
3. A cleanup accepts exactly one non-const value of that handle type and returns
   `void`.
4. Producer and cleanup semantics have construction/release evidence from names,
   documentation, or bodies.
5. The cleanup candidate is unique at the best evidence score.

Ambiguous cleanup candidates fail closed. Every accepted relation stores its
evidence, confidence and source in `ownership.json`.

For complete structs, parse/decode/from functions additionally need an
allocation origin in their implementation or an explicit ownership contract.
Matching a `parse` name and a `free` signature alone does not prove that a
returned pointer is owned. A wrapper may inherit allocation evidence through
a call to its implementation or through a configured default allocator.

## FT closure and scope control

Opaque handles are lifecycle boundary nodes. SFG traversal stops at such a node,
because traversing through a shared handle would pull every API that accepts the
handle into one oversized FT.

When no in-project usage evidence exists, the extractor chooses one
high-confidence producer/cleanup relation for each handle consumed by the ISF.
It prefers higher confidence, then the producer with fewer parameters, then
stable function identity. This is the conservative static fallback. The
resulting FT contains:

```text
producer -> handle -> ISF -> cleanup
```

The ownership relation records the ISF as a consumer. Stage 4 therefore checks
that the producer result is saved, passed to the target, and released exactly
once after all consumers.

The FT metadata contains `authority`, `lifecycle_closure`, and
`opaque_boundary_nodes` so the decision can be audited.

## In-project usage mining

Phase 1 also writes `usage_patterns.json`. It parses every project-owned C
function body and retains two layers of evidence:

- `traces`: ordered calls to known project APIs, classified as `test`,
  `example`, or `production` by source path;
- `patterns`: resource lifecycles grouped by their complete normalized shape.

The miner follows one variable from a producer return or `&out` argument through
consumer argument positions to cleanup. Direct variable aliases are normalized.
Different variables in the same caller are never joined. Each pattern stores
`support_total`, `support_by_source`, and all caller locations instead of
discarding observations after the first match.

A pattern identity includes producer mode, ordered consumers, their argument
positions, cleanup argument position, conditions, path kind, and lifecycle
kind. Consequently, create/parse/free and createNS/reset/parse/free remain two
FT variants even when they share an ISF and resource type. Variant identity is
included in the stable FT hash.

The lifecycle model supports:

- owned return values;
- out-parameter producers;
- reference-count retain/release pairs over an existing argument;
- unconditional and conditional cleanup;
- cleanup in a branch that exits through `return` or `goto`, recorded as an
error path.

## Constrained LLM semantic review

When Phase 1 uses `--semantic-analyzer llm`, each resource-local batch of mined
patterns is sent to the same semantic backend after static extraction. The model
reviews lifecycle validity, identifies the required executable subsequence,
marks optional diagnostic/setup calls, and assigns an equivalence group. The
prompt, strict JSON response, confidence, model reason, and provider failure
status are persisted under `semantic_reviews` and each pattern's
`semantic_review`.

The LLM is an evidence reviewer rather than a source of new edges. A decision is
discarded unless its required sequence is a real ordered subsequence, starts at
the observed producer, ends at the observed cleanup, retains every ISF call,
and uses only observed APIs. Static resource type, variable flow, argument
positions, lifecycle kind, normal/error path, and conditions remain immutable.
Provider errors retain the static pattern and are recorded without exposing
provider details. A failed batch is recursively split so one malformed decision
does not discard unrelated patterns; a failed singleton is retried once before
the static fallback is used.

Two patterns are merged into one executable FT only when the LLM gives the same
group and the immutable lifecycle fields plus required sequence agree. Support
counts and evidence are summed. Different producers, cleanup paths, reference
count modes, conditions, or required call sequences still produce separate FT
variants. This permits semantically optional calls to be collapsed without
recreating the original over-merged lifecycle problem.

`observed_sequence` is carried into the FT ownership contract with order and
duplicate calls intact. HarnessPlan and final C++ validation require that exact
project-API subsequence, so incremental parsers that call the target more than
once are not reduced to a one-call harness.

Structural steps preserve APIs with the same SFG endpoints as separate
obligations. Two functions form alternatives only when the parsed wrapper body
directly delegates to the other function and their endpoints and lifecycle
roles agree. The evidence is stored in FT metadata as
`structural_alternatives` and shown to Stage 4.

Stage 4 carries these fields into its ownership contract and checks the actual
producer argument or assignment, cleanup argument position, ordering, and
required code guard. `triplets rank` policy `ft-priority-v4` adds a usage-support
metric based on observation frequency, source diversity, and production usage,
tracks ISF target novelty separately from helper overlap, and excludes an
existing `LLVMFuzzerTestOneInput` from generation targets.

Compile, runtime, and target-scoped coverage remain later authority levels.
They should feed a separate posterior score so the mined evidence stays
auditable.
