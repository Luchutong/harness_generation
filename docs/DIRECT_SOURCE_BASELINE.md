# Source-only harness baseline: one request

This is a one-shot comparison for `mp_parse`, recorded on 2026-09-21. The
request gave `deepseek-v4-flash` the full `parser.h` and `parser.c`, plus a
generic C++17 libFuzzer harness task. It did **not** include the Function
Triplet, ProtocolIR, the hand-written harness, or feedback from a compiler or
coverage run. Temperature was 0.2; one request returned a complete response
(`finish_reason=stop`). The exact request, response, harness, source hashes,
and measurements are in `tests/fixtures/direct_source_baseline/`.

The returned `harness.cpp` compiles and runs. It initializes one context,
passes the whole input to `mp_parse`, then tries to split up to eight frames
using a length it finds in the bytes. It does not synthesize or repair the
magic, version, length, or checksum. The fixed corpus contains command bytes,
not complete wire frames; the run therefore remains at the parser's initial
format guard. None of the three runs entered `mp_checksum` or an opcode body.

All measurements below used the same `target.c` implementation, structured
corpus, C target object plus C++ harness object, sanitizer-free LLVM target
source coverage, 20,000 executions, and seeds 1, 2, 3. `target.c`'s parser
implementation is byte-for-byte the same as `parser.c` from its
`#include <limits.h>` onward. The exact `fuzz_structured.cpp` was measured
separately with the same build recipe; its numbers match the reference arm
reported in `docs/GENERATION_VARIANCE.md`.

| Harness | Lines | Regions | Branches |
|---|---:|---:|---:|
| Source-only, seeds 1–2 | 10/82 (12.20%) | 15/76 (19.74%) | 7/68 (10.29%) |
| Source-only, seed 3 | 10/82 (12.20%) | 14/76 (18.42%) | 5/68 (7.35%) |
| Three staged generations, nine runs | 81/82 (98.78%) each | 69–71/76 (90.79–93.42%) | 55–57/68 (80.88–83.82%) |
| Exact hand-written `fuzz_structured.cpp` | 78/82 (95.12%) | 70/76 (92.11%) | 56/68 (82.35%) |

This result identifies a concrete failure in **this one source-only output**:
recognizing frame fields in comments and code was not enough; the harness
needed to construct an accepted outer frame. It is not an isolated causal
estimate of ProtocolIR's contribution. The staged path also uses different
prompts, several LLM calls, validation and a rollback retry; another direct
source prompt or another generation may behave differently.
