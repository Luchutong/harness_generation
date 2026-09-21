# mini_parser Benchmark

This benchmark is adapted from the `mini_parser` source project. Its original
checkout path is recorded as provenance in `manifest.json`; no command here
requires that path.

`target.c` is an amalgamation of `parser.h` and `parser.c`, so the existing
single-file harness-generation pipeline can pass the complete target to the
LLM and compile a harness by including exactly one `"target.c"`.

The target API is:

```c
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);
```

`harnesses/structured.c` is the C11 equivalent of
the source project's `fuzz/fuzz_structured.cpp`. It converts fuzzer
bytes into a sequence of valid mini_parser frames, keeps one `mp_context` alive
for all commands in the same fuzz input, and destroys the context at the end.

`harnesses/pass_through.c` is intentionally much weaker: it invokes `mp_parse`
once with raw `Data`/`Size`. It is a feedback-loop baseline only; it is never
provided to the model as a hidden reference implementation.

`protocol.json` is the declarative contract supplied to LLM prompts. It spells
out the mini_parser frame layout, little-endian length/checksum fields,
stateful context lifetime, and the bounded multi-frame command-loop requirement.
The generator can auto-discover it next to `target.c`, or it can be passed
explicitly with `--protocol-spec`.

Run the reference harness through this framework with:

```bash
python3 -m harness_generation \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --harness benchmarks/mini_parser/harnesses/structured.c \
  --output runs/mini_parser_structured_reference \
  --fuzz-seconds 5 \
  --corpus benchmarks/mini_parser/corpus/structured
```

Run one real provider-backed feedback revision round from the weak baseline:

```bash
export DEEPSEEK_API_KEY='...'
python3 -m harness_generation feedback-loop \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --parent-harness benchmarks/mini_parser/harnesses/pass_through.c \
  --output runs/mini_parser_feedback_loop \
  --rounds 1 \
  --children-per-round 2 \
  --feedback-threshold 0.9
```

The loop saves `round_000/automatic_feedback.json`, injects that exact packet
plus its evidence snapshots into each round-1 LLM prompt, evaluates every child,
and records the selected child in `feedback_loop.json`. It does not claim that
selection proves semantic improvement; absent dynamic probes remain unknown.
