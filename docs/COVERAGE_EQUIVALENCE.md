# Coverage equivalence: the contract path against the reference

`docs/PROTOCOL_FORMAT_MINING.md` §5.3 asks whether a spec-driven generic harness reaches the coverage the hand-written reference harness reaches. This document answers it for one benchmark, and it is generated from the measurement it reports: `harness_generation/coverage_arms.py` writes `tests/fixtures/coverage_arms/measurements.json`, and `python -m harness_generation coverage-arms --report docs/COVERAGE_EQUIVALENCE.md` renders that file into this one. No number below is typed by hand.

## Arms

| arm | role | recipe | sha256 | bytes | source |
| --- | --- | --- | --- | --- | --- |
| `reference` | `accepted_reference` | `single_tu` | `6039764f6fd3` | 1160 | `benchmarks/mini_parser/harnesses/structured.c` |
| `contracted` | `published_contracted` | `two_tu` | `49a5a01c87cf` | 1845 | `tests/fixtures/coverage_arms/contracted_published.c` |
| `ft_only` | `published_ft_only` | `two_tu` | `20447fb262a3` | 494 | `tests/fixtures/coverage_arms/ft_only_published.c` |
| `pass_through` | `tracked_baseline` | `single_tu` | `155663f1033e` | 492 | `benchmarks/mini_parser/harnesses/pass_through.c` |
| `rejected_attempt_003` | `diagnostic_rejected` | `two_tu` | `fc0cd8ef29b7` | 2165 | `tests/fixtures/stage4_recorded_attempts/attempt_003.c` |

Only `published_contracted` and `published_ft_only` are candidates; the reference is a human baseline and `diagnostic_rejected` is the attempt the audit refused, measured to show what the refusal was worth. `--with-diagnostic-arm` is what includes it.

## Budget and seeds

`20000` executions per arm per seed, seeds 1, 2, 3, corpus `benchmarks/mini_parser/corpus/structured` copied by content hash into every run. Coverage is measured with the sanitizers off (`-x c++ -std=c++17 -g -O1 -fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping` for the harness), so no arm is truncated by its own finding and equal `-runs` is equal work.

```
clang: Ubuntu clang version 18.1.3 (1ubuntu1)
clang++: Ubuntu clang version 18.1.3 (1ubuntu1)
llvm-cov: Ubuntu LLVM version 18.1.3
llvm-profdata: Ubuntu LLVM version 18.1.3
```

## Layer A — `instrumented_program` (telemetry, not the gate)

libFuzzer `cov`/`ft` over the whole instrumented program, harness included, built with the sanitizers the pipeline uses. A run that found something stopped at the finding, so its numbers are coverage-at-first-crash and are not comparable across arms.

| arm | seed | status | cov | ft | executed | truncated | findings |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `reference` | 1 | `finding` | 36 | 64 | 43 | yes | libfuzzer_error, undefined_behavior |
| `reference` | 2 | `finding` | 33 | 51 | 10 | yes | address_sanitizer |
| `reference` | 3 | `finding` | 35 | 61 | 16 | yes | address_sanitizer |
| `contracted` | 1 | `finding` | 66 | 68 | 1348 | yes | address_sanitizer |
| `contracted` | 2 | `finding` | 60 | 62 | 1240 | yes | address_sanitizer |
| `contracted` | 3 | `finding` | 71 | 85 | 801 | yes | libfuzzer_error, undefined_behavior |
| `ft_only` | 1 | `completed` | 11 | 12 | 20000 | no | — |
| `ft_only` | 2 | `completed` | 11 | 12 | 20000 | no | — |
| `ft_only` | 3 | `completed` | 11 | 12 | 20000 | no | — |
| `pass_through` | 1 | `completed` | 6 | 7 | 20000 | no | — |
| `pass_through` | 2 | `completed` | 6 | 7 | 20000 | no | — |
| `pass_through` | 3 | `completed` | 6 | 7 | 20000 | no | — |
| `rejected_attempt_003` | 1 | `finding` | 67 | 70 | 1348 | yes | address_sanitizer |
| `rejected_attempt_003` | 2 | `finding` | 61 | 64 | 1240 | yes | address_sanitizer |
| `rejected_attempt_003` | 3 | `finding` | 74 | 99 | 801 | yes | libfuzzer_error, undefined_behavior |

## Layer B — `target_code` (the gate)

LLVM source-based coverage filtered to `target.c`, sanitizers off, every arm at the same `-runs`. `functions` is reported and not gated: a single-TU build can inline a target function into the harness and leave its own counter at zero while its regions are covered.

| arm | seed | status | lines | regions | branches | functions | entered |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `reference` | 1 | `passed` | 78/82 (95.122%) | 70/76 (92.1053%) | 56/68 (82.3529%) | 5/5 (100.0%) | _Z10mp_destroyP10mp_context, _Z11mp_checksumPKhm, _Z7mp_initP10mp_context, _Z8mp_parseP10mp_contextPKhm, harness.c:_ZL4le16PKh |
| `reference` | 2 | `passed` | 78/82 (95.122%) | 70/76 (92.1053%) | 56/68 (82.3529%) | 5/5 (100.0%) | _Z10mp_destroyP10mp_context, _Z11mp_checksumPKhm, _Z7mp_initP10mp_context, _Z8mp_parseP10mp_contextPKhm, harness.c:_ZL4le16PKh |
| `reference` | 3 | `passed` | 78/82 (95.122%) | 70/76 (92.1053%) | 56/68 (82.3529%) | 5/5 (100.0%) | _Z10mp_destroyP10mp_context, _Z11mp_checksumPKhm, _Z7mp_initP10mp_context, _Z8mp_parseP10mp_contextPKhm, harness.c:_ZL4le16PKh |
| `contracted` | 1 | `passed` | 78/82 (95.122%) | 67/76 (88.1579%) | 53/68 (77.9412%) | 5/5 (100.0%) | mp_checksum, mp_destroy, mp_init, mp_parse, target.c:le16 |
| `contracted` | 2 | `passed` | 78/82 (95.122%) | 67/76 (88.1579%) | 53/68 (77.9412%) | 5/5 (100.0%) | mp_checksum, mp_destroy, mp_init, mp_parse, target.c:le16 |
| `contracted` | 3 | `passed` | 78/82 (95.122%) | 67/76 (88.1579%) | 53/68 (77.9412%) | 5/5 (100.0%) | mp_checksum, mp_destroy, mp_init, mp_parse, target.c:le16 |
| `ft_only` | 1 | `passed` | 10/82 (12.1951%) | 16/76 (21.0526%) | 8/68 (11.7647%) | 3/5 (60.0%) | mp_destroy, mp_init, mp_parse |
| `ft_only` | 2 | `passed` | 10/82 (12.1951%) | 16/76 (21.0526%) | 8/68 (11.7647%) | 3/5 (60.0%) | mp_destroy, mp_init, mp_parse |
| `ft_only` | 3 | `passed` | 10/82 (12.1951%) | 16/76 (21.0526%) | 8/68 (11.7647%) | 3/5 (60.0%) | mp_destroy, mp_init, mp_parse |
| `pass_through` | 1 | `passed` | 10/82 (12.1951%) | 16/76 (21.0526%) | 8/68 (11.7647%) | 3/5 (60.0%) | _Z10mp_destroyP10mp_context, _Z7mp_initP10mp_context, _Z8mp_parseP10mp_contextPKhm |
| `pass_through` | 2 | `passed` | 10/82 (12.1951%) | 16/76 (21.0526%) | 8/68 (11.7647%) | 3/5 (60.0%) | _Z10mp_destroyP10mp_context, _Z7mp_initP10mp_context, _Z8mp_parseP10mp_contextPKhm |
| `pass_through` | 3 | `passed` | 10/82 (12.1951%) | 16/76 (21.0526%) | 8/68 (11.7647%) | 3/5 (60.0%) | _Z10mp_destroyP10mp_context, _Z7mp_initP10mp_context, _Z8mp_parseP10mp_contextPKhm |
| `rejected_attempt_003` | 1 | `passed` | 78/82 (95.122%) | 68/76 (89.4737%) | 54/68 (79.4118%) | 5/5 (100.0%) | mp_checksum, mp_destroy, mp_init, mp_parse, target.c:le16 |
| `rejected_attempt_003` | 2 | `passed` | 78/82 (95.122%) | 67/76 (88.1579%) | 53/68 (77.9412%) | 5/5 (100.0%) | mp_checksum, mp_destroy, mp_init, mp_parse, target.c:le16 |
| `rejected_attempt_003` | 3 | `passed` | 78/82 (95.122%) | 67/76 (88.1579%) | 53/68 (77.9412%) | 5/5 (100.0%) | mp_checksum, mp_destroy, mp_init, mp_parse, target.c:le16 |

### Seed spread

The seed changes the target coverage of `rejected_attempt_003`. Every other arm measures the same at every seed, so for those the rows above are one measurement.

### The refused attempt

`rejected_attempt_003` is the attempt Stage 4 refused, measured here only as a diagnostic. Its target coverage is lines 95.122%, regions 88.1579%–89.4737%, branches 77.9412%–79.4118%; `contracted`'s is lines 95.122%, regions 88.1579%, branches 77.9412%.

The two differ on at least one metric, on at least one seed.

Either way the audit was not a coverage filter. It refused this harness for reimplementing one of the project's own algorithms, which is a judgement about the harness rather than about how much of the target it reaches -- so its target coverage says nothing about whether the refusal was right, and this arm is here only to show what the refusal cost in coverage terms. Nothing above endorses it: it stays what the gates made it, which is not a product, and it is not a candidate for the gate.

### Recipe control

`ft_only` minus `pass_through`, in percentage points per seed:

| metric | seed 1 | seed 2 | seed 3 |
| --- | --- | --- | --- |
| `branches` | 0.0 | 0.0 | 0.0 |
| `lines` | 0.0 | 0.0 | 0.0 |
| `regions` | 0.0 | 0.0 | 0.0 |

ft_only minus pass_through, in target-coverage percentage points, one value per seed.  Both arms make the same one call on raw bytes, so this bounds the translation-unit/language-mode/inlining effect on the rest of the table.

### Determinism

`reference` at seed 1, run twice: identical = `True` over status, coverage_edges_or_blocks, features, executed_units. A same-seed repeat is a replay, which is why the campaign counts distinct seeds instead.

## Gate

Candidate `contracted` (role `published_contracted`) against `reference`, tolerance 0.05, verdict **`below_reference`**.

| metric | seed | reference % | candidate % | ratio | strict | within tolerance |
| --- | --- | --- | --- | --- | --- | --- |
| `branches` | 1 | 82.3529 | 77.9412 | 0.946429 | False | False |
| `branches` | 2 | 82.3529 | 77.9412 | 0.946429 | False | False |
| `branches` | 3 | 82.3529 | 77.9412 | 0.946429 | False | False |
| `lines` | 1 | 95.122 | 95.122 | 1.0 | True | True |
| `lines` | 2 | 95.122 | 95.122 | 1.0 | True | True |
| `lines` | 3 | 95.122 | 95.122 | 1.0 | True | True |
| `regions` | 1 | 92.1053 | 88.1579 | 0.957143 | False | True |
| `regions` | 2 | 92.1053 | 88.1579 | 0.957143 | False | True |
| `regions` | 3 | 92.1053 | 88.1579 | 0.957143 | False | True |

An arm-level verdict requires every seed to pass: a metric that holds at one seed and not another has not been shown to hold.

## Budget sensitivity

The same arms at other budgets, coverage layer only. A harness that has to search for an input the target accepts needs executions to reach what a harness that constructs a valid frame directly reaches at once, so this is where a verdict that is really a statement about one budget shows itself.

### `-runs=2000`

| arm | seed | status | lines | regions | branches |
| --- | --- | --- | --- | --- | --- |
| `reference` | 1 | `passed` | 78/82 (95.122%) | 70/76 (92.1053%) | 56/68 (82.3529%) |
| `reference` | 2 | `passed` | 78/82 (95.122%) | 70/76 (92.1053%) | 56/68 (82.3529%) |
| `reference` | 3 | `passed` | 78/82 (95.122%) | 70/76 (92.1053%) | 56/68 (82.3529%) |
| `contracted` | 1 | `passed` | 65/82 (79.2683%) | 56/76 (73.6842%) | 43/68 (63.2353%) |
| `contracted` | 2 | `passed` | 73/82 (89.0244%) | 61/76 (80.2632%) | 49/68 (72.0588%) |
| `contracted` | 3 | `passed` | 72/82 (87.8049%) | 60/76 (78.9474%) | 48/68 (70.5882%) |
| `ft_only` | 1 | `passed` | 10/82 (12.1951%) | 15/76 (19.7368%) | 6/68 (8.8235%) |
| `ft_only` | 2 | `passed` | 10/82 (12.1951%) | 15/76 (19.7368%) | 6/68 (8.8235%) |
| `ft_only` | 3 | `passed` | 10/82 (12.1951%) | 15/76 (19.7368%) | 6/68 (8.8235%) |
| `pass_through` | 1 | `passed` | 10/82 (12.1951%) | 15/76 (19.7368%) | 6/68 (8.8235%) |
| `pass_through` | 2 | `passed` | 10/82 (12.1951%) | 15/76 (19.7368%) | 6/68 (8.8235%) |
| `pass_through` | 3 | `passed` | 10/82 (12.1951%) | 15/76 (19.7368%) | 6/68 (8.8235%) |
| `rejected_attempt_003` | 1 | `passed` | 75/82 (91.4634%) | 63/76 (82.8947%) | 50/68 (73.5294%) |
| `rejected_attempt_003` | 2 | `passed` | 68/82 (82.9268%) | 59/76 (77.6316%) | 46/68 (67.6471%) |
| `rejected_attempt_003` | 3 | `passed` | 72/82 (87.8049%) | 60/76 (78.9474%) | 48/68 (70.5882%) |

Verdict at this budget: **`below_reference`** (min ratios `branches` 0.767858, `lines` 0.833333, `regions` 0.8)

## Caveats

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

## Reproduce

```bash
python -m harness_generation coverage-arms \
    --artifacts artifacts/coverage_arms \
    --runs 20000 \
    --seeds 1,2,3 \
    --with-diagnostic-arm \
    --record tests/fixtures/coverage_arms/measurements.json
python -m harness_generation coverage-arms --report docs/COVERAGE_EQUIVALENCE.md
python -m harness_generation coverage-arms --check
```
