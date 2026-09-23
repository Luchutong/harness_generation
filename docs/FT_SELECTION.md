# Function Triplet scoring and selection

The FT selector narrows a large project before harness generation. It uses only
persisted Phase 1 evidence and canonical `triplets.json`, so the result is
repeatable and can be reviewed without making LLM calls.

## Two levels

The selector first checks eligibility. An FT is eligible when its ISF has a
positively classified byte stream parameter and the FT has a nonempty function
footprint. If the ISF consumes an opaque handle, its producer/cleanup lifecycle
must also be closed by a validated ownership relation. Missing evidence is
recorded as `unavailable`; it is not silently converted to a zero score.

Eligible FTs receive an intrinsic score from five dimensions. Usage support is
included only when Phase 1 observed a lifecycle; unobserved FTs keep the former
four-dimension scale through measured-weight renormalization.

| Dimension | Weight | Evidence |
| --- | ---: | --- |
| Input evidence | 30% | Maximum confidence of a positive byte stream parameter on the ISF |
| Structural confidence | 25% | Annotation confidence, weakest decision, and fraction of non-inferred SFG edges |
| Structural opportunity | 25% | Saturating counts of PRFs, structures, source files, and edges |
| Harness readiness | 20% | Input binding, guards, return handling, struct access, and cleanup evidence |
| Usage support | 20% | Log-scaled observation count, source-kind diversity, production-caller presence, and lifecycle/LLM confidence |

The weighted mean is renormalized over measured dimensions. Each metric stores
its status, score, and raw evidence in the selection manifest. The score predicts
the expected value of attempting harness generation. It is not a claim that the
generated harness will compile or reach the target.

An existing `LLVMFuzzerTestOneInput` is excluded because it is already a
harness entry point, not a project API target.

## Cost model

The baseline cost is:

```text
number of FT functions + number of Stage 2 structural units + 3
```

The final `3` covers Stage 3 once and Stage 4 twice. Regeneration, validation,
and fuzzing are not included. The manifest records this limitation explicitly.

## Budgeted selection

The selector greedily chooses the fitting FT with the highest marginal benefit;
the call estimate breaks otherwise equal choices and the call budget remains a
hard limit. This avoids filling a finite FT count with cheap, weak callback
targets while leaving most of the call budget unused. Marginal benefit retains
70% of the intrinsic score and gives 30% to novelty. Novelty assigns 50% to an ISF that has not yet
been selected as a target, 35% to new helper functions, and 15% to new
structures. A function appearing as a helper in one FT therefore does not mark
that function as an already covered fuzz target. This reduces spending on FTs
that cover nearly the same project region while preserving distinct targets.
Stable FT IDs break ties, so identical inputs produce identical output.

Use both an FT count and a call budget when the project is large:

```bash
harness-generation triplets rank \
  --artifacts artifacts/project \
  --min-score 0.55 \
  --max-ft 20 \
  --max-calls 300
```

This writes `artifacts/project/ft_selection.json`. Generate exactly the selected
FTs, in the selected order, with:

```bash
harness-generation generate-all \
  --artifacts artifacts/project \
  --selection artifacts/project/ft_selection.json \
  --provider openai-compatible
```

The unselected ranking remains in the manifest. If the call budget cannot fit an
FT, the selector leaves it unselected rather than partially running its pipeline.
The manifest contains a SHA-256 fingerprint of the canonical FT catalog;
`generate-all` rejects a stale manifest after the catalog changes.

## Recommended large-project loop

1. Extract FTs and rank them with a conservative call budget.
2. Generate and validate the selected batch.
3. Measure target coverage for successful harnesses.
4. Remove project regions already covered and rank the remaining FTs again.
5. Treat repeated compile/runtime failures as new evidence for a future policy
   revision; `ft-priority-v3` intentionally uses only pre-generation evidence,
   including mined in-project usage.

Keep the `policy_version` with experiment results. Scores from different policy
versions should not be compared as though they used the same scale.
