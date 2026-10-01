# Frozen blind evaluation

`cohort_v2/` is the historical independently selected set: twelve new synthetic structures and
four pinned real libraries, covering string/owned object, opaque/feed,
callback and memory/stream input. Every native A/B/C trial uses the frozen
production implementation and fixed ceilings. Expected annotations and
reference programs remain outside `source/` and never enter the worker.
Its observed failures have since informed production changes. Keep its original
frozen results as historical blind evidence, but treat subsequent runs on this
set as development/regression; select a new independent set for a new blind cohort.

The original `synthetic/` and `real/` directories belong to an **invalidated
infrastructure pilot**. Its worker omitted the build recipe schema version;
20 completed and 4 interrupted trials were preserved, never retried. The pilot
also exposed overly restrictive creator/setter annotations and a callback field
matching omission. These are evaluation limitations, not confirmed Gate defects.
They are excluded from the current blind denominator. Production semantics,
prompts, Gate and budgets were unchanged; only evaluation plumbing/adjudication
was revised before selecting and running the new set.

```bash
.venv/bin/python -m scripts.blind_eval.freeze --output artifacts/<new-output>
# Select an independent set after freeze, before any native call.
.venv/bin/python -m scripts.blind_eval.runner --benchmark-dir benchmarks/blind/<new-set> --output artifacts/<new-output> --repetitions 5 --workers 4
.venv/bin/python -m scripts.blind_eval.report --input artifacts/<new-output> --output docs/BLIND_GENERALIZATION_EVALUATION.md
```

Once failures inform production rule changes, retire that set from blind evidence
and establish a new set. Source snapshots, annotation/code hashes, failed runs,
provider errors and preregistered schedules must remain preserved.
