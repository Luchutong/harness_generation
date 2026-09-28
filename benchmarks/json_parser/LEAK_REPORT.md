# json-parser: `json_parse_ex` leaks on the `max_memory` abort path

**Status:** confirmed, unpatched upstream · 2026-09-23
**Component:** [`json-parser/json-parser`](https://github.com/json-parser/json-parser) — `json.c`
**Upstream:** the benchmark's `project/json.c` is byte-identical to `master` today (`diff` against
`raw.githubusercontent.com/json-parser/json-parser/master/json.c` is empty), so this is live
upstream, not an artifact of the pinned commit
**CWE-401** · impact: availability (unbounded growth in a caller that caps parsing with `max_memory`)

## Summary

`json_parse_ex` cleans up after a failed parse by freeing one of two disjoint things — the
first-pass allocation chain, or the partially built value tree — and neither reaches the values
that are still *open* at the moment of the abort. A four-byte input leaks:

```c
json_settings s = { 0 };
s.max_memory = 88;
char err[json_error_max];
json_value *v = json_parse_ex(&s, "[\"\"]", 4, err);   /* returns NULL, err = "Memory allocation failure" */
/* LeakSanitizer: 40 byte(s) leaked in 1 allocation(s) */
```

The same class of leak costs 616 bytes in 21 allocations on a 199-byte input at the budget the
harness uses (`max_memory = 4096`).

## Root cause

`json_parse_ex` parses in two passes (`json.c:366`). Pass 1 allocates one `json_value` per value
(`json.c:280`) and threads them onto a chain that runs `root → … → tail` (`json.c:298-300`); pass 2
re-uses those structs (`json.c:175-176`) and allocates the payloads — array `values`, object
entries + key names, string buffers (`json.c:197`, `:242`, `:264`). A value is linked into its
parent's `values[]` **only once it is completed** (`json.c:1017-1040`), so at any instant the path
from `root` to `top` is held together by `parent` pointers alone.

`json_alloc` returns 0 when the running total passes `max_memory` (`json.c:156-159`). The failure
path is then `goto e_alloc_failure` → `e_failed` (`json.c:1084-1122`):

```c
 1109    if (state.first_pass)
 1110       alloc = root;

 1112    while (alloc)
 1113    {
 1114       top = alloc->_reserved.next_alloc;
 1115       state.settings.mem_free (alloc, state.settings.user_data);
 1116       alloc = top;
 1117    }

 1119    if (!state.first_pass)
 1120       json_value_free_ex (&state.settings, root);
```

Two things are missed, and they compound:

- **Line 1109 is false in pass 2**, so `alloc` is not rewound to `root`; the loop frees only the
  *unconsumed tail* of the chain, from wherever pass 2 had walked to. Every struct pass 2 already
  popped is no longer reachable from it.
- **`json_value_free_ex` descends only through `values[]`** (`json.c:1152`, `:1163`). The open path
  `root → top` has no entries written yet, so the walk never reaches it.

So a pass-2 abort leaks every `json_value` on the open path, plus any payload pass 2 had already
allocated for it. At `[""]` with a budget of 88 the open path is the single string value `v1`:
`v0`'s 8-byte `values` array is allocated (80 + 8 = 88, not over), then `v1`'s 1-byte string buffer
pushes the total to 89 and fails. `v1` is freed by neither branch. — 40 bytes.

Two contributing details, both real but neither sufficient on its own:

- **`used_memory` is never reset between passes.** It is a field on `json_state` (`json.c:129`),
  incremented at `json.c:157`, and the two passes run inside one `for` loop (`json.c:366`), so
  pass 2 inherits pass 1's total against the same budget. The whole document's struct cost is
  charged before the first payload is allocated.
- **The accounting does not roll back on failure.** `json.c:157` adds `size` to `used_memory` and
  *then* compares; a refused allocation is still charged, so the effective budget is lower than
  configured and drifts down with every failure.

## Why the generated harnesses cannot reach it

`json_settings.max_memory` defaults to 0, which `json_alloc` reads as "unlimited"
(`json.c:156`), so `e_alloc_failure` is unreachable. Both generated harnesses
(`ft_json_parse_26fecbbbfb75`, `ft_json_parse_ex_f4934a9a2bdc`) leave it at 0. The multi-path
harness sets `max_memory = 4096` on its fourth call and reaches the path on its first inputs.

This is visible in coverage: the multi-path harness settles at `cov: 685` where both plain
harnesses plateau at `cov: 640`, and the extra edges are the `max_memory` and
`json_enable_comments` branches.

## Evidence

Reproducer: a single `json_parse_ex` call with a `max_memory` budget, built with
`-fsanitize=address` and run under `ASAN_OPTIONS=detect_leaks=1`. Every row below is a *single*
call — no fuzzer, no harness involved — which is what rules out the harness as the source.

| input | bytes | `max_memory` | result |
| --- | --- | --- | --- |
| `[""]` | 4 | 87 | `NULL`, **no leak** — the abort lands in pass 1 and the chain walk is correct |
| `[""]` | 4 | 88 | `NULL`, **40 B leaked in 1 allocation** |
| `[""]` | 4 | 89 | parses successfully, no leak |
| `[0,""]` | 6 | 136 | `NULL`, 40 B leaked in 1 allocation |
| `[0,[0]]` | 7 | 176 | `NULL`, 40 B leaked in 1 allocation |
| LSan artifact | 199 | 4096 | `NULL`, **616 B leaked in 21 allocations** |

The two stacks from the 199-byte case, verbatim:

```
Indirect leak of 520 byte(s) in 13 object(s) allocated from:
    #1 json_alloc  project/json.c:162:11
    #2 new_value   project/json.c:280:34      <- pass-1 json_value structs still on the open path
Indirect leak of 96 byte(s) in 8 object(s) allocated from:
    #1 json_alloc  project/json.c:162:11
    #2 new_value   project/json.c:197:60      <- pass-2 array payloads for those same values
```

The band of budgets that leaks for a given input is `[pass-1 total, pass-1 total + pass-2 payloads)`
— that is, any budget that is exhausted *during the second pass*. Above the band the parse
succeeds; below it the abort lands in pass 1, where the chain walk happens to be correct. So the
defect is not "any OOM" but precisely "the budget runs out after pass 1", which is the normal case
for a `max_memory` cap set to bound a document slightly larger than the cap allows.

Reproduce:

```sh
P=<project>   # benchmarks/json_parser/project
clang -std=c11 -g -O1 -fsanitize=address -I$P one.c $P/json.c -o one -lm
printf '[""]' > poc.json
ASAN_OPTIONS=detect_leaks=1 ./one poc.json 88
```

## Impact

Each aborted parse leaks the open path — bounded by how much of the document pass 2 had built,
which is bounded by the budget itself. A caller that uses `max_memory` as hardening and parses
attacker-supplied documents (the reason the setting exists) leaks on every document that trips the
cap, so repeated requests grow the process without bound. Severity is a property of the caller:
a one-shot CLI parse leaks nothing that matters, a long-running service taking untrusted JSON with
a cap leaks per request.

**Not verified.** No end-to-end DoS was built and no per-request leak figure was measured for a
realistic budget; the scaling claim is the mechanism above, not a measurement beyond the 616 bytes
at `max_memory = 4096`.

## Fix

Rewind `alloc` unconditionally before the chain walk, so pass 2 frees what pass 1 allocated, and let
`json_value_free_ex` handle the tree:

```diff
@@ -1106,8 +1106,7 @@
-    if (state.first_pass)
-       alloc = root;
+    alloc = root;
```

`alloc = root` is correct in both passes: in pass 1 nothing has been popped, and in pass 2 the
chain is still threaded back to `root` through `next_alloc`, so the walk frees every struct —
including the ones pass 2 popped, which is exactly the set that leaks today. The open path's
payload arrays are freed by the `json_value_free_ex` call that already runs on the pass-2 path.

**Verified.** With only this change, all four rows of the evidence table are clean under
`detect_leaks=1` (the same four leak without it), and the parse results are unchanged — the
budgets that succeeded before still succeed.

Worth fixing alongside it, since both make the budget behave unlike what a caller would expect:
reset `state.used_memory` at the top of each pass in the `json.c:366` loop, and roll the increment
back in `json_alloc` when the comparison fails.

## Provenance

Found by `harness_multi.c`, an LLM-authored harness that was hand-corrected before use, on its
first smoke run (497 executions) — it exercises four entry paths in one input: `json_parse`,
`json_parse_ex` with default settings, `json_parse_ex` with `json_enable_comments`, and
`json_parse_ex` with `max_memory = 4096`. Only the fourth reaches the defect. The attribution above
was done with a standalone single-call reproducer written after the fact, so the finding does not
depend on the harness being correct.
