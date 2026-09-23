# markdown-wasm: `unsigned` fold index breaks link-label matching

**Status:** confirmed, unpatched upstream · 2026-09-23
**Component:** `rsms/markdown-wasm` 1.2.0 — vendored `src/md4c.c`
**Upstream:** commit `0d99d1151ff4d929a8ac8f3a191bfec54a10a869` (2021-07-06), still `master` HEAD today
**Not affected:** md4c itself — no release 0.3.2–0.5.0, nor `master`, declares this variable `unsigned`

## Summary

`md_get_unicode_fold_info()` searches three case-folding tables and stores the result of the
binary search in a local declared `unsigned`. That makes the guard two lines later
(`if (index >= 0)`) unconditionally true, including for the `-1` the search returns when the
codepoint is in none of the tables. The pointer arithmetic that follows therefore runs on
`0xFFFFFFFF`.

The fork took the signedness from a warning-silencing pass: `-Wsign-compare` fires at
`md4c.c:1599`/`:1604` because `a_fi_off` is `OFF` (`typedef unsigned MD_OFFSET`) while
`n_codepoints` was `int`. Making the field unsigned turned `index * n_codepoints` mixed-sign, so
the local was made unsigned too — and the guard silently died.

There are three consequences, and only the first is the one a sanitizer reports.

| | platform | effect |
| --- | --- | --- |
| A | native, 64-bit | out-of-bounds read at `+16 GB`, SEGV |
| B | wasm32 | bounded out-of-bounds read (~12 bytes), no trap |
| C | wasm32, shipped npm build | link-label confusion — 354 codepoints alias other labels |

## Root cause

```c
 698    for(i = 0; i < (int) SIZEOF_ARRAY(FOLD_MAP_LIST); i++) {
 699        unsigned index;                          /* md4c 0.4.4: int index */
 700
 701        index = md_unicode_bsearch__(codepoint, FOLD_MAP_LIST[i].map, FOLD_MAP_LIST[i].map_size);
 702        if(index >= 0) {                         /* dead: true for every value */
 703            /* Found the mapping. */
 704            unsigned n_codepoints = FOLD_MAP_LIST[i].n_codepoints;
 705            const unsigned* map = FOLD_MAP_LIST[i].map;
 706            const unsigned* codepoints = FOLD_MAP_LIST[i].data + (index * n_codepoints);
 707
 708            memcpy(info->codepoints, codepoints, sizeof(unsigned) * n_codepoints);
 709            info->n_codepoints = n_codepoints;
 710
 711            if(FOLD_MAP_LIST[i].map[index] != codepoint) {   /* second wild read */
```

`md_unicode_bsearch__()` returns `-1` at `md4c.c:510`. The whole signedness pass, against md4c
0.4.4 (185 changed lines in total):

```diff
@@ struct MD_UNICODE_FOLD_INFO_tag @@
-    int n_codepoints;
+    unsigned n_codepoints;

@@ FOLD_MAP_LIST[] @@
-            int n_codepoints;
+            unsigned n_codepoints;

@@ md_get_unicode_fold_info @@
-            int index;
+            unsigned index;                 <- the defect

@@ md_get_unicode_fold_info @@
-                int n_codepoints = FOLD_MAP_LIST[i].n_codepoints;
+                unsigned n_codepoints = FOLD_MAP_LIST[i].n_codepoints;
```

A project-wide scan for the same shape — an `unsigned` local compared against zero — finds only
one other candidate, `md4c.c:222`, whose comparison sits behind an `MD_ASSERT` and is harmless.

## Reachability

Any codepoint above `0x7f` outside `FOLD_MAP_1` takes the path; a link reference definition whose
label holds one is enough. Two minimal inputs, both of which crash a 64-bit native build:

```
5b e4 b8 ad 5d 3a 20 2f 78          ["[中]: /x"]        valid UTF-8, 8 bytes
5b ac ac ac ac 5d 3a 78             ["[\xAC\xAC\xAC\xAC]:x"]   malformed UTF-8, 8 bytes
```

In the second, `md_decode_utf8__` returns `(unsigned) str[0]` for a byte that is neither a lead
byte nor a valid continuation, so `0xAC` sign-extends to `0xFFFFFFAC`.

Because the branch returns as soon as it is taken (`:723`), the `FOLD_MAP_2` and `FOLD_MAP_3`
iterations never run: every multi-codepoint case fold is dead regardless of platform. `[ß]` and
`[ss]`, `[ẞ]` and `[ss]`, `[İ]` and `[i̇]`, `[ﬁ]` and `[fi]`, `[ﬅ]` and `[st]` no longer match.

## What the wild index reads

`index` is always exactly `0xFFFFFFFF` and `n_codepoints` is always 1, 2 or 3 from the static
table, so the two addresses are fixed: `data - 4` and `map - 4`, the word immediately before each
array. Which word that is comes from the linker's data layout, so the corrupted fold value is
deterministic per build and independent of the input.

Read out of the live linear memory of the shipped `dist/markdown.wasm`:

| address | object | word read |
| --- | --- | --- |
| `0x0D1C` | `WHITESPACE_MAP[7]` = `S(0x3000)` (`md4c.c:521`) | `0x00003000` — this is `map - 4` |
| `0x116C` | alignment padding between two data segments | `0x00000000` — this is `data - 4` |
| `0x0D20`–`0x1163` | `FOLD_MAP_1` (273 words) | — |
| `0x1170`–`0x15B3` | `FOLD_MAP_1_DATA` (273 words) | — |

`WHITESPACE_MAP` ends exactly where `FOLD_MAP_1` begins, which is why the read lands on the
whitespace table's last entry. Both words were stable across five different workloads.
Substituting them into `md4c.c:719` gives the whole behaviour of the shipped artifact:

```
folded(c) = c - 0x3000        for every codepoint above 0x7f outside FOLD_MAP_1
```

## Evidence

Each row run against the byte-identical npm artifact and against upstream md4c 0.4.4 compiled
natively with the same renderer, which is the behavioural reference.

| input | md4c 0.4.4 | shipped artifact | kind |
| --- | --- | --- | --- |
| `[A]: /url` + `[a]` | link | link | correct |
| `[中]: /url` + `[中]` | link | link | correct |
| `[ä]: /url` + `[ä]` | link | link | correct |
| `[Ä]: /url` + `[ä]` | link | literal `[ä]` | false negative |
| `[Α]` + `[α]`, `[А]` + `[а]` | link | literal | false negative |
| `[ß]` + `[ss]`, `[ﬁ]` + `[fi]` | link | literal | false negative |
| `[A]: /url` + `[ち]` | literal `[ち]` | **link to `/url`** | false positive |
| `[b]: /url` + `[ぢ]` | literal | **link** | false positive |
| `[À]: /url` + `[ム]` | literal | **link** | false positive |
| `[Α]: /url` + `[㎱]` | literal | **link** | false positive |
| `[А]: /url` + `[㐰]` | literal | **link** | false positive |
| `[x y]: /url` + `[x〠y]` | literal | **link** | false positive |

354 codepoints alias labels they have nothing to do with, 37 of them hijacking an ASCII letter or
digit:

| colliding codepoint | folds to | resolves a definition labelled |
| --- | --- | --- |
| `U+3030` 〰 … `U+3039` 〹 | `0x30`…`0x39` | `0`…`9` |
| `U+3061` ち … `U+307A` ぺ | `0x61`…`0x7a` | `a`…`z` / `A`…`Z` |
| `U+3020` 〠 | `0x20` | a space |
| `U+30E0` ム | `0x00E0` | `À` |
| `U+33B1` ㎱ | `0x03B1` | `Α` |
| `U+3430` 㐰 | `0x0430` | `А` |

The remaining 317 collide with Latin Extended (76), Greek and Greek Extended (63), Cyrillic (17),
Armenian, Georgian, Glagolitic, Halfwidth forms and CJK compatibility ideographs — each one a
codepoint at `v + 0x3000` for a legitimate fold value `v`.

The effect is not "non-ASCII matches anything": `[a]` with `[ぢ]`, `[z]` with `[ほ]`, `[À]` with
`[メ]` and `[Α]` with `[㎲]` all stay literal, exactly as `c - 0x3000` predicts.

## What survives a rebuild

`0x3000` belongs to this binary. A future build may place different objects around the arrays, so
the alias table should be recomputed for any artifact you care about. The rest does not depend on
layout:

- Multi-codepoint folding is dead in **every** build — the branch returns at the first iteration
  whatever the value read is. Shown on a 32-bit build whose two words are both zero, so its fold
  function is the identity: `[ß]`/`[ss]` still fails there.
- The out-of-bounds read and the 64-bit SEGV are present in every build.
- Any non-ASCII label whose fold is not itself gets a corrupted value whenever the offset is
  non-zero.
- With a zero offset — the 32-bit build measured here — the corruption is the identity function
  and single-codepoint cases happen to behave. A rebuild could land there.

A 32-bit native build is a proxy for the pointer-width question only, not for the values.

## Fix

```diff
--- a/src/md4c.c
+++ b/src/md4c.c
@@ -696,7 +696,7 @@ static void md_get_unicode_fold_info(unsigned codepoint, MD_UNICODE_FOLD_INFO* in
     for(i = 0; i < (int) SIZEOF_ARRAY(FOLD_MAP_LIST); i++) {
-            unsigned index;
+            int index;
```

Restoring the type the guard depends on removes all three consequences at once; verified by
rebuilding the same sources with only this change. Two notes for whoever applies it. The warning
that provoked the original change is real, so it will come back — silence it where it belongs:

```diff
-        if(a_fi_off >= a_fi.n_codepoints) {
+        if(a_fi_off >= (OFF) a_fi.n_codepoints) {
```

and the field should go back to `int` as well. Restoring `index` alone is sufficient, but leaving
`n_codepoints` unsigned keeps `index * n_codepoints` mixed-sign, which is the shape that invited
the change in the first place.

`dist/` must be rebuilt from the fix for the published artifact to change.

## Reproduction

```sh
# shipped artifact — node, no build step
npm pack markdown-wasm@1.2.0 && tar xzf markdown-wasm-1.2.0.tgz
node -e 'const m = require("./package/dist/markdown.node.js");
         console.log(m.parse(Buffer.from("[A]: /url\n\n[ち]\n", "utf8")))'
# expected (md4c 0.4.4): <p>[ち]</p>
# observed:              <p><a href="/url">ち</a></p>

# native 64-bit — SEGV at md4c.c:708
clang -std=gnu11 -DMD4C_USE_UTF8 -Dexport= \
  -fsanitize=fuzzer,address,undefined -g -O1 -I <project> \
  harnesses/md_parse.c <project>/md4c.c -o /tmp/fold_fuzz
printf '[\xe4\xb8\xad]: /url\n' > /tmp/poc.md
/tmp/fold_fuzz /tmp/poc.md
# ==ERROR: AddressSanitizer: SEGV ... #0 md_get_unicode_fold_info md4c.c:708

# control — upstream md4c 0.4.4 renders every row of the evidence table correctly
curl -O https://raw.githubusercontent.com/mity/md4c/release-0.4.4/src/md4c.c
```

## Provenance and caveats

The analysed file is `src/md4c.c` at blob `52884ebcdf770682672ab778a6d9868de759bdd3`, byte-for-byte
the upstream file at the pinned commit. `wasmc.js` compiles release with `-DMD4C_USE_UTF8`, the
same path the native builds here take. The npm tarball for 1.2.0 is byte-identical to the committed
`dist/` in both `markdown.wasm` (`0e3e932f…`) and `markdown.node.js` (`56aab5e1…`), so installed
copies are affected, not just the repository.

**Verified.** Every behaviour in the evidence table. The two stray words, read from live linear
memory and stable across five workloads. The one-token fix restoring all three impact classes.

**Not verified.** Impact in any specific application. The fail-open matching is a real deviation
from CommonMark and severe in principle for a caller that keys trust on reference definitions, but
no end-to-end exploit against a real consumer was built, and severity beyond "wrong link target"
is a property of the caller, not of the library. The `SAFE_HEAP` claim is a reading of what that
check does — bounds against linear memory — not a test of a debug build.

**Disclosure.** Unpatched in current `master` and in the 1.2.0 npm release; not a bug in md4c
upstream, whose own users are unaffected. Route: issue or private report to `rsms/markdown-wasm`,
noting that `dist/` must be rebuilt from the fix.

---

Found while smoke-fuzzing a generated `md_parse` harness in `harness_generation`
(`benchmarks/markdown_wasm`) — 47 227 execs, SEGV at `md4c.c:708`, reproduced with the handwritten
reference harness in `harnesses/`.
