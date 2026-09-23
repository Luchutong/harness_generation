# markdown-wasm benchmark

The `project/` directory is a byte-for-byte copy of the C and header files in
[`rsms/markdown-wasm`](https://github.com/rsms/markdown-wasm) at the commit
recorded in `manifest.json`. The JavaScript and WebAssembly build are outside
this native C harness test. `target_build.json` mirrors the C source list in
upstream `wasmc.js`; it excludes optional `fmt_json.c` and uses `-Dexport=` to
make the WebAssembly export annotation acceptable to native Clang.

Two real fuzz targets are useful here:

* `md_parse` takes Markdown bytes and an `MD_PARSER` callback table. Its
  `userdata` is opaque to the parser; a caller's `WBuf` lifecycle must not
  become part of this target's FT.
* `parseUTF8` is the exported wrapper that renders HTML into a shared buffer.
  Its output pointer is borrowed until the next call, so the harness must not
  free it. The optional JavaScript code-block callback is left null.

Reference harnesses are in `harnesses/`. They are handwritten or adapted for
this native benchmark and are not generator output. To reproduce Phase 1 and
FT selection from the repository root:

```sh
.venv/bin/python -m sfg_builder \
  --project benchmarks/markdown_wasm/project \
  --output /tmp/markdown_wasm_ft --semantic-analyzer mock
.venv/bin/python -m harness_generation triplets \
  --artifacts /tmp/markdown_wasm_ft
.venv/bin/python -m harness_generation triplets rank \
  --artifacts /tmp/markdown_wasm_ft --max-ft 5
```

Native sanitizer build and short smoke run:

```sh
clang -std=gnu11 -DMD4C_USE_UTF8 -fsanitize=fuzzer,address,undefined -g -O1 \
  -Ibenchmarks/markdown_wasm/project \
  benchmarks/markdown_wasm/harnesses/md_parse.c \
  benchmarks/markdown_wasm/project/md4c.c -o /tmp/markdown_md_parse_fuzzer
/tmp/markdown_md_parse_fuzzer -runs=100 benchmarks/markdown_wasm/corpus

clang -std=gnu11 -DMD4C_USE_UTF8 -Dexport= \
  -fsanitize=fuzzer,address,undefined -g -O1 \
  -Ibenchmarks/markdown_wasm/project \
  benchmarks/markdown_wasm/harnesses/parse_utf8.c \
  benchmarks/markdown_wasm/project/{md.c,md4c.c,fmt_html.c,wbuf.c,wlib.c} \
  -o /tmp/markdown_parse_utf8_fuzzer
/tmp/markdown_parse_utf8_fuzzer -runs=100 benchmarks/markdown_wasm/corpus
```

The reference harnesses demonstrate that the two native entry points are
buildable. FT selection and generation need to be judged separately: the
ranker favors some large internal helper FTs over `md_parse` and `parseUTF8`,
and `parseUTF8` has no struct edge despite a valid byte stream. Both entry
points therefore have to be named explicitly rather than selected:

```sh
# md_parse ranks 7/22 and parseUTF8 ranks 17/22, while --max-ft 5 stops at the
# five helper FTs above them, so each run is pinned with --ft.
set -a && . ./.env && set +a
.venv/bin/python -m harness_generation run --artifacts /tmp/mdw_run_mdparse \
  --ft ft_md_parse_845d811ea6d4 --build --smoke-fuzz --real-llm \
  --target-build benchmarks/markdown_wasm/target_build.json
.venv/bin/python -m harness_generation run --artifacts /tmp/mdw_run_parseutf8 \
  --ft ft_parseutf8_3960c7b3e25c --build --smoke-fuzz --real-llm \
  --target-build benchmarks/markdown_wasm/target_build.json
```

## Generator results

Both runs reach `success: true` with every gate passed (compiler, linker,
intermediate, runtime) and `promotion.json` `status: stable_promoted`. Each
smoke run is `passed_with_limitations` for the same reason: it found a crash in
the target, which is preserved as `crash_classification: potential_target_crash`
instead of being charged to the harness.

| FT | attempts | rollbacks | execs (60s) | edges | finding |
| --- | --- | --- | --- | --- | --- |
| `ft_md_parse_845d811ea6d4` | 1 | 0 | 47227 | 4490 | `md4c.c:708` SEGV in `md_get_unicode_fold_info` |
| `ft_parseutf8_3960c7b3e25c` | 4 | 3 | 35585 | 4387 | `wbuf.c:146` misaligned `u32` load and store in `fmtu32` |

Both findings are reproducible with the reference harnesses in `harnesses/`, so
they are target defects rather than artifacts of the generated harness.

### `md4c.c` fold lookup

The defect is one token. `md_get_unicode_fold_info` declares the fold-map search
result as `unsigned index` (`md4c.c:699`) and then tests `if(index >= 0)`
(`md4c.c:702`), which is false for every value. `md_unicode_bsearch__` returns
`-1` for a codepoint that no fold map covers, so `index` becomes `0xffffffff` and
`FOLD_MAP_LIST[i].data + (index * n_codepoints)` is a wild pointer that the
`memcpy` at `md4c.c:708` dereferences. Ordinary input reaches it: any link
reference definition whose label holds a codepoint outside the fold maps -- CJK,
kana, emoji -- and so does eight bytes of malformed UTF-8,
`5b ac ac ac ac 5d 3a 78` (`[\xac\xac\xac\xac]:x`), where `md_decode_utf8__`
returns `(unsigned) str[0]` and sign-extends `0xac` to `0xffffffac`.

Because the branch returns as soon as it is taken, `FOLD_MAP_2` and `FOLD_MAP_3`
are never consulted either, so every multi-codepoint case fold is dead as well:
`[ß]`/`[ss]`, `[ẞ]`/`[ss]`, `[İ]`/`[i̇]`, `[ﬁ]`/`[fi]` and `[ﬅ]`/`[st]` stop
matching.

#### What the wild index reads

`index` is always exactly `0xffffffff`, and `n_codepoints` is always 1, 2 or 3
from the static table, so the two addresses are `data - 4` and `map - 4`: the
words immediately *before* the arrays. Which words those are is fixed by the
linker rather than by the input, so the corrupted fold value is deterministic per
build. On x86-64 the offset is `+16 GB`, because the 32-bit unsigned product is
zero-extended to `ptrdiff_t`, and the process dies on a SEGV.

In the shipped `dist/markdown.wasm` both words can be read back out of the live
linear memory: `map - 4` lands on the last entry of `WHITESPACE_MAP`,
`S(0x3000)` (`md4c.c:521`), and `data - 4` lands in the twelve bytes of alignment
padding between two data segments, so zero. Both are stable across workloads,
which gives

    folded(c) = c - 0x3000     for every codepoint outside FOLD_MAP_1 above 0x7f

and makes the shipped artifact's label matching wrong in both directions, with no
sanitizer and no crash involved:

| case | upstream md4c 0.4.4 | shipped `markdown.wasm` |
| --- | --- | --- |
| `[Ä]: /url` + `[ä]` | link | literal `[ä]` |
| `[Α]` + `[α]`, `[А]` + `[а]` | link | literal |
| `[ß]`/`[ss]`, `[ﬁ]`/`[fi]` | link | literal |
| `[中]` + `[中]`, `[ä]` + `[ä]` | link | link |
| `[A]: /url` + `[ち]` | literal `[ち]` | **link to `/url`** |

The first three rows are false negatives and the last is a false positive: 354
codepoints alias labels they have nothing to do with, `U+3061`–`U+307A`
(ちぢっつづてでとどなにぬねのはばぱひびぴふぶぷへべぺ) aliasing `a`–`z`,
`U+3030`–`U+3039` aliasing `0`–`9`, `U+30E0` aliasing `À`, and `U+3020` acting
as a space. Fail-open label matching is the dangerous direction for anything that
keys trust on reference definitions, and the 26 kana are ordinary Japanese
characters, so this also mislinks ordinary Japanese documents. A label identical
to itself, `[ä]` + `[ä]`, still works, because both sides take the same corrupted
path.

The `-m32` native build does not show any of this: there `map - 4` and `data - 4`
are both zero, so `folded(c) = c` and the corruption is the identity function.
A 32-bit native build is therefore a proxy for the pointer-width question only,
not for the values.

`project/md4c.c` is byte-for-byte the upstream file at the pinned commit
(`git hash-object` gives the upstream blob `52884ebc…`, and that commit is
current `master`), so this is not an artifact of the benchmark. It is also not
inherited from md4c: no release from 0.3.2 through 0.5.0, nor `master`,
declares that variable `unsigned`. The fork introduced it and has carried it
since 2021.

### `wbuf.c` short-string copy

`fmtu32` copies a short numeric string through `u32*` at an address that is not
4-byte aligned, so the load and store at `wbuf.c:146` are undefined behaviour.
This one is notional rather than exploitable: x86-64 and WebAssembly both
service unaligned accesses, so it is only fatal because this benchmark runs
UBSan with the default halt-on-error. Under an AddressSanitizer-only build the
same input passes.

Three consequences for how the smoke gate is configured. UBSan findings are
counted as `potential_target_crash` exactly like memory errors, which will
overstate severity for any target whose shipping platform tolerates the UB; a
crash that only reproduces with 64-bit pointers can be invisible in the artifact
the project actually ships, which is what happened to the `md4c.c` SEGV; and the
gate can report only the *crash* face of a defect whose more serious face is
silent. Here the SEGV was one line of a finding whose wasm-visible half is the
label confusion above, which no sanitizer would have flagged in the shipped
build -- a differential test against the reference implementation is what
exposes that class. All of this was cheap to separate because the reference
harnesses made attribution immediate.

The three rollbacks on `parseUTF8` are all the same validator rejection: the
harness passes the optional code-block callback through a local variable that
holds either `NULL` or a matching function, and the callback check requires the
argument itself to be a null or a function. The retry feedback converged on
attempt 4 to `(void *)harness_onCodeBlock`. That cast is needed because the
portable ABI declaration spells the `JSTextFilterFun` parameter as `void *`,
since `common.h` cannot be included from C++. Keeping the typedef name in the
declaration and pasting it from `project_context.callback_typedefs` would let
the compiler check the signature instead of the Python-side check doing it.
