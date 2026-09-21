# Independent generation variance

FT: `ft_mp_parse_787468773c9f`. Status: **complete**.
Requested independent generations: 3; seeds per generation: 3; fixed budget: 20000 executions.
LLM: deepseek-v4-flash; temperature: 0.2.

Each generation starts in a fresh artifact root from the same input catalogs. Rollback attempts within one generation are not separate samples. Coverage is LLVM target-source coverage with sanitizers off.
The reference is a single translation unit; each generated harness's recipe is listed below. These measurements describe this benchmark and do not isolate a method effect from recipe differences.

Reference measurement: complete.

| metric | measured generations | reference mean % | generated mean % | between generation sample variance | within generation sample variance | between CV | within CV |
|---|---:|---:|---:|---:|---:|---:|---:|
| lines | 3/3 | 95.122 | 98.7805 | 0 | 0 | 0 | 0 |
| regions | 3/3 | 92.1053 | 93.1287 | 0.256493 | 0.76948 | 0.00543819 | 0.00941922 |
| branches | 3/3 | 82.3529 | 83.4967 | 0.320373 | 0.961119 | 0.00677889 | 0.0117414 |

Sample variances use n−1. Between generation variance is computed from each complete generation's mean across seeds; within generation variance is the mean of its seed level sample variances. These are descriptive spreads, not a confidence interval or a causal estimate.

## Trial outcomes

| trial | generation | Stage 4 attempts | recipe | measured seeds | harness SHA-256 | reason |
|---:|---|---:|---|---:|---|---|
| 1 | published | 1 | two_tu | 3 | b859ffdc20950734f4adcae9b81a8b6a64abc3c6cb95cc6791607ad0dbe2d1b0 | — |
| 2 | published | 2 | two_tu | 3 | 509e017722d18416d2f59ae6e5a1df1ad0d944298ddaf5b7406315e95b5022e1 | — |
| 3 | published | 1 | two_tu | 3 | a9958499972a36d678fabad4ee104553c99a87055adb74fccd7a1be61fb6f90e | — |

A failed generation or missing coverage measurement stays in the requested denominator. It is never imputed as zero or silently replaced. Identical harness hashes are retained as separate requests and disclosed above; different requests do not guarantee different code.
Three generations support only descriptive spreads for this target and budget. Seed level zero variance means no variation was observed at this budget; it is not three independent confirmations.
