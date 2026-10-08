# json_parse 端到端修复报告

日期：2026-10-03。目标仓库为 `/home/luchitong/work/json-parser`，目标 HEAD 为 `9d50ae5ea2cdeef3b75146c621ec7b26e2e3642f`。本轮使用当前 `v0.2` 本地实现，在不修改目标源码、不扩大 blind 实验、不增加 Agent 工具集合的前提下，完成了 `json_parse` 从真实模型调查到可编译、可运行 harness 的 fresh 全链验证。

## 结论

本轮最终 frozen fingerprint 为 `f34899aa9221087c9a92f3c1989826264591983fcdcac129c4146c81d80d0b41`。真实模型链路 `candidates -> candidate-validate -> semantic-slice -> minimal-ft -> harness-context -> context-generate --build --runtime` 全部返回 0，Context `generation_allowed=true`、`frozen=true`、hard gaps 为 0，12/12 个 mandatory semantic obligation roots 闭合。HarnessPlan 生成成功，代码模型只进行 Plan 到 C/C++ 翻译，生成的 harness 通过编译、ASan/UBSan runtime、21 个额外 JSON/错误输入回放和 2000 次短 libFuzzer 运行。

这证明当前框架已经能在一个已知真实项目开发样例上生成可编译、可运行的 harness。它仍不能证明跨项目泛化、稳定成功率、Candidate recall 或覆盖提升；本次入口是人工指定的公开 API `json.c:1125:json_parse`，数据集角色明确为 `known-project-development-regression`。

## 实验身份

| 项目 | 值 |
| --- | --- |
| 目标仓库 | `/home/luchitong/work/json-parser` |
| 目标 HEAD | `9d50ae5ea2cdeef3b75146c621ec7b26e2e3642f` |
| 目标源码文件 | 57 个，最终 hash 全部匹配，git status 为空 |
| 框架分支 / HEAD | `v0.2` / `59b6afb55e382eec3c62427e3273502455315285` |
| 冻结 fingerprint | `f34899aa9221087c9a92f3c1989826264591983fcdcac129c4146c81d80d0b41` |
| 模型 provider | `openai-compatible` |
| 请求模型 | `ark-code-latest` |
| 实际响应模型 | `deepseek-v4-flash-ga-260731` |
| thinking | disabled |
| 入口 | `json.c:1125:json_parse` |
| 入口选择 | human-selected public API |
| artifact root | `/home/luchitong/work/harness_generation/artifacts/json_parse_closure_20261003T153052Z` |

默认预算未放宽：Validation/Slice 为 6 rounds、24 tools、48k source chars、4096 output；Context 为 24 model calls、64 tools、96k source chars、16 discoveries、depth 2、每 requirement 4 rounds、3 次 completeness pass、1 次 terminal repair、8192 output。

## 为什么这轮能闭合

这轮关键修复不是让模型自由发挥更多，而是把 cleanup 输入的证明边界收窄成一个可验证的 harness 局部事实：如果 CORE 返回 owned pointer，并且源码证明公开 cleanup API 正是消费这个 returned resource，那么 cleanup 参数可以作为 `harness_cleanup_input_binding` 闭合。这个证明只说明 harness 把同一个 owned CORE return 传给公开 cleanup；它不声称库内部所有 heap 字段都被 harness 初始化，也不把任意同类型对象当作可释放对象。

第二个关键修复是跨 predicate 的源码证据复用。之前 cleanup 证明所需 helper 已经被读取和认证，但在从 caller flow 到 ownership/lifecycle 的边界上 depth 被重复加深，导致现有证据不能复用。当前版本在重建可复用 source records 时使用已授权 scope 和 actual caller flow，把 cleanup helper 保留在既有 depth 预算内。

这两处修复让 `json_parse -> json_value_free` 的关系能进入统一的 obligation closure：Graph 与 semantic facts 不再各自持有一套互相孤立的真相，Plan 最终只看 canonical recipes。

## 端到端结果

最终 trial 位于 `/home/luchitong/work/harness_generation/artifacts/json_parse_closure_20261003T153052Z/json_parse/trial.json`。

| 阶段 | 结果 |
| --- | --- |
| Static / candidates | parser-only artifacts，27 个函数，annotations/flows 可为空 |
| Candidate validation | accepted，真实模型响应 4 次 |
| Semantic Slice | `completed_with_unresolved`，CORE 1 个，unresolved 5 个 |
| Minimal FT | `completed_with_unresolved`，CORE 为 `json_parse` |
| Harness Context | complete，2 次模型调用，23 次工具调用，57,219 source chars |
| Semantic Obligation Graph | 25 个节点，12/12 mandatory roots closed，frontier 为空 |
| API Closure | required support 1 个：`json_value_free` |
| HarnessPlan | schema 2，policy `source-grounded-harness-plan-v12`，frozen=true |
| Code generation | 1 次真实模型调用，prompt version `frozen-plan-code-v8` |
| Code validation | `frozen_plan_code_v4`，valid |
| Build | 4 条 clang/clang++ 命令全部返回 0 |
| Runtime | 6/6 固定输入通过，ASan/UBSan enabled |
| Extra runtime | 21/21 JSON、嵌套、错误输入、二进制输入通过 |
| Short fuzz | libFuzzer `-runs=2000` 通过 |

本次全链共有 13 个成功 provider response，0 个 provider error，耗时 159.707 秒。token 统计为 prompt 270,606、completion 12,733、total 283,339。

## Plan 与生成代码

HarnessPlan 位于：

`/home/luchitong/work/harness_generation/artifacts/json_parse_closure_20261003T153052Z/json_parse/context_generations/ft_json_parse_0ae4807a5c9deb61296da49c/plan_3c41660047105fa8f8e6d72a/harness_plan.json`

生成 harness 位于：

`/home/luchitong/work/harness_generation/artifacts/json_parse_closure_20261003T153052Z/json_parse/context_generations/ft_json_parse_0ae4807a5c9deb61296da49c/plan_3c41660047105fa8f8e6d72a/58122935d6cefecb62f1bb21/harness.cpp`

Plan 中的核心 recipe 只有三类：

| 参数 / 资源 | recipe | 含义 |
| --- | --- | --- |
| `json_parse(json, ...)` | `fuzz_bytes` | fuzz bytes 作为显式长度 buffer |
| `json_parse(..., length)` | `fuzz_size` | fuzz size 与 buffer length 绑定 |
| `json_value_free(value)` | `resource_reference` | 精确引用 `json_parse` 返回的 owned resource |

生成代码保留 binary zero，额外分配 `size + 1` 并补终止零，但调用 `json_parse(json_buffer, size)` 时仍传原始 size。返回的 `json_value *` 在 cleanup 区域由 `json_value_free` 释放；空返回值不释放。

## 验证与完整性审计

完成审计保存于：

`/home/luchitong/work/harness_generation/artifacts/json_parse_closure_20261003T153052Z/completion_audit.json`

审计结果：

| 检查项 | 结果 |
| --- | --- |
| 当前生产文件 vs manifest | 160/160 匹配 |
| frozen 生产文件 vs manifest | 160/160 匹配 |
| 目标源码 vs manifest | 57/57 匹配 |
| 目标仓库 git status | 空 |
| 目标 HEAD vs manifest | 匹配 |
| stage exits | 6/6 为 0 |
| Context hard missing | 0 |
| mandatory roots | 12/12 closed |
| Plan frozen | true |
| code origin | model_translation |
| build/runtime | passed / passed |
| extra runtime / fuzz | passed / passed |
| 凭证字面量扫描 | 0 hits |

完整回归在当前工作区通过：`666 passed in 354.59s (0:05:54)`。这次回归覆盖了 cleanup input scope 负例、跨 predicate 源码复用、owned return 绑定、semantic closure、callback 边界、proof reliability、source detail tools 和既有 pipeline tests。

## 同日失败轨迹

下表按 frozen 版本分开记录，不合并成成功率：

| artifact | fingerprint | 终态 | 响应 / tokens | 主要阻塞 |
| --- | --- | --- | ---: | --- |
| `json_parse_native_20261003T050716Z` | `3d7cdf9c...` | semantic-slice failed | 8 / 97,727 | Slice 输出未过终态校验 |
| `json_parse_repair_20261003T062759Z` | `0600fd86...` | harness-context failed | 19 / 571,230 | cleanup 与 support role conflict，6/8 roots closed |
| `json_parse_closure_20261003T071607Z` | `f3661cb1...` | semantic-slice failed | 8 / 89,366 | Slice terminal schema/choice 问题 |
| `json_parse_closure_20261003T072825Z` | `4a20dc2a...` | harness-context failed | 15 / 390,231 | source-signed cleanup 证据不足，0/7 roots closed |
| `json_parse_closure_20261003T074353Z` | `93b2d805...` | harness-context failed | 15 / 335,865 | cleanup input scope 未被义务图接受，9/14 roots closed |
| `json_parse_closure_20261003T153052Z` | `f34899aa...` | passed | 13 / 283,339 | 最终修复后全链通过 |

这些失败证明本轮成功不是简单重跑得到的偶然状态，而是具体边界修复后的新 frozen 版本结果。但最终版本只有一次 fresh 全链成功，不能据此估计方差或稳定成功率。

## 仍然不足

1. 这不是跨项目泛化证据。目标是已经多轮用于开发的真实项目，入口为人工指定公开 API；没有评估 Candidate recall。
2. 这不是稳定性 cohort。最终 fingerprint 只做了一次 fresh 全链，额外 runtime 和短 fuzz 验证的是同一个生成 harness 的执行安全性。
3. `json_parse` 是 direct explicit-length parser。callback、stream abstraction、RAII/C++、多实例 shared context、重复 feed/CORE、复杂 out parameter、非零 aggregate field init 还需要独立样例验证。
4. cleanup input scope 证明是 harness 局部绑定证明，不是目标库内部 tree invariant 的形式化证明。
5. runtime 固定输入和 2000 次短 fuzz 只能说明当前 harness 在这些执行路径上通过 sanitizer；没有目标限定 coverage、reference oracle 或长期 fuzz 结论。
6. provider 400/timeout 问题在本次最终 trial 中没有出现；这不能证明供应商协议问题永久解决。

## 下一步建议

下一步不应启动 blind cohort。更合适的是固定当前 fingerprint，做 5 到 10 次同目标 `json_parse` 重复 fresh run，确认 Slice、Context、Plan、build/runtime 是否稳定，并记录 hard gaps、model/tool calls、tokens 和 provider events。随后再选择 3 到 5 个结构不同的已知开发样例，分别覆盖 callback construction source、shared context lifecycle、owned-return cleanup、out-parameter creator 和 stream/file abstraction。只有这些小规模重复结果稳定后，才值得重新设计跨项目泛化实验。
