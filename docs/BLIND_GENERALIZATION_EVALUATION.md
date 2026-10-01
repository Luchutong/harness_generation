# Blind Generalization Evaluation

> 2026-09-29 服务恢复复测已按用户要求暂停：完成 52/240、启动后中断 4、未启动 184；Slice 45/52、Context complete 0/52，Plan/code/compile/runtime 未执行。复测结果独立保存在[暂停收集报告](BLIND_GENERALIZATION_RETEST.md)。下文仅为原始 V2 的完整 240 次结果，两轮不合并。

本轮使用固定语义实现，以新的 API semantic patterns 和实测前选定的真实项目评价泛化。旧五类 fixture 仅是 Development / Regression Set，不进入盲测分母。本实验显式指定 target anchor，属于 **semantic pipeline evaluation**，不评价 project-level Candidate recall。

当前记录 **240/240** 个 native trials；状态：**completed, frozen**。没有 paired replay、失败后修代码、追加预算或挑选最佳一次。


**正式 cohort：240 个 fresh native trials。** Context complete 0/240，runtime success 0/240。以下结果使用原始 native 记录，另以独立 observational audit 恢复 supervisor 判读异常行的已保存阶段/成本；这些行的语义仍为 unverified。没有新增模型调用或重跑。

本轮没有建立新的端到端泛化证据：**Slice success 127/240，Context complete 0/240，Plan/code/compile/runtime 均未执行**。142 次试验取得模型响应，98 次没有响应；104 次受 HTTP 429 影响，另有 terminal-repair HTTP 400。每 case/config 的 5 次是 fresh attempts，未全部获得 5 次完整语义轨迹，因此不能据此判定跨模式稳定性或 A/B/C 的因果增益。

所有失败仍计入正式分母；在 86 个无 provider-error trial 中，73 个进入 Context，也全部被 Gate 拦截。当前可观察到的是局部 identity、cleanup、NUL 与 callback ABI/registration 事实复用，不能将其当作完整新 API pattern 的成功。confirmed false_complete 事件为 0，但没有 Gate complete 样本，条件错误完成率为 N/A。

## 1. Frozen implementation identity

- git commit：`11c27c084a0b96c4c9ca016721b7ddb8d7536d5f`，branch `v0.2`，dirty files 52；本地未提交代码属于冻结身份。
- production fingerprint：`d2b183cb70503604b98e7024790f93f4829e513a9005fed7f26a60a0583988f9`。
- 135 个生产 Python 源文件和 root runtime dependencies 有摘要；原始源码和 tracked patch 归档于 `freeze/`。
- requested model：`ark-code-latest`；provider `openai-compatible`，thinking `disabled`。
- served models：deepseek-v4-flash-ga-260731。
- 开始时间：`2026-09-28T18:11:44.656966+00:00`；结束时间：`2026-09-28T19:50:33.554983+00:00`。
- production/evaluation/benchmarks unchanged：`True/True/True`。

| Component | Frozen version |
| --- | --- |
| semantic_discovery.models | `SCHEMA_VERSION=1`, `POLICY_VERSION=recall-first-entry-validation-v3` |
| semantic_slicing.models | `SLICE_POLICY_VERSION=recall-first-semantic-slice-v1` |
| minimal_ft.models | `SCHEMA_VERSION=1`, `POLICY_VERSION=semantic-slice-minimal-ft-v1` |
| harness_context.models | `POLICY_VERSION=ft-guided-harness-context-v1`, `REQUIREMENT_VERSION=harness-requirements-v3`, `PROMPT_VERSION=ft-requirement-agent-v5`, `TOOL_VERSION=ft-scoped-repository-v3`, `SCHEMA_VERSION=1` |
| harness_context.construction | `VERSION=verified-construction-v2` |
| harness_context.resource_identity | `VERSION=resource-identity-v1` |
| harness_context.input_contracts | `VERSION=input-representation-v1` |
| harness_context.ordering | `VERSION=provenance-ordering-v1` |
| context_generation.builder | `PLAN_POLICY=frozen-context-harness-plan-v5` |
| context_generation.stage4 | `PROMPT_VERSION=frozen-plan-code-v5` |
| context_generation.validation | `CODE_VALIDATOR_VERSION=frozen_plan_code_v2` |
| context_generation.build | `BUILD_POLICY_VERSION=frozen_context_build_v3` |

## 2. Development set

direct buffer、NUL string、shared context、owned return、callback 只用于 unit/regression/negative tests 与 implementation validation。此前 25-run 和 paired cohort 均为开发数据，已在对应 runner、报告中标记。它们不证明跨项目泛化。

## 3. Blind synthetic set

十二种新结构维度：creator with arguments、out-parameter initialization、malloc/memset/helper initialization、custom allocator、refcount、opaque public context、setter callback registration、nested callback table、callback pull input、multiple feeds、simultaneous same-type resources、memory stream。

每个 case 的源文件仅在 preregistration benchmark directory 下的 `synthetic/<id>/source/`，expected contract 位于同级 `ground_truth.json`。独立 reference harness 在 source 外，用于验证样例自身可执行，未向 Agent 提供。它们不是旧 fixture 改名，也不用于新增生产规则。

| Blind model | Explicit target | New semantic dimension |
| --- | --- | --- |
| `configured_decoder` | `bx_decode` | creator args + output status + private configuration |
| `output_handle` | `oh_ingest` | out-parameter + failure-cleared output + capacity |
| `helper_allocated` | `ha_finish` | helper malloc + helper initialization + copied feed |
| `saved_allocator` | `sa_parse` | custom allocator copied into resource + callback release |
| `aliased_refcount` | `ar_decode` | owned returned reference aliases input object + double unref |
| `private_session` | `ps_decode` | opaque layout + creator name argument + internal state |
| `registration_object` | `ro_parse` | setter takes registration object + private parser state |
| `three_level_callbacks` | `tc_decode` | three nested layout levels + void notification callback |
| `signed_pull_reader` | `sr_parse` | signed read result + retained callback context + EOF/error |
| `three_feed_transaction` | `tf_commit` | three required state transitions + independently chunked input |
| `paired_snapshots` | `sp_compare` | two same-type instances + different creator arguments + non-alias |
| `out_memory_stream` | `ms_parse` | out-parameter stream + separate memory binding + pull parser |

16/16 独立 reference harness 在模型调用前通过 C 编译及 0–256 字节长度的 ASan/UBSan replay；16/16 build adapters 又通过实际 TargetBuildConfig loader、C target + C++ harness link 与六个固定输入检查。两类预检均为 reference-only、零模型调用，不进入 native 成功率，也不证明 coverage。

## 4. Blind real-project set

在 production freeze 后、native run 前选定 target APIs。源码为原始库实现和 header slice；统一排除 examples、tests 和上游 fuzzer，选择不基于框架成功。此范围限制不能当作全仓库入口发现。

| Target | Upstream / commit | Language / build | Model / selection rationale |
| --- | --- | --- | --- |
| `toml_parse` | [tomlc99](https://github.com/cktan/tomlc99/tree/29076dfd095bbbbd50a3c1b2760d29f4b83e74ac) / `29076dfd095bbbbd50a3c1b2760d29f4b83e74ac` | C / Make / standalone toml.c | NUL string to owned TOML table; selected before V2 native results, not by framework success |
| `XML_Parse` | [Expat](https://github.com/libexpat/libexpat/tree/13c5f63a7f1c52c2feee3b16a1134d4fb68e9ea0) / `13c5f63a7f1c52c2feee3b16a1134d4fb68e9ea0` | C / CMake | Opaque parser handle plus incremental feed and final flag |
| `csv_parse` | [libcsv](https://github.com/rgamble/libcsv/tree/b1d5212831842ee5869d99bc208a21837e4037d5) / `b1d5212831842ee5869d99bc208a21837e4037d5` | C / Autotools / standalone libcsv.c | Caller state init plus synchronous field/row callback ABI |
| `mpack_tree_parse` | [MPack](https://github.com/ludocode/mpack/tree/c9d1820ecfdbc3954c60a218492251e457cc1f86) / `c9d1820ecfdbc3954c60a218492251e457cc1f86` | C / Make / standalone src/mpack sources | Tree state accepts memory source or stream callback, owns tree storage; input via initialization |

一个 API 可以覆盖多个模型类别；项目数与入口数分别记录。构建系统及原始 source hashes 位于 real selection/manifest；构建布局准备在任何 native call 前完成，没有修改目标库算法。

## 5. Ground truth and semantic adjudication

`ground_truth.schema.json` 与人工独立 contract annotation 包含 CORE、required support、resource origin/consumers/cleanup、input binding、ownership、callback、ordering、invocation multiplicity 和必要约束。Pipeline worker 不导入 evaluator 或 fixtures；仅得到 source/、target API 与纯 build options。Agent 工具只能索引 trial project；注释目录不在可读取范围。

Supervisor 在 worker 退出后才加载 truth。CORE/support precision/recall 按预注册 API sets 计算，资源比较明确的 origin 与消费身份，生命周期检查明确 creator/output 和 cleanup，ownership 检查返回/参数和 release，callback 检查精确 field/registration/ABI，ordering 检查 hard-edge reachability，multiplicity 检查独立预期调用次数。

这些是必要契约检查，不是任意 C/C++ 语义的形式化证明。未产出契约为 unverified；pull reader/custom allocator 行为不能只由 ABI 判断，仍需 code audit。Runtime 通过也不会把 unknown 自动改成 correct。

自动 `false_complete` 为 Gate complete 且 checker 判断必要-contract mismatch；最终还须独立确认其不是合法替代构造路线。单纯 compile/static failure 不自动证明 Gate semantic unsoundness；另列 complete_but_invalid、unverified dimensions、sanitizer failures。未检出的错误不等于不存在；确认后的人工 audit 应作为独立追加结果，不能覆盖原始 trial。

## 6. Budgets and native design

每 case / configuration 注册五个独立 trials，fresh source copy 和 artifact root；Candidate、Slice、FT、Context、Plan、code 按上游成功依次运行，失败后停止。没有 resume。A/B/C 不是同证据重投影。schedule 固定 seed 20260929，仅用于作业交错，不是模型随机 seed。Agent temperature/provider seed 未指定，code temperature 0.2，最多 8192 output tokens；四种 library adapters 只有原始 build flags/header paths，没有语义适配。

```json
{
  "validation": {
    "max_rounds": 6,
    "max_tool_calls": 24,
    "max_source_chars": 48000,
    "max_references_per_query": 10,
    "max_callers": 10,
    "max_callees": 10,
    "max_lines_per_read": 80,
    "max_chars_per_record": 12000
  },
  "context": {
    "max_rounds_per_requirement": 4,
    "max_total_model_calls": 24,
    "max_tool_calls": 64,
    "max_discovered_functions": 16,
    "max_dependency_depth": 2,
    "max_source_chars": 96000,
    "max_completeness_rounds": 3,
    "max_references_per_query": 6,
    "max_lines_per_read": 80,
    "max_chars_per_record": 12000,
    "max_terminal_repairs": 1
  }
}
```

所有类别、A/B/C 使用相同阶段 ceiling。Terminal schema repair 是冻结实现既有行为，非失败后外部 retry。实际调用/tokens 可不同；并发数量在 preregistration 中固定，不改变每个 trial 预算。

记录中 Candidate、Slice、Context 的最大 model calls 分别为 6、6、24；源码读取未超过 48k、48k、96k chars。Candidate/Slice 输出上限为 4096 tokens，Context/code 为 8192；代码生成配置为单次请求，本轮未触发。

## 7. Native repeated-run results

Development、blind synthetic、blind real 分开统计。所有失败进入分母，未到达的 compile/runtime 计为未成功，但不称为编译错误。

| Set / case | Config | Trials | Candidate accepted | Slice success | Context complete | Plan | Compile | Runtime | False complete |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| blind_real / expat_opaque_feed | A | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_real / expat_opaque_feed | B | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_real / expat_opaque_feed | C | 5 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_real / libcsv_callback | A | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_real / libcsv_callback | B | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_real / libcsv_callback | C | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_real / mpack_stream_tree | A | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_real / mpack_stream_tree | B | 5 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_real / mpack_stream_tree | C | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_real / tomlc99_owned_string | A | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_real / tomlc99_owned_string | B | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_real / tomlc99_owned_string | C | 5 | 4 | 4 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / aliased_refcount | A | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / aliased_refcount | B | 5 | 4 | 4 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / aliased_refcount | C | 5 | 4 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / configured_decoder | A | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / configured_decoder | B | 5 | 4 | 4 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / configured_decoder | C | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / helper_allocated | A | 5 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / helper_allocated | B | 5 | 3 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / helper_allocated | C | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / out_memory_stream | A | 5 | 4 | 4 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / out_memory_stream | B | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / out_memory_stream | C | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / output_handle | A | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / output_handle | B | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / output_handle | C | 5 | 5 | 5 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / paired_snapshots | A | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / paired_snapshots | B | 5 | 4 | 4 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / paired_snapshots | C | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / private_session | A | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / private_session | B | 5 | 4 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / private_session | C | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / registration_object | A | 5 | 4 | 4 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / registration_object | B | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / registration_object | C | 5 | 4 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / saved_allocator | A | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / saved_allocator | B | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / saved_allocator | C | 5 | 4 | 4 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / signed_pull_reader | A | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / signed_pull_reader | B | 5 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / signed_pull_reader | C | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / three_feed_transaction | A | 5 | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / three_feed_transaction | B | 5 | 4 | 4 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / three_feed_transaction | C | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / three_level_callbacks | A | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / three_level_callbacks | B | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / three_level_callbacks | C | 5 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |


补充按配置统计的阶段状态（invalid output 单列，可能与 verdict 重叠）：

| Set / Config | Trials | Accepted | Unresolved | Rejected | Invalid output | Slice success | Context incomplete | Context invalid | Context not run |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| blind_synthetic/A | 60 | 29 | 30 | 1 | 0 | 29 | 19 | 10 | 31 |
| blind_synthetic/B | 60 | 34 | 26 | 0 | 1 | 32 | 15 | 17 | 28 |
| blind_synthetic/C | 60 | 39 | 21 | 0 | 0 | 37 | 22 | 15 | 23 |
| blind_real/A | 20 | 10 | 10 | 0 | 0 | 10 | 10 | 0 | 10 |
| blind_real/B | 20 | 9 | 11 | 0 | 0 | 9 | 9 | 0 | 11 |
| blind_real/C | 20 | 10 | 10 | 0 | 0 | 10 | 9 | 1 | 10 |

Slice success 包含冻结实现的 completed_with_unresolved；不自动等于 CORE 完整。CORE/support 的空产物和未到达阶段单独记录。Plan/code/compile/runtime 未执行的 trial 都进入端到端分母；条件编译成功率的分母只有实际编译尝试。



提供商可用性（受影响 trial 数，多标签，可重叠）：

| Config | Native attempts | 有模型响应 | 无模型响应 | HTTP 400 | HTTP 429 | 无 provider error | 无 provider error 且进入 Context |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 80 | 45 | 35 | 17 | 38 | 24 | 20 |
| B | 80 | 47 | 33 | 16 | 34 | 29 | 23 |
| C | 80 | 50 | 30 | 14 | 32 | 33 | 30 |

HTTP 429 在后段集中出现；已知只能确认服务端拒绝，原始 trace 没有足够信息区分具体限流/额度原因。HTTP 400 多见于冻结实现的 terminal repair。另有少量无 HTTP status 的请求错误。所有失败留在正式分母，未更换模型、凭证或重试。5 trials 指独立尝试数，不能解释为每个 case/config 有 5 次完整模型轨迹。无 provider error 的子集仅用于诊断，不能替代预注册成功率；该子集也没有 Context complete。


总体 Candidate accepted / unresolved / rejected 为 **131 / 108 / 1**，invalid-output 另有 1 次（与 verdict 重叠）。Slice completed / completed_with_unresolved / invalid / not_run 为 **79 / 48 / 4 / 109**。Context incomplete / invalid / not_run 为 **84 / 43 / 113**。Plan、code generation、compile、runtime 和 sanitizer 的实际尝试数均为 **0**，端到端成功为 0/240，条件成功率均为 N/A。

## 8. Semantic correctness

Each dimension is correct / incorrect / unverified / not applicable. Precision/recall and per-check evidence are in per-trial evaluation.json. Missing data remains unverified; zero denominator is N/A.

| Set / Config | Dimension | Correct | Incorrect | Unverified | N/A |
| --- | --- | ---: | ---: | ---: | ---: |
| blind_synthetic / A | resource_identity | 6 | 21 | 31 | 2 |
| blind_synthetic / A | lifecycle | 16 | 13 | 31 | 0 |
| blind_synthetic / A | ownership | 14 | 15 | 31 | 0 |
| blind_synthetic / A | callback | 2 | 7 | 33 | 18 |
| blind_synthetic / A | ordering | 18 | 9 | 31 | 2 |
| blind_synthetic / A | input_binding | 22 | 4 | 34 | 0 |
| blind_synthetic / A | multiplicity | 0 | 0 | 38 | 22 |
| blind_synthetic / B | resource_identity | 0 | 32 | 28 | 0 |
| blind_synthetic / B | lifecycle | 22 | 10 | 28 | 0 |
| blind_synthetic / B | ownership | 13 | 19 | 28 | 0 |
| blind_synthetic / B | callback | 3 | 1 | 30 | 26 |
| blind_synthetic / B | ordering | 20 | 12 | 28 | 0 |
| blind_synthetic / B | input_binding | 27 | 4 | 29 | 0 |
| blind_synthetic / B | multiplicity | 0 | 0 | 40 | 20 |
| blind_synthetic / C | resource_identity | 8 | 27 | 23 | 2 |
| blind_synthetic / C | lifecycle | 21 | 16 | 23 | 0 |
| blind_synthetic / C | ownership | 17 | 20 | 23 | 0 |
| blind_synthetic / C | callback | 2 | 8 | 25 | 25 |
| blind_synthetic / C | ordering | 21 | 14 | 23 | 2 |
| blind_synthetic / C | input_binding | 28 | 6 | 26 | 0 |
| blind_synthetic / C | multiplicity | 0 | 0 | 31 | 29 |
| blind_real / A | resource_identity | 1 | 5 | 10 | 4 |
| blind_real / A | lifecycle | 2 | 6 | 10 | 2 |
| blind_real / A | ownership | 1 | 9 | 10 | 0 |
| blind_real / A | callback | 0 | 2 | 10 | 8 |
| blind_real / A | ordering | 1 | 9 | 10 | 0 |
| blind_real / A | input_binding | 3 | 5 | 12 | 0 |
| blind_real / A | multiplicity | 0 | 0 | 10 | 10 |
| blind_real / B | resource_identity | 0 | 5 | 11 | 4 |
| blind_real / B | lifecycle | 0 | 6 | 11 | 3 |
| blind_real / B | ownership | 0 | 9 | 11 | 0 |
| blind_real / B | callback | 0 | 3 | 11 | 6 |
| blind_real / B | ordering | 1 | 8 | 11 | 0 |
| blind_real / B | input_binding | 4 | 4 | 12 | 0 |
| blind_real / B | multiplicity | 0 | 0 | 11 | 9 |
| blind_real / C | resource_identity | 0 | 5 | 11 | 4 |
| blind_real / C | lifecycle | 2 | 5 | 11 | 2 |
| blind_real / C | ownership | 1 | 8 | 11 | 0 |
| blind_real / C | callback | 0 | 2 | 11 | 7 |
| blind_real / C | ordering | 1 | 8 | 11 | 0 |
| blind_real / C | input_binding | 1 | 6 | 13 | 0 |
| blind_real / C | multiplicity | 0 | 0 | 11 | 9 |


API set overlap：仅对该阶段已保存产物计算 micro precision/recall，分母列明。未到达阶段不伪装成已验证契约。

| Set / Config | API set | Observations | TP | FP | FN | Micro precision | Micro recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| blind_synthetic/A | core_precision_recall | 29 | 37 | 6 | 2 | 0.86 | 0.95 |
| blind_synthetic/A | support_precision_recall | 29 | 50 | 2 | 8 | 0.96 | 0.86 |
| blind_synthetic/B | core_precision_recall | 34 | 43 | 5 | 4 | 0.90 | 0.91 |
| blind_synthetic/B | support_precision_recall | 32 | 65 | 4 | 2 | 0.94 | 0.97 |
| blind_synthetic/C | core_precision_recall | 39 | 47 | 6 | 3 | 0.89 | 0.94 |
| blind_synthetic/C | support_precision_recall | 37 | 69 | 2 | 4 | 0.97 | 0.95 |
| blind_real/A | core_precision_recall | 10 | 10 | 0 | 0 | 1.00 | 1.00 |
| blind_real/A | support_precision_recall | 10 | 6 | 1 | 9 | 0.86 | 0.40 |
| blind_real/B | core_precision_recall | 9 | 9 | 2 | 0 | 0.82 | 1.00 |
| blind_real/B | support_precision_recall | 9 | 6 | 0 | 9 | 1.00 | 0.40 |
| blind_real/C | core_precision_recall | 10 | 10 | 2 | 0 | 0.83 | 1.00 |
| blind_real/C | support_precision_recall | 10 | 3 | 2 | 11 | 0.60 | 0.21 |

required support precision 是与预注册 required API 集合的重合度；额外合法 helper 并不因此成为语义错误。表中 incorrect 包含部分 Context 缺少必要事实，须结合 Gate 状态解读，不能直接视为 unsound success。
MPack 的合法 initializer_alternatives 由生命周期检查单独判断；原始 support-set overlap 未归一化这些替代 initializer，可能产生路线差异的 FP/FN。


跨全部预注册 trial，把缺失阶段视为空预测时：CORE recall 为 **156/300 = 52.0%**，required-support set recall 为 **199/435 = 45.7%**；分母是人工 reference API entries，不是 Candidate discovery 的召回率。这两个端到端集合指标包含服务端拒绝，且 support 替代路线限制仍适用。与条件指标相对照，可以看到只看已产出 Slice/Context 的高 precision/recall 会隐藏大量前段失败。

## 9. False-complete and conservative failures

| Set / Config | complete_and_runtime_valid | complete_but_invalid | blocked_conservatively | semantic_verified + runtime | 自动 false-complete flags（需审计） |
| --- | ---: | ---: | ---: | ---: | ---: |
| blind_synthetic / A | 0 | 0 | 60 | 0 | 0 |
| blind_synthetic / B | 0 | 0 | 60 | 0 | 0 |
| blind_synthetic / C | 0 | 0 | 60 | 0 | 0 |
| blind_real / A | 0 | 0 | 20 | 0 | 0 |
| blind_real / B | 0 | 0 | 20 | 0 | 0 |
| blind_real / C | 0 | 0 | 20 | 0 | 0 |

本批尚未确认 false complete；这不表示不存在未审计的 callback、input transport 或其他语义缺陷。


判读边界：原始 supervisor 有 1 个 adjudication_error，原始记录及异常类型原样保留。独立 audit 只恢复阶段、成本、API 集合和规则命中；没有修复 callback checker，该行语义一律 unverified。恢复结果见 posthoc_v2/summary.json 和 analysis_code.py；其 native_summary_sha256 可核对原始记录未被覆盖。

blocked_conservatively 在汇总中指没有生成许可，包含前段退出和 provider failure，不能解释成每次都完成了语义证明。confirmed false_complete 需要 Gate 放行且独立审计证明 mandatory contract 错误；自动旗标本身不足以确认。若 complete 为零，条件 false-complete rate 为 N/A，没有检验 Gate 放行后的 soundness。


## 10. Certificate / rule applicability

下表 C 为完整未干预实现；A/B 的 disabled 原因单独保存，不能误当成规则自然失败。每 trial 记录 fired / did_not_fire / blocked / produced_unresolved。未命中原因属于 evaluation-side diagnosis，没有改动生产规则来追求命中。

| Set / Config | Rule | Applied trials | Cases with a hit | Blocked | Produced unresolved |
| --- | --- | ---: | ---: | ---: | ---: |
| blind_synthetic / A | resource_identity | 0 | 0 | 0 | 0 |
| blind_synthetic / A | creator_return | 0 | 0 | 0 | 0 |
| blind_synthetic / A | cleanup_consumption | 0 | 0 | 0 | 0 |
| blind_synthetic / A | public_callback_object | 0 | 0 | 0 | 0 |
| blind_synthetic / A | nul_contract | 0 | 0 | 0 | 0 |
| blind_synthetic / A | local_state_transition | 0 | 0 | 0 | 0 |
| blind_synthetic / A | ordering_projection | 23 | 11 | 0 | 0 |
| blind_synthetic / B | resource_identity | 13 | 6 | 6 | 19 |
| blind_synthetic / B | creator_return | 0 | 0 | 0 | 0 |
| blind_synthetic / B | cleanup_consumption | 0 | 0 | 0 | 0 |
| blind_synthetic / B | public_callback_object | 0 | 0 | 0 | 0 |
| blind_synthetic / B | nul_contract | 0 | 0 | 0 | 0 |
| blind_synthetic / B | local_state_transition | 0 | 0 | 0 | 0 |
| blind_synthetic / B | ordering_projection | 30 | 11 | 0 | 0 |
| blind_synthetic / C | resource_identity | 21 | 8 | 9 | 16 |
| blind_synthetic / C | creator_return | 0 | 0 | 0 | 0 |
| blind_synthetic / C | cleanup_consumption | 10 | 6 | 0 | 0 |
| blind_synthetic / C | public_callback_object | 0 | 0 | 0 | 0 |
| blind_synthetic / C | nul_contract | 0 | 0 | 0 | 0 |
| blind_synthetic / C | local_state_transition | 0 | 0 | 0 | 0 |
| blind_synthetic / C | ordering_projection | 31 | 11 | 0 | 0 |
| blind_real / A | resource_identity | 0 | 0 | 0 | 0 |
| blind_real / A | creator_return | 0 | 0 | 0 | 0 |
| blind_real / A | cleanup_consumption | 0 | 0 | 0 | 0 |
| blind_real / A | public_callback_object | 0 | 0 | 0 | 0 |
| blind_real / A | nul_contract | 2 | 1 | 0 | 0 |
| blind_real / A | local_state_transition | 0 | 0 | 0 | 0 |
| blind_real / A | ordering_projection | 1 | 1 | 0 | 0 |
| blind_real / B | resource_identity | 0 | 0 | 0 | 9 |
| blind_real / B | creator_return | 0 | 0 | 0 | 0 |
| blind_real / B | cleanup_consumption | 0 | 0 | 0 | 0 |
| blind_real / B | public_callback_object | 0 | 0 | 0 | 0 |
| blind_real / B | nul_contract | 1 | 1 | 0 | 0 |
| blind_real / B | local_state_transition | 0 | 0 | 0 | 0 |
| blind_real / B | ordering_projection | 1 | 1 | 0 | 0 |
| blind_real / C | resource_identity | 0 | 0 | 0 | 10 |
| blind_real / C | creator_return | 0 | 0 | 0 | 0 |
| blind_real / C | cleanup_consumption | 0 | 0 | 0 | 0 |
| blind_real / C | public_callback_object | 0 | 0 | 0 | 0 |
| blind_real / C | nul_contract | 1 | 1 | 0 | 0 |
| blind_real / C | local_state_transition | 0 | 0 | 0 | 0 |
| blind_real / C | ordering_projection | 2 | 2 | 0 | 0 |

完整配置 C 的局部命中：resource identity **21/80 trials、8 个 case**；cleanup consumption **10/80、6 个 case**；NUL **1/80、1 个真实 TOML case**；hard ordering projection **33/80、13 个 case**。creator_return、public_callback_object、local state transition 均为 **0/80**。分母包含未进入 Context 的 trial，规则自然适用次数另见逐次 certificates；“命中”不等于全契约正确或端到端成功。

## 11. Failure taxonomy

Failures are multi-label. Early upstream failure keeps downstream metrics N/A/false, not zero hard gaps. Operational/programming errors are retained as observed failures; no code was repaired using their results.

| Failure | Trials |
| --- | ---: |
| provider_error | 154 |
| argument_construction_unknown | 118 |
| semantic_contract_mismatch | 118 |
| candidate_unresolved | 108 |
| lifecycle_unknown | 97 |
| ownership_unknown | 94 |
| state_unknown | 75 |
| input_binding_unknown | 66 |
| resource_identity_unresolved | 43 |
| return_semantics_unknown | 39 |
| callback_unknown | 39 |
| slice_missing_support | 31 |
| resource_identity_conflict | 20 |
| slice_overexpanded_core | 19 |
| slice_missing_core | 9 |
| api_closure_unknown | 5 |
| slice_invalid | 4 |
| evaluation_error | 1 |
| candidate_false_negative | 1 |
| candidate_rejected | 1 |
| candidate_invalid_output | 1 |

## 12. Native A/B/C ablation

A keeps Agent-grounded model IDs but removes framework resource projection and construction certificates. B adds generic resource identity/flow, disables allocation/free ownership shortcut and reuse normalization, and still removes high-level creator/public callback/cleanup/state certificates. C is the original frozen implementation.

Gate, prompts, registry, callback ABI enrichment, NUL projection, bounded evidence preflight and existing ordering validators are held constant. Generic flow tool evidence is still available to the Agent in every config; this experiment isolates deterministic projection, not removal of an Agent tool. This is a subtractive intervention, not an exact historical baseline. Independent native model trajectories mean A→B→C differences require repeated sampling, not paired causal token claims.

| Config | Native attempts | Slice success | Context observed | Context complete | Runtime success |
| --- | ---: | ---: | ---: | ---: | ---: |
| A | 80 | 39 | 39 | 0 | 0 |
| B | 80 | 41 | 41 | 0 | 0 |
| C | 80 | 47 | 47 | 0 | 0 |

三组均未完成 Context，且 provider availability 不均衡；不能据 39→41→47 推断 certificates 导致 Slice 改善，construction intervention 本身发生在 Slice 之后。B 的 partial identity 评分也不能由规则命中替代。现有数据支持“有局部规则复用，但未观察到 completion 增益”，不支持通用语义构造能力或显著因果效果。

## 13. Cost

tokens are reported provider usage, not price or uncached billed tokens. Failed provider attempts without usage cannot be priced. Context grouped traces are deduplicated; global Context metrics govern call/tool counts. Actual output size, FT/core/support/unresolved/gaps/closure/source chars, elapsed time and all raw stages are retained per trial.

| Set / Config | Model calls | Tools | Prompt tokens | Completion tokens | Total tokens | Mean hard gaps (observed Context only) | Mean source chars | Mean seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| blind_synthetic / A | 838 | 1,453 | 6,533,712 | 749,475 | 7,283,187 | 8.9 | 8,988.2 | 94.9 |
| blind_synthetic / B | 948 | 1,610 | 7,286,816 | 868,568 | 8,155,384 | 8.6 | 10,510.9 | 109.5 |
| blind_synthetic / C | 1,000 | 1,738 | 7,803,583 | 917,215 | 8,720,798 | 8.9 | 11,415.6 | 119.5 |
| blind_real / A | 341 | 787 | 3,109,691 | 122,793 | 3,232,484 | 13.4 | 61,627.3 | 56.4 |
| blind_real / B | 300 | 670 | 2,978,539 | 122,844 | 3,101,383 | 20.7 | 53,831.2 | 59.8 |
| blind_real / C | 339 | 754 | 3,273,299 | 134,178 | 3,407,477 | 14.3 | 59,471.4 | 63.2 |


大小指标：均值仅使用 observed artifacts，括号为观测数，未到达阶段为 N/A。

| Set / Config | Slice CORE | Slice SUPPORT | Slice unresolved | FT CORE | FT support candidates | Hard gaps | Soft unknowns | API closure |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| blind_synthetic/A | 1.48 (29) | 1.76 (29) | 0.38 (29) | 1.48 (29) | 1.76 (29) | 8.86 (29) | 1.62 (29) | 3.28 (29) |
| blind_synthetic/B | 1.41 (34) | 1.53 (34) | 0.88 (34) | 1.44 (32) | 1.62 (32) | 8.56 (32) | 1.62 (32) | 3.59 (32) |
| blind_synthetic/C | 1.36 (39) | 1.74 (39) | 0.51 (39) | 1.38 (37) | 1.84 (37) | 8.92 (37) | 1.62 (37) | 3.30 (37) |
| blind_real/A | 1.00 (10) | 0.00 (10) | 68.70 (10) | 1.00 (10) | 0.00 (10) | 13.40 (10) | 65.40 (10) | 1.70 (10) |
| blind_real/B | 1.22 (9) | 1.11 (9) | 68.56 (9) | 1.22 (9) | 1.11 (9) | 20.67 (9) | 68.56 (9) | 2.11 (9) |
| blind_real/C | 1.20 (10) | 1.00 (10) | 40.70 (10) | 1.20 (10) | 1.00 (10) | 14.30 (10) | 39.90 (10) | 1.70 (10) |

全 cohort 已记录成本：model calls 3766，tool calls 7012，prompt / completion / total tokens 30,985,640 / 2,915,073 / 33,900,713。

完整尺寸分布、均值/中位数/最大值、分组状态与 micro 分母保存在 posthoc_v2/aggregates.json。usage 缺失的失败请求不算零成本，实际账单无法从本实验推断。


主 cohort 墙钟时间约 **98.8 分钟**；trial elapsed 合计约 **6.40 小时**，包含四 worker 并发，不能当作墙钟时间。全体平均 elapsed 95.93 秒受后段快速 429 失败影响；不能据此比较语义效率。所有成本均只属于正式 V2 native cohort，不含 pilot、开发集、reference preflight 或后处理。

## 14. Limitations

只有五个重复样本/配置/模式，非独立第三方持有的盲集；由实现者在 freeze 后创建，仍有 pattern selection bias。真实项目均为 C，没有 C++ 项目效度；显式 target 和原始 source slice 不支持 entry discovery recall。六个固定 ASan/UBSan replay 输入不证明 coverage 或穷尽正确性。

人工 annotation 及自动 necessary-contract checker 可能遗漏不变量；unverified 的 reader/allocator/field values 不能当作成功。A/B 是 evaluation-side projection intervention，预算相同不代表调查/evidence 相同。指标未控制 provider 时间变化和硬件噪声。若这一批失败以后参与规则修改，必须换新的 blind set，保留本批。


基础设施限制：V1 pilot 因 build recipe 漏写 schema_version 而终止，20 个完成和 4 个中断 trial 全部保留并排除正式分母；修复评测接线后重新冻结并选用完全不同的 V2 集合。V1 callback-setter false-complete 自动旗标存在合法公开字段初始化替代路线，未经确认，不作为 Gate 缺陷证据。V2 evaluator 的 callback field=null 异常保持冻结，只追加上述独立观察审计。详见 [observed failures](BLIND_GENERALIZATION_OBSERVED_FAILURES.md)。



98 个 trial 未取得模型响应，154 个 trial 至少出现一次 provider error；A/B/C 取得响应的机会不同。因而本轮完成了预注册采样与保存，但没有完成每模式/配置 5 次无服务错误的语义稳定性验证。三组 completion 均为零，不能估计 construction certificates 的成功率增益，也不能把服务端错误归因于规则不覆盖。


## 15. Which capabilities generalized?

完整配置 C 中具有已检查必要契约且 runtime 通过的模式：尚无已充分验证的 positive pattern。

这些是 observed capability，只有在重复成功和独立语义证据都足够时才支持对应模式泛化；不能推广成 framework generalizes across C/C++ projects。


局部必要-contract 检查：C 中 resource identity correct 8 个 trial，涉及 configured_decoder, private_session, signed_pull_reader；callback ABI/registration correct 2 个 trial，涉及 registration_object。这些 Context 仍被 Gate 拦截，不能当作完整 API pattern 成功。规则命中只说明证据投影被应用，不自动等于整份语义契约正确。


## 16. Narrow deterministic proof subset

creator_return 仍要求无参数精确 calloc creator、单来源、非逃逸字段 consumer 和唯一 cleanup；public_callback_object 仍要求完整公开 layout、可显式初始化所有字段和同步非逃逸；cleanup_consumption 仍要求精确单参数 free wrapper及已有独立 owned producer。它们的 zero hit 或少量 hit 应如实解释为 recognized subset，而非修改规则提高 benchmark。

最终原始 summary、preregistration、源码归档、每次日志/annotation digest/evaluation.json 均在本地 artifact 目录。报告没有替换失败，也没有把 development 数据混进成功率。

复现（需先创建新的 freeze/output 和新盲集；禁止对已反馈到算法的本集继续称 blind）：

```bash
.venv/bin/python -m scripts.blind_eval.freeze --output artifacts/<new-frozen-output>
.venv/bin/python -m scripts.blind_eval.runner --benchmark-dir benchmarks/blind/<new-cohort> --output artifacts/<new-frozen-output> --repetitions 5 --workers 4
.venv/bin/python -m scripts.blind_eval.report --input artifacts/<output> --output docs/BLIND_GENERALIZATION_EVALUATION.md
```

本轮 synthetic patterns：

- `configured_decoder`: creator args + output status + private configuration
- `output_handle`: out-parameter + failure-cleared output + capacity
- `helper_allocated`: helper malloc + helper initialization + copied feed
- `saved_allocator`: custom allocator copied into resource + callback release
- `aliased_refcount`: owned returned reference aliases input object + double unref
- `private_session`: opaque layout + creator name argument + internal state
- `registration_object`: setter takes registration object + private parser state
- `three_level_callbacks`: three nested layout levels + void notification callback
- `signed_pull_reader`: signed read result + retained callback context + EOF/error
- `three_feed_transaction`: three required state transitions + independently chunked input
- `paired_snapshots`: two same-type instances + different creator arguments + non-alias
- `out_memory_stream`: out-parameter stream + separate memory binding + pull parser

真实入口数 4；独立项目数 4。


源码边界核对（静态设计分析，不能替代本轮未执行的 Plan/runtime）：

- `construction.zero_creator` 只接受无参数、单指针返回、函数体精确为 `return calloc(1, sizeof(T));`；其局部链还要求单 origin、单 cleanup、可证明的字段 consumer。带参数 creator、out initialization、helper allocation、refcount 和重复调用不会仅凭相近类型成为同一证书。
- `construction.public_callback_object` 明确拒绝嵌套 `field_path` 和非空 `setup_api`，并要求完整字段初始化及同步非逃逸。准确 callback ABI 与可构造 callback object 是两个独立判断；nested table、setter、pull reader 的 ABI 证据不能自动完成其构造或行为契约。
- `resource_identity.endpoint` 以 function/parameter/return 为键；多候选 creator identity 留为 unresolved。它不是任意调用实例与引用计数单位的模型。
- Plan 的 SUPPORT 能按显式 resource 重复，但 CORE 仍按 API 调度一次；多个 return resource 会触发明确的 alias 限制。三次 feed 和两个对象上的 CORE feed，需要比函数级 ordering 更细的调用实例证据。本轮未到达 Plan，因此这属于表示边界，不是已观察到的运行崩溃。
- NUL projection 要求已发布的 fuzz binding、明确 nul_terminate transform 与源码中限定的 libc/循环证据；不能由 char-pointer 类型或项目名直接完成。手写 lexer、间接输入和跨 helper string contract 可能停在 recognized proof subset 之外。

本轮 worker 的静态准备是函数/签名/body 解析；legacy SFG edges、annotations 和文档为空。现有 scoped source/value-flow 工具仍运行。所有配置相同，但这些结果不能解释成完整 legacy-SFG 分析或全仓库 Candidate discovery 的评价。


可复核产物位于 `artifacts/blind_generalization_v2_20260929/`：`freeze/manifest.json`、`preregistration.json`、原始 `summary.json`、`trials/*/evaluation.json` 和 logs；独立观察审计在 `posthoc_v2/summary.json`、`aggregates.json`、`trials.csv`、`analysis_code.py`。唯一原始判读异常是 `libcsv_callback/C/4` 的 TypeError，原始 runner 因该异常返回 1，但 240 次采样和最终 freeze 检查均完成。该行缺失语义保持 unverified，不覆盖原始记录。

本次新增实现为独立 freeze/schema/fixture/runner/ablation/report 和 post-hoc audit。生产算法、prompt、Gate、工具集合和预算始终保持原冻结身份。离线回归测试与发展集验证独立于 blind 成功率。
