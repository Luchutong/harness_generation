# Invalidated infrastructure pilot v1

本轮使用固定语义实现，以新的 API semantic patterns 和实测前选定的真实项目评价泛化。旧五类 fixture 仅是 Development / Regression Set，不进入盲测分母。本实验显式指定 target anchor，属于 **semantic pipeline evaluation**，不评价 project-level Candidate recall。

本轮已因 worker build recipe 缺少 schema_version 而中止；不进入泛化证据。当前记录 **20/255** 个 native trials；状态：**in progress / not finalized**。没有 paired replay、失败后修代码、追加预算或挑选最佳一次。

## 1. Frozen implementation identity

- git commit：`11c27c084a0b96c4c9ca016721b7ddb8d7536d5f`，branch `v0.2`，dirty files 48；本地未提交代码属于冻结身份。
- production fingerprint：`d2b183cb70503604b98e7024790f93f4829e513a9005fed7f26a60a0583988f9`。
- 135 个生产 Python 源文件和 root runtime dependencies 有摘要；原始源码和 tracked patch 归档于 `freeze/`。
- requested model：`ark-code-latest`；provider `openai-compatible`，thinking `disabled`。
- served models：deepseek-v4-flash-ga-260731。
- 开始时间：`2026-09-28T17:36:05.159078+00:00`；结束时间：`pending`。
- production/evaluation/benchmarks unchanged：`None/None/None`。

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

每个 case 的源文件仅在 `benchmarks/blind/synthetic/<id>/source/`，expected contract 位于同级 `ground_truth.json`。独立 reference harness 在 source 外，用于验证样例自身可执行，未向 Agent 提供。它们不是旧 fixture 改名，也不用于新增生产规则。

## 4. Blind real-project set

在 production freeze 后、native run 前选定五个 target APIs，来自四个不同 upstream projects。源码为原始库实现和 header slice；统一排除 examples、tests 和上游 fuzzer，选择不基于框架成功。此范围限制不能当作全仓库入口发现。

| Target | Upstream / commit | Model / selection rationale |
| --- | --- | --- |
| `ini_parse_string` | [inih](https://github.com/benhoyt/inih/tree/2bbdec4a366c8c39746ee0982e7ca0febbb044b6) / `2bbdec4a366c8c39746ee0982e7ca0febbb044b6` | NUL string entry with synchronous handler; not chosen by observed framework success |
| `ini_parse_stream` | [inih](https://github.com/benhoyt/inih/tree/2bbdec4a366c8c39746ee0982e7ca0febbb044b6) / `2bbdec4a366c8c39746ee0982e7ca0febbb044b6` | Custom fgets-style input reader and userdata; pull transport outside byte-pointer parser arguments |
| `yajl_parse` | [yajl](https://github.com/lloyd/yajl/tree/5e3a7856e643b4d6410ddc3f84bc2f38174f2872) / `5e3a7856e643b4d6410ddc3f84bc2f38174f2872` | Opaque allocated handle plus SAX callbacks and incremental bytes |
| `http_parser_execute` | [http-parser](https://github.com/nodejs/http-parser/tree/ec8b5ee63f0e51191ea43bb0c6eac7bfbff3141d) / `ec8b5ee63f0e51191ea43bb0c6eac7bfbff3141d` | Stateful incremental feed with parser settings and callback return protocol |
| `cJSON_ParseWithLength` | [cJSON](https://github.com/DaveGamble/cJSON/tree/6d9f2443ab071f86e5d9b43025a40929ec41c46c) / `6d9f2443ab071f86e5d9b43025a40929ec41c46c` | Owned parse tree, recursive release and explicit input length |

inih 同时提供 string 和 custom stream 两个入口；它们不是两个独立项目。YAJL 为 opaque handle/SAX streaming，http-parser 为 incremental feed，cJSON 为 owned object parser。构建系统及原始 source hashes 位于 real selection/manifest；构建布局准备在任何 native call 前完成，没有修改目标库算法。

## 5. Ground truth and semantic adjudication

`ground_truth.schema.json` 与人工独立 contract annotation 包含 CORE、required support、resource origin/consumers/cleanup、input binding、ownership、callback、ordering、invocation multiplicity 和必要约束。Pipeline worker 不导入 evaluator 或 fixtures；仅得到 source/、target API 与纯 build options。Agent 工具只能索引 trial project；注释目录不在可读取范围。

Supervisor 在 worker 退出后才加载 truth。CORE/support precision/recall 按预注册 API sets 计算，资源比较明确的 origin 与消费身份，生命周期检查明确 creator/output 和 cleanup，ownership 检查返回/参数和 release，callback 检查精确 field/registration/ABI，ordering 检查 hard-edge reachability，multiplicity 检查独立预期调用次数。

这些是必要契约检查，不是任意 C/C++ 语义的形式化证明。未产出契约为 unverified；pull reader/custom allocator 行为不能只由 ABI 判断，仍需 code audit。Runtime 通过也不会把 unknown 自动改成 correct。

`false_complete` 为 Gate complete 且独立必要-contract 比较已证明 mandatory mismatch。单纯 compile/static failure 不自动证明 Gate semantic unsoundness；另列 complete_but_invalid、unverified dimensions、sanitizer failures。未检出的错误不等于不存在；确认后的人工 audit 应作为独立追加结果，不能覆盖原始 trial。

## 6. Budgets and native design

每 case / configuration 至少五个独立 trials，fresh source copy、Candidate、Slice、FT、Context、Plan 与 code；没有 resume。A/B/C 不是同证据重投影。schedule 固定 seed 20260929，仅用于作业交错，不是模型随机 seed。Agent temperature/provider seed 未指定，code temperature 0.2，最多 8192 output tokens；四种 library adapters 只有原始 build flags/header paths，没有语义适配。

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

## 7. Native repeated-run results

Development、blind synthetic、blind real 分开统计。所有失败进入分母，未到达的 compile/runtime 计为未成功，但不称为编译错误。

| Set / case | Config | Trials | Candidate accepted | Slice success | Context complete | Plan | Compile | Runtime | False complete |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| blind_real / cjson_owned | A | 2 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| blind_real / cjson_owned | C | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_real / http_parser_feed | B | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_real / inih_stream | B | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_real / inih_stream | C | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_real / inih_string | A | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_real / inih_string | B | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_real / yajl_opaque | B | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / callback_setter | C | 2 | 2 | 2 | 1 | 1 | 0 | 0 | 1 |
| blind_synthetic / creator_arguments | C | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / custom_allocator | A | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / memory_stream | A | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / nested_callback_table | C | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / opaque_context | C | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| blind_synthetic / pull_callback | A | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / reference_counting | A | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / reference_counting | B | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| blind_synthetic / repeated_feeds | C | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |

## 8. Semantic correctness

Each dimension is correct / incorrect / unverified / not applicable. Precision/recall and per-check evidence are in per-trial evaluation.json. Missing data remains unverified; zero denominator is N/A.

| Set / Config | Dimension | Correct | Incorrect | Unverified | N/A |
| --- | --- | ---: | ---: | ---: | ---: |
| blind_synthetic / A | resource_identity | 1 | 2 | 0 | 1 |
| blind_synthetic / A | lifecycle | 3 | 1 | 0 | 0 |
| blind_synthetic / A | ownership | 1 | 3 | 0 | 0 |
| blind_synthetic / A | callback | 0 | 1 | 1 | 2 |
| blind_synthetic / A | ordering | 2 | 2 | 0 | 0 |
| blind_synthetic / A | input_binding | 2 | 1 | 1 | 0 |
| blind_synthetic / A | multiplicity | 0 | 0 | 1 | 3 |
| blind_synthetic / B | resource_identity | 0 | 0 | 0 | 1 |
| blind_synthetic / B | lifecycle | 1 | 0 | 0 | 0 |
| blind_synthetic / B | ownership | 1 | 0 | 0 | 0 |
| blind_synthetic / B | callback | 0 | 0 | 0 | 1 |
| blind_synthetic / B | ordering | 1 | 0 | 0 | 0 |
| blind_synthetic / B | input_binding | 1 | 0 | 0 | 0 |
| blind_synthetic / B | multiplicity | 0 | 0 | 1 | 0 |
| blind_synthetic / C | resource_identity | 1 | 4 | 0 | 1 |
| blind_synthetic / C | lifecycle | 4 | 1 | 0 | 1 |
| blind_synthetic / C | ownership | 1 | 4 | 0 | 1 |
| blind_synthetic / C | callback | 0 | 3 | 0 | 3 |
| blind_synthetic / C | ordering | 1 | 4 | 0 | 1 |
| blind_synthetic / C | input_binding | 5 | 1 | 0 | 0 |
| blind_synthetic / C | multiplicity | 0 | 0 | 1 | 5 |
| blind_real / A | resource_identity | 0 | 0 | 0 | 3 |
| blind_real / A | lifecycle | 0 | 2 | 0 | 1 |
| blind_real / A | ownership | 0 | 3 | 0 | 0 |
| blind_real / A | callback | 0 | 1 | 0 | 2 |
| blind_real / A | ordering | 0 | 2 | 0 | 1 |
| blind_real / A | input_binding | 1 | 2 | 0 | 0 |
| blind_real / A | multiplicity | 0 | 0 | 0 | 3 |
| blind_real / B | resource_identity | 0 | 1 | 0 | 3 |
| blind_real / B | lifecycle | 0 | 1 | 0 | 3 |
| blind_real / B | ownership | 1 | 3 | 0 | 0 |
| blind_real / B | callback | 0 | 2 | 0 | 2 |
| blind_real / B | ordering | 0 | 2 | 0 | 2 |
| blind_real / B | input_binding | 1 | 2 | 1 | 0 |
| blind_real / B | multiplicity | 0 | 0 | 0 | 4 |
| blind_real / C | resource_identity | 0 | 0 | 0 | 2 |
| blind_real / C | lifecycle | 0 | 1 | 0 | 1 |
| blind_real / C | ownership | 0 | 2 | 0 | 0 |
| blind_real / C | callback | 0 | 1 | 0 | 1 |
| blind_real / C | ordering | 0 | 1 | 0 | 1 |
| blind_real / C | input_binding | 0 | 1 | 1 | 0 |
| blind_real / C | multiplicity | 0 | 0 | 0 | 2 |

## 9. False-complete and conservative failures

| Set / Config | complete_and_runtime_valid | complete_but_invalid | blocked_conservatively | semantic_verified + runtime | confirmed false_complete |
| --- | ---: | ---: | ---: | ---: | ---: |
| blind_synthetic / A | 0 | 0 | 4 | 0 | 0 |
| blind_synthetic / B | 0 | 0 | 1 | 0 | 0 |
| blind_synthetic / C | 0 | 2 | 4 | 0 | 1 |
| blind_real / A | 0 | 0 | 3 | 0 | 0 |
| blind_real / B | 0 | 0 | 4 | 0 | 0 |
| blind_real / C | 0 | 0 | 2 | 0 | 0 |

Confirmed mandatory contract mismatch trials:

- `callback_setter/C/4`: resource_identity, lifecycle, ownership, callback, ordering。见该 trial evaluation.json 中的 checks。

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
| blind_synthetic / A | ordering_projection | 3 | 3 | 0 | 0 |
| blind_synthetic / B | resource_identity | 1 | 1 | 0 | 0 |
| blind_synthetic / B | creator_return | 0 | 0 | 0 | 0 |
| blind_synthetic / B | cleanup_consumption | 0 | 0 | 0 | 0 |
| blind_synthetic / B | public_callback_object | 0 | 0 | 0 | 0 |
| blind_synthetic / B | nul_contract | 0 | 0 | 0 | 0 |
| blind_synthetic / B | local_state_transition | 0 | 0 | 0 | 0 |
| blind_synthetic / B | ordering_projection | 1 | 1 | 0 | 0 |
| blind_synthetic / C | resource_identity | 4 | 4 | 0 | 2 |
| blind_synthetic / C | creator_return | 0 | 0 | 0 | 0 |
| blind_synthetic / C | cleanup_consumption | 3 | 3 | 0 | 0 |
| blind_synthetic / C | public_callback_object | 1 | 1 | 0 | 0 |
| blind_synthetic / C | nul_contract | 0 | 0 | 0 | 0 |
| blind_synthetic / C | local_state_transition | 0 | 0 | 0 | 0 |
| blind_synthetic / C | ordering_projection | 4 | 4 | 0 | 0 |
| blind_real / A | resource_identity | 0 | 0 | 0 | 0 |
| blind_real / A | creator_return | 0 | 0 | 0 | 0 |
| blind_real / A | cleanup_consumption | 0 | 0 | 0 | 0 |
| blind_real / A | public_callback_object | 0 | 0 | 0 | 0 |
| blind_real / A | nul_contract | 0 | 0 | 0 | 0 |
| blind_real / A | local_state_transition | 0 | 0 | 0 | 0 |
| blind_real / A | ordering_projection | 0 | 0 | 0 | 0 |
| blind_real / B | resource_identity | 0 | 0 | 0 | 2 |
| blind_real / B | creator_return | 0 | 0 | 0 | 0 |
| blind_real / B | cleanup_consumption | 0 | 0 | 0 | 0 |
| blind_real / B | public_callback_object | 0 | 0 | 0 | 0 |
| blind_real / B | nul_contract | 0 | 0 | 0 | 0 |
| blind_real / B | local_state_transition | 0 | 0 | 0 | 0 |
| blind_real / B | ordering_projection | 0 | 0 | 0 | 0 |
| blind_real / C | resource_identity | 0 | 0 | 0 | 2 |
| blind_real / C | creator_return | 0 | 0 | 0 | 0 |
| blind_real / C | cleanup_consumption | 0 | 0 | 0 | 0 |
| blind_real / C | public_callback_object | 0 | 0 | 0 | 0 |
| blind_real / C | nul_contract | 0 | 0 | 0 | 0 |
| blind_real / C | local_state_transition | 0 | 0 | 0 | 0 |
| blind_real / C | ordering_projection | 0 | 0 | 0 | 0 |

## 11. Failure taxonomy

Failures are multi-label. Early upstream failure keeps downstream metrics N/A/false, not zero hard gaps. Operational/programming errors are retained as observed failures; no code was repaired using their results.

| Failure | Trials |
| --- | ---: |
| semantic_contract_mismatch | 17 |
| argument_construction_unknown | 14 |
| ownership_unknown | 14 |
| lifecycle_unknown | 12 |
| input_binding_unknown | 10 |
| provider_error | 10 |
| callback_unknown | 9 |
| return_semantics_unknown | 8 |
| state_unknown | 8 |
| slice_missing_support | 6 |
| slice_overexpanded_core | 6 |
| resource_identity_unresolved | 4 |
| api_closure_unknown | 2 |
| slice_missing_core | 1 |
| plan_blocked | 1 |

## 12. Native A/B/C ablation

A keeps Agent-grounded model IDs but removes framework resource projection and construction certificates. B adds generic resource identity/flow, disables allocation/free ownership shortcut and reuse normalization, and still removes high-level creator/public callback/cleanup/state certificates. C is the original frozen implementation.

Gate, prompts, registry, callback ABI enrichment, NUL projection, bounded evidence preflight and existing ordering validators are held constant. Generic flow tool evidence is still available to the Agent in every config; this experiment isolates deterministic projection, not removal of an Agent tool. This is a subtractive intervention, not an exact historical baseline. Independent native model trajectories mean A→B→C differences require repeated sampling, not paired causal token claims.

## 13. Cost

tokens are reported provider usage, not price or uncached billed tokens. Failed provider attempts without usage cannot be priced. Context grouped traces are deduplicated; global Context metrics govern call/tool counts. Actual output size, FT/core/support/unresolved/gaps/closure/source chars, elapsed time and all raw stages are retained per trial.

| Set / Config | Model calls | Tools | Prompt tokens | Completion tokens | Total tokens | Mean hard gaps (observed Context only) | Mean source chars | Mean seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| blind_synthetic / A | 121 | 248 | 1,008,669 | 114,945 | 1,123,614 | 14.0 | 24,518.8 | 258.5 |
| blind_synthetic / B | 16 | 29 | 114,682 | 16,432 | 131,114 | 1.0 | 16,333.0 | 135.5 |
| blind_synthetic / C | 179 | 346 | 1,383,808 | 136,921 | 1,520,729 | 8.0 | 22,152.8 | 190.6 |
| blind_real / A | 101 | 186 | 777,826 | 35,278 | 813,104 | 8.0 | 88,198.3 | 129.3 |
| blind_real / B | 135 | 277 | 1,226,478 | 52,484 | 1,278,962 | 14.8 | 93,201.8 | 142.6 |
| blind_real / C | 68 | 127 | 536,543 | 26,298 | 562,841 | 9.5 | 80,058.0 | 146.4 |

## 14. Limitations

只有五个重复样本/配置/模式，非独立第三方持有的盲集；由实现者在 freeze 后创建，仍有 pattern selection bias。四个真实项目均为 C，没有 C++ 项目效度；显式 target 和原始 source slice 不支持 entry discovery recall。六个固定 ASan/UBSan replay 输入不证明 coverage 或穷尽正确性。

人工 annotation 及自动 necessary-contract checker 可能遗漏不变量；unverified 的 reader/allocator/field values 不能当作成功。A/B 是 evaluation-side projection intervention，预算相同不代表调查/evidence 相同。指标未控制 provider 时间变化和硬件噪声。若这一批失败以后参与规则修改，必须换新的 blind set，保留本批。

## 15. Which capabilities generalized?

完整配置 C 中具有已检查必要契约且 runtime 通过的模式：尚无已充分验证的 positive pattern。

这些是 observed capability，只有在重复成功和独立语义证据都足够时才支持对应模式泛化；不能推广成 framework generalizes across C/C++ projects。

## 16. Narrow deterministic proof subset

creator_return 仍要求无参数精确 calloc creator、单来源、非逃逸字段 consumer 和唯一 cleanup；public_callback_object 仍要求完整公开 layout、可显式初始化所有字段和同步非逃逸；cleanup_consumption 仍要求精确单参数 free wrapper及已有独立 owned producer。它们的 zero hit 或少量 hit 应如实解释为 recognized subset，而非修改规则提高 benchmark。

最终原始 summary、preregistration、源码归档、每次日志/annotation digest/evaluation.json 均在本地 artifact 目录。报告没有替换失败，也没有把 development 数据混进成功率。

复现（需先创建新的 freeze/output 和新盲集；禁止对已反馈到算法的本集继续称 blind）：

```bash
.venv/bin/python -m scripts.blind_eval.freeze --output artifacts/<new-frozen-output>
.venv/bin/python -m scripts.blind_eval.runner --output artifacts/<new-frozen-output> --repetitions 5 --workers 4
.venv/bin/python -m scripts.blind_eval.report --input artifacts/<output> --output docs/BLIND_GENERALIZATION_EVALUATION.md
```

原始 automatic false-complete flag 中的 callback_setter/C/4 尚未确认：公开栈对象和字段初始化是合法替代路线，原 annotation/checker 过度约束 creator/setter，且 callback field alias 未完整匹配。见 observed_failures.json。
