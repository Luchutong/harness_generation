# 固定 fingerprint 的 fresh 稳定性复测报告

当前实现状态：G 三个同身份分次登记组已完成 17/20，H 独立 callback 组完成 3/3；当前 Main 的 I 候选事务与回滚修改只做静态检查，测试继续暂停。新实现尚不能作为稳定性结果，见 [候选事务与回滚报告](CONTEXT_REPAIR_TRANSACTION_REPORT.md)。以下各版本原始失败和分母保持不变。

后续进展（2026-10-05）：下面保留原 fingerprint 的历史结果。正式 A 为 9/20、B 为 7/20、C 为 16/20、E 为 12/20，均未达到稳定目标。F 完整回归 1527 项通过并合入主工作区，正式 fresh 已完成 **18/20**：JSON5 为 5/5；callback、owned return 各 2/3；shared、out parameter、memory stream 各 3/3。两项失败分别停在代码 callback 绑定校验和 Context 长度契约闭合，整批尚未稳定，同身份追加确认批次未启动。新修复、预算内回退及独立重复验证见 [框架稳定性修复报告](STABILITY_FRAMEWORK_REPAIR_REPORT.md)；Context 定向修订见 [闭合反馈报告](CONTEXT_CLOSURE_FEEDBACK_REPORT.md)。离线回放不会补算原 fresh 成功。

日期：2026-10-04。实际执行时间（Asia/Shanghai）：09:45:38–10:20:02，约 34 分 23 秒。

## 结论

按 JSON_PARSE_END_TO_END_REPAIR_REPORT.md 固定当前生产代码，完成 20 次独立 fresh 全链：先做 json_parse 5 次，再对五个结构不同的已知开发样例各做 3 次。**当前未达到稳定成功目标。** JSON 为 3/5，结构样例为 4/15。所有失败保留，没有失败重试、resume、手填语义事实或更换生产版本。

每类 n=3、JSON n=5 仅是描述性观测，不能估计长期稳定成功率；没有单因素反事实重放，成功/失败间的差异不能视为独立因果效应。

7 次进入生成的运行全部通过 frozen Plan、模型翻译、code validation、build 和 runtime：28 条编译/链接命令及 42 个 ASan/UBSan/leak-check 固定输入全部通过。失败集中在 Slice 和 Context；下游条件性的 7/7 不能代表全链稳定。

## 身份、预算与样例

- 生产 fingerprint：`f34899aa9221087c9a92f3c1989826264591983fcdcac129c4146c81d80d0b41`。算法为 160 个生产文件 hash map 的 sorted compact JSON SHA256，与原报告一致。
- 框架：v0.2 / `59b6afb55e382eec3c62427e3273502455315285`；目标：`/home/luchitong/work/json-parser` / `9d50ae5ea2cdeef3b75146c621ec7b26e2e3642f`。
- 执行代码来自新的 frozen 快照，另冻结并审计 `project_catalog.py`。当前及 frozen 的 160 个生产文件、目标 57 个文件全部匹配；目标 HEAD/status 不变。
- Provider 为 openai-compatible，请求 ark-code-latest，所有实际响应为 deepseek-v4-flash-ga-260731，thinking disabled；2 workers。所有 JSON 完成后才开始结构样例。
- 每次使用独立 parser-only artifacts；Candidate → Validation → Slice → Minimal FT → Context → Plan → C/C++ → build/runtime 全部走真实链路。

预算保持原值：Validation/Slice 6 rounds、24 tools、48k source chars、4096 output；Context 24 model calls、64 tools、96k source chars、16 discoveries、depth 2、每 requirement 4 rounds、3 次 completeness pass、1 次 terminal repair、8192 output。代码翻译 8192 output、temperature 0.2。Agent timeout 60 秒，代码翻译 timeout 120 秒。20 次已保存配置均与 registration 匹配。

五类样例使用 scripts/smoke_argument_graph.py 既有 CASES，以及已退役为开发回归用途的 benchmarks/blind/synthetic/memory_stream/source/api.c。保持源码和入口名称不变，完整来源/SHA256 在 registration.samples。JSON 属于 known-project-development-regression；结构样例是已知合成开发 fixture，memory stream 不代表真实文件 IO。

本轮 schedule/samples 是计划的权威列表；registration 继承的 baseline cases 字段只记录原 JSON 样例。

| 样例 | 入口 | 结构覆盖 | 全链通过 | 三次 hard gaps |
| --- | --- | --- | --- | --- |
| callback_context | `api.c:8:parse` | 实际 handle callback、creator 返回 userdata、精确 ABI/同步调用 | 0/3 | 39 / 28 / 26 |
| shared_context | `api.c:7:parse` | a/b alias；acquire → supply → parse → dispose；保留输入指针 | 1/3 | 25 / 4 / 0 |
| owned_return | `api.c:4:parse` | owned Result 返回；observe 再消费；dispose 精确返回对象 | 1/3 | 34 / 2 / 0 |
| out_parameter | `api.c:7:parse` | State **out 输出存储、Options 零初始化、creator/cleanup | 2/3 | 5 / 0 / 0 |
| memory_stream | `api.c:8:sv_parse_stream` | open_memory → 循环 read → close；局部数组/sizeof 容量 | 0/3 | 55 / 55 / 78 |

## JSON 的稳定性

Candidate validation 5/5 accepted；Slice 3/5 可消费、2/5 invalid。有效 Slice 的 CORE 均只有 json.c:1125:json_parse，unresolved 数量为 10、6、5；失败 fallback 为 8、12，完整 Slice 输出有方差。

到达 Context 的 3 次全部 complete/frozen：hard gaps 0、12/12 mandatory roots closed、frontier 为空、支持 API 均为 json_value_free。每次 Context 都用 2 model calls、23 tool calls、57,219 source chars。Plan/build/runtime 各为 3/3；两次 Slice 失败未到达这些阶段，不能计为零 hard gaps。

成功 Plan 的 canonical 执行绑定三次一致，并与历史成功一致：json=fuzz_bytes、length=fuzz_size、cleanup=value 的 resource_reference 精确指向 owned CORE return。归一化 binding signature 为 `ac4423ccca3f3a8c3637b424ff4e67cde37f05f2a919d91ad3fe41e2d6f73ed4`。

完整 Plan 去掉 ID/证据噪音后仍有 3 个 annotation 变体：length 的 input_binding 分别为 fixed_scalar/fuzz_data/direct、fixed_scalar/derived/none、以及缺省；canonical recipe 都绑定 size。三个 fresh Plan 的 error_cleanup=false，历史成功为 true。因此只能说 canonical 绑定稳定，不能说完整 Plan 一致。历史成功仅作对照，不计入本轮分母或成本。

最终签名投影保留调用顺序及每条 ordering edge 的起点/终点，只对边集合排序。复核发现并修正了初版 collector 对边内部排序的问题；最终 metrics 与归档 collector 已重新生成，原始 Plan 和执行记录保持原样。

JSON 总成本：54 model calls、152 tool calls、1,025,071 tokens，单次总 tokens 130,627–286,360。供应商请求错误 0，但发生 terminal_schema_error 与 output_truncated 各一次恢复。

## 逐 trial 结果

Calls/tools 为全链预算计数；tokens 为已保存成功响应的实际用量。“—”表示 Context 未进入，不代表 hard gaps=0。完整的分阶段计数、source chars、hard gap 主体/证据、roots/frontier、Plan 签名和 provider events 在 metrics.json。

| Trial | Slice | Context 终态 | Hard gaps | Model / tools | 已知 tokens | Provider 失败 | Build / runtime |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| json_parse_r01 | invalid | 未进入 | — | 9 / 15 | 130,627 | 0 | 未进入 |
| json_parse_r02 | valid | complete | 0 | 13 / 42 | 274,107 | 0 | passed / passed |
| json_parse_r03 | valid | complete | 0 | 12 / 41 | 286,360 | 0 | passed / passed |
| json_parse_r04 | invalid | 未进入 | — | 10 / 17 | 145,758 | 0 | 未进入 |
| json_parse_r05 | valid | complete | 0 | 10 / 37 | 188,219 | 0 | passed / passed |
| callback_context_r01 | valid | invalid_context | 39 | 17 / 27 | 271,747 | 2 | 未进入 |
| shared_context_r01 | valid | completeness_budget_exhausted | 25 | 17 / 25 | 230,087 | 1 | 未进入 |
| owned_return_r01 | valid | invalid_context | 34 | 16 / 19 | 438,775 | 0 | 未进入 |
| out_parameter_r01 | valid | completeness_budget_exhausted | 5 | 16 / 23 | 317,656 | 0 | 未进入 |
| memory_stream_r01 | valid | completeness_budget_exhausted | 55 | 29 / 31 | 1,030,146 | 0 | 未进入 |
| callback_context_r02 | valid | invalid_context | 28 | 23 / 34 | 430,371 | 1 | 未进入 |
| shared_context_r02 | valid | completeness_budget_exhausted | 4 | 13 / 21 | 323,488 | 0 | 未进入 |
| owned_return_r02 | valid | completeness_budget_exhausted | 2 | 12 / 16 | 190,543 | 0 | 未进入 |
| out_parameter_r02 | valid | complete | 0 | 13 / 18 | 287,315 | 0 | passed / passed |
| memory_stream_r02 | valid | completeness_budget_exhausted | 55 | 21 / 29 | 584,689 | 0 | 未进入 |
| callback_context_r03 | valid | completeness_budget_exhausted | 26 | 23 / 37 | 481,088 | 1 | 未进入 |
| shared_context_r03 | valid | complete | 0 | 13 / 20 | 315,982 | 0 | passed / passed |
| owned_return_r03 | valid | complete | 0 | 13 / 22 | 235,654 | 0 | passed / passed |
| out_parameter_r03 | valid | complete | 0 | 15 / 21 | 303,769 | 0 | passed / passed |
| memory_stream_r03 | valid | invalid_context | 78 | 18 / 30 | 481,494 | 0 | 未进入 |

到达/通过分母：Candidate validation 20/20，Slice 18/20，Context 7/18，Plan 7/7，build 7/7，runtime 7/7。11 个失败 Context 均被 Gate 阻止，代码模型调用 0；另外 2 次 Slice 失败未进入后续阶段。worker_exit=0 只表示 worker 正常保存终态，成功按 stage_exits、Gate 和 runtime 判断。

out_parameter 两个成功 Plan 的严格签名和 binding signature 也各有两种变体；binding projection 唯一差异为 resources[0].reuse=per_context / per_input。两份代码通过当前检查，但这一生命周期 annotation 的不一致仍需规范化并重测。shared_context、owned_return 各只有一份成功 Plan，无法确认其成功 Plan 的重复稳定性。

## 成本和 provider events

| 阶段 | Model calls | Tools | Source chars | Prompt tokens | Completion tokens | Total tokens | Responses / failures |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| candidate-validate | 77 | 86 | 122,800 | 246,947 | 18,485 | 265,432 | 77 / 0 |
| semantic-slice | 75 | 160 | 300,781 | 895,402 | 61,986 | 957,388 | 75 / 0 |
| harness-context | 154 | 279 | 309,335 | 5,311,123 | 305,152 | 5,616,275 | 149 / 5 |
| context-generate | 7 | 0 | 0 | 107,107 | 1,673 | 108,780 | 7 / 0 |
| 总计 | 313 | 525 | 732,916 | 6,560,579 | 387,296 | 6,947,875 | 308 / 5 |

5 个失败请求均为 Context timeout：callback r01 两次、r02 一次、r03 一次，shared r01 一次。没有已保存的 HTTP 400/429/5xx 错误。timeout 的 usage 未知，6,947,875 tokens 是已知用量下界；未知用量没有计成零。7 次代码生成用量全部保存。

另外保存 9 条 execution_error、7 条 schema_error、2 次 protocol_recovery（terminal_schema_error 1、output_truncated 1）。这些事件可能描述同一次失败，不能相加为请求数。没有 model_error=budget_exhausted 事件，但有 completeness 预算终止：memory r01/r02 均完成 3 轮 completeness，Context 调用分别 22/12，未耗尽 24 次模型调用上限。

去重依据 Context attempt 的 group_cost_owner 与 response_id，排除根目录 latest trace 副本及同组 requirement 复制。预算 model/tool/source counters 与原生事件计数分开保存；bootstrap/evidence reuse 不能直接累加为 provider 原生 tool 调用。独立审计核对了所有 Context token/model totals、308 个互不重复的 response IDs 和全链 token 总额。

## 缺口和成功对照

1. **Slice 终态 schema。** JSON r01 的 unresolved json_parse_ex/new_value/hex_value 都没有 open_questions，修复只补第一项。r04 先输出截断，再对同一 cleanup 函数同时选 unresolved/exclude，违反唯一函数身份。应一次列全缺失项并明确每函数只选一个 choice，保留现有严格校验。
2. **已有能力的模型契约选择不稳。** out r01 的 dispose.s=owned/release_api=null 留下一项 ownership 叶子并连带 5 gaps；r02/r03 用 transferred 均成功，lifetime 并非决定性差异。shared r02 将保存给后续 parse 的 supply.src 标为 borrowed/during_call；r03 改为 borrowed/until_release 后 26 roots 全闭。
3. **owned-return 字段输入依赖已有实现。** owned r01 长度参数存在 input/derived 构造冲突；r02 把 observe.r 的输入依赖声明为 not_applicable。r03 正确选择 source=context、via=parse，现有 input_dependent_returned_fields 桥接闭合 19 roots。不能把这些失败误报为 cleanup 或字段桥接能力不存在。
4. **callback 间接身份和提案退役。** 部分 trial 有旧 input/creator 或 cleanup API/mandatory 提案冲突。r03 即使只保留正确 creator，已证明的 parse.user→handle.user forwarding 仍未将间接 endpoint 归一到 acquire 的同一资源，产生 semantic_recipe_unverifiable。四次 callback timeout 是额外影响，不能解释全部缺口。
5. **stream canonical 构造。** r01/r02 有相同 10 个最小 frontier/55 gaps：creator data/size fuzz roots、reader 与 parser 的共享 stream 身份、局部 out[4]/sizeof(out) 容量与内部循环 reader 调用。resource_identity 已观察到 guarded open→parse→close origin；缺的是 canonical 构造投影和内部 reader 连接。r03 的 creator-return creation.api=null 与同资源 parser creation.api=open_memory 冲突，1 轮后 invalid、78 gaps。三次均无 provider 错误。
6. **Plan 规范事实。** JSON 绑定一致但完整 annotation 有方差；out 的 reuse 不同。应区分规范执行/生命周期事实与证据、ID 噪音，并在新 frozen 版本重测。

详细 obligation/fact/resource IDs、最小 frontier、原始 trace 路径及成功对照见 failure_analysis.json / failure_analysis.md。上述建议是本轮诊断，没有修改固定生产代码或把失败补写为成功。

## 审计与下一步

最终 independent_audit complete=true、audit_passed=true：20/20 运行身份完整，当前/frozen/target hashes、预算和 provider 匹配，Gate 拦截所有不完整 Context，通过的 mandatory roots 全闭、Plan frozen、code_origin=model_translation，7 个 build/runtime 通过。文本 artifacts 的实际凭证字面量扫描 0 hits。审计通过代表记录可信，不代表成功稳定。

结果属于已知项目与合成开发回归，不能推断 Candidate recall、跨项目泛化或覆盖提高。Runtime 仅为每个 harness 的六种固定输入；没有把旧报告的额外 21 个回放和 2000 次 fuzz 算入本轮，也未证明长期/跨输入生命周期安全。

先修复终态诊断、source-backed ownership/lifetime/input-pair 选择及冲突退役，再连接 callback 间接身份和 stream 构造证书并规范化 Plan。修复要使用新 fingerprint、单独重复这组小规模样例；本轮记录不混入新版本成绩。当前没有扩大泛化实验的依据。

## 记录和复现

Artifact root：`/home/luchitong/work/harness_generation/artifacts/fresh_stability_f348_20261004`。

- registration.json：160 个冻结生产文件、计划、fixture 来源/SHA256、模型和预算。
- metrics.json / cohort_report.md：全部阶段、hard gaps、调用/token、条件分母、Plan signatures。
- 各 trial 的 artifacts/provider_events.json：去重后的供应商、协议和校验事件。
- independent_audit.json、completion_audit.json、environment.json、secret_literal_audit.json：独立核对、最终身份、依赖版本和文本凭证扫描。
- failure_analysis.json / failure_analysis.md：13 个失败及成功对照的具体证据。
- 使用的 runner/collector/auditor 已复制进 artifact root。

复现需要工作区已有 `.env` 配置（LLM_API_KEY、LLM_BASE_URL、LLM_MODEL、LLM_THINKING）；归档不包含凭证。

```bash
cd /home/luchitong/work/harness_generation
.venv/bin/python scripts/repeat_fresh_stability.py \
  --output artifacts/fresh_stability_f348_NEW \
  --json-repetitions 5 --sample-repetitions 3 --workers 2
.venv/bin/python scripts/collect_fresh_stability.py \
  --experiment-root artifacts/fresh_stability_f348_NEW
.venv/bin/python scripts/audit_fresh_stability.py \
  --experiment-root artifacts/fresh_stability_f348_NEW --require-complete
```

输出目录须全新；runner 只接受与原成功报告匹配的生产文件，每次前后审计身份。生产修复后应为新 fingerprint 重新注册实验，不复用本轮分母。

后续框架修复、新 fingerprint 的验证与全部开发 smoke 记录见 [框架稳定性修复报告](STABILITY_FRAMEWORK_REPAIR_REPORT.md)。本报告保留原 `f348` 的 20 次结果，后续实验不改变这里的成功分母。
