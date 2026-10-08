# json_parse 当前版本真实模型测试

日期：2026-10-03。目标：`/home/luchitong/work/json-parser` 的 `json_parse`，入口 `json.c:1125:json_parse`。

**本轮未生成 harness。fresh 全链通过 Candidate Validation，但 Slice 引用了已失效的历史 choice ID；固定历史 Slice 后的 fresh Context 闭合 8/15 个必需根，仍因 cleanup、内部支持 API 的参数、callback 和顺序缺口被 Gate 阻止。19 个真实模型响应均为 HTTP 200，没有 timeout、400、429 或本地进程崩溃。**

本次仅测试和收集结果，没有修改生产实现，没有放宽 Gate，没有启动 blind cohort。

## 测试设置与归因边界

- 本地分支：`v0.2`；HEAD：`59b6afb55e382eec3c62427e3273502455315285`，包含当前未提交实现。
- 执行前冻结 160 个生产源码/配置文件，所有测试使用冻结副本。fingerprint：`3d7cdf9c17d259271d7e42df8faa0b0e2bac5354eca30285f4fe9114845e47ea`。
- 目标 HEAD：`9d50ae5ea2cdeef3b75146c621ec7b26e2e3642f`；目标 57 个文件的哈希在测试前后相同，目标 Git 工作区保持干净。
- 使用仓库 `.env` 的供应商配置。请求模型 `ark-code-latest`，实际响应 `deepseek-v4-flash-ga-260731`，thinking disabled。
- Python 3.12.3、OpenAI SDK 2.54.0、tree-sitter 0.26.0、tree-sitter-c 0.24.2、Clang 18.1.3。
- 静态起点为 parser-only：扫描 `json.c`、`json.h`、`examples/*.c`、`tests/*.c`，得到 27 个函数；annotations、flows、SFG 均为空，不注入手写语义。
- Validation / Slice：6 rounds、24 tools、48,000 source chars、4,096 output tokens；Slice 最多发现 32 个函数。
- Context：grouped，24 model calls、64 tools、96,000 source chars、16 discoveries、depth 2；每 Requirement 4 rounds，最多 3 completeness rounds、1 terminal repair，输出上限 8,192 tokens。
- Context policy / prompt / tools：`source-grounded-harness-context-v6` / `source-grounded-context-agent-v20` / `ft-scoped-repository-v10`。

共两个不同条件，每个条件一次，不合并为重复成功率：

1. **fresh 全链**：人工选定公开入口，Candidate Validation 和 Slice 均真实调用模型。入口选择不是 Candidate recall 实验。
2. **固定上游组件**：fresh Slice 失败后，保留历史真实 Slice 的角色与未决项，重新签发当前源码证据，重算 CORE proof，并显式迁移 Slice policy header。当前 Minimal FT validator 通过后，重新进行真实 Context 调查。没有手写 Context facts，没有回放模型回答，不记为 fresh Slice 成功。

旧 policy header 首次被当前 FT 校验拒绝，发生于准备阶段，模型调用为零；该材料保留在 `fixed_upstream_header_rejected/`。迁移经过当前 FT 校验，未复用 invalid 的 fresh Slice。

这是已经多轮开发使用的真实项目样例，属于 Development / Regression；不是盲测，也不足以推断稳定性或跨项目泛化。

## 逐阶段结果

| 条件 | Candidate | Slice | Minimal FT | Context | Plan / harness / compile / runtime |
|---|---|---|---|---|---|
| fresh 全链 | accepted | invalid：`slice_role_choice_not_issued` | 未进入 | 未进入 | 未进入 |
| 固定历史 Slice，fresh Context | 历史角色来源 | 保留历史未决项，当前证据重算 | CORE 1、SUPPORT 1，`completed_with_unresolved` | incomplete，8/15 必需根闭合，14 条 hard-gap 报告行 | `context-generate` 被 Gate 阻止，代码模型调用 0 |

目标 `json.c` 独立 C 编译通过。这不是生成 harness 的编译成绩。本次没有 harness 编译、runtime、fuzz 或 coverage 成绩；未执行的阶段不计为执行失败。

## 本轮定位的问题

### 1. Slice 的候选身份随证据变化而失效

Slice 第四次响应达到 4,096 token 输出上限，触发既有 protocol recovery；第五次响应正常调用 terminal tool，但提交了四个旧 choice ID：对应 `json_value_free_ex`、`process_object`、`process_value`、`process_array`，均为 unresolved 选择。

这四个 ID **确实曾在当前真实对话中由框架签发**，不是模型凭空编造；新增证据后，它们不再属于最终候选集合。`choice_id` 的哈希包含 evidence IDs，因而同一个函数和角色会随着证据更新获得另一个 ID。模型引用旧集合，最终触发 `slice_role_choice_not_issued`，整份分类被拒绝。

本轮的最终失败不是单纯的输出截断：截断被恢复后，动态身份失效仍阻止了 Slice。fallback 中仅保留的 anchor 没有被当成有效 Slice 继续构建 FT。

证据：[候选身份诊断](../artifacts/json_parse_native_20261003T050716Z/slice_choice_diagnostic.json)。下一步应将稳定的语义主体身份与证据修订分开，或显式保留并重新校验历史签发选择；不得接受任意未知 ID。

### 2. 内部委托被提升为 harness 必需支持 API

固定上游 FT 的 SUPPORT 是 `json_value_free`。Context 随后将 `json_parse_ex` 选择为 required creation API，`required_by=json_parse`；最终 API Closure 包含 CORE `json_parse` 和 REQUIRED SUPPORT `json_parse_ex`。

实际入口自己构造 `json_settings settings = {0}`，并调用 `json_parse_ex(&settings, json, length, 0)`。因此，仅调用公开 `json_parse` 的 harness 不需要再显式调用一次 `json_parse_ex`。**本轮结果提示，源码证明需要的内部实现依赖与 harness 需要独立调用的 API 仍存在边界混淆。**

这次扩展新增了 `json_parse_ex` 的输入绑定、长度、callback 和 lifecycle 义务，并产生 required-support ordering 缺口。该判断基于本轮源码和实际 Closure，不是消融实验；不能把所有失败都归因于这一项。后续应先区分内部委托证明和外部调用义务，再重测预算使用。

### 3. 完整源码取得仍未转化为 cleanup 消费证明

最终 evidence 能重算 `json_parse_ex`、`json_value_free`、`json_value_free_ex`、`default_alloc`、`default_free` 等完整定义，扫描的五个源码文件均通过认证。本轮已经取得 `default_free`，不能继续将失败归结为没有找到 deallocator 源码。

但 Context 没有签发 canonical `cleanup_consumption`，也没有产出 callback binding diagnostic。复合 JSON 资源的释放涉及间接 `mem_free`、while/switch、parent/child 遍历、指针重赋值与多类子存储，当前证据仍不足以被受支持的证明机制接受。

Agent 曾提出返回资源由 `json_value_free` 必须清理，但该 lifecycle 行不属于当前签发的候选，被 schema 拒绝。随后接受的 `json_parse` lifecycle 提案仍带 `cleanup.mandatory=false, api=null`。Gate 最终保留 `mandatory_cleanup_unresolved`，没有因这个 resolved 提案就允许生成。

此外，`json_parse_ex` 的 argument / length / callback 提案被拒绝为 `semantic_fact_requires_untruncated_subject_source`。全局证据包含完整函数，不代表这些提案引用的证据子集充分；后续需要核查源码组合证明与提案引用之间的复用边界，不能直接断言 validator 误阻塞。

### 4. 此轮未验证完整的事实纠正路径

最终 `validation_errors=[]`，未出现 `subject_repair_conflict` 或 `conflicting_resource_identity`；但是 `retired_semantic_proposals=0`，`subject_repair_history.withdrawals=[]`。

这意味着本轮没有复现上一轮的修复冲突，也没有实际完成“错误提案进入 active facts → 取得充分的新证明 → 撤回旧提案”的完整路径。正确 cleanup 提案在签发校验处就被拒绝，不能据此宣布主体修复已经得到真实模型验证。

## Closure 与成本

| Context 指标 | 结果 |
|---|---:|
| 全部 obligation nodes | 37 |
| proved / missing / blocked nodes | 25 / 10 / 2 |
| 必需根闭合 / 未闭合 | 8 / 7 |
| hard-gap 报告行 | 14 |
| Model calls | 11 / 24 |
| Tool calls，包含框架读取 | 33 / 64 |
| Source chars 已计费 | 91,400 / 96,000 |
| Completeness rounds | 1 |
| Bootstrap source reads / evidence reuses | 4 / 10 |
| 跨义务复用的不同 evidence IDs | 21 |
| 显式源码查询 / 完全相同的重复查询 | 12 / 2 |
| Canonical cleanup sources | 0 |
| 终止原因 | `max_source_chars` |

下一次读取会超过剩余源码预算，因此在已计费 91,400 字符时停止；不是模型调用预算耗尽。14 条 hard-gap 行包括依赖传播和同一义务上的不同问题，不是 14 个独立未闭合根。

hard-gap code：`mandatory_cleanup_unresolved` 2、`argument_input_binding_unresolved` 4、`callback_contract_unresolved` 2、`mandatory_requirement_unresolved` 5、`required_support_order_unresolved` 1。

| 条件 | 成功供应商响应 | Prompt tokens | Completion tokens | Total tokens | 用时 |
|---|---:|---:|---:|---:|---:|
| fresh 全链 | 8：Validation 3、Slice 5 | 91,426 | 6,301 | 97,727 | 62.06 秒 |
| 固定上游 fresh Context | 11 | 467,311 | 29,649 | 496,960 | 313.96 秒 |
| 合计 | 19 | 558,737 | 35,950 | **594,687** | — |

按 `response_id` 去重，并排除 grouped Requirement 重复发布的 traces；历史 Slice 的调用和成本不计入本轮。19 个响应全部 HTTP 200，包含一次 `finish_reason=length`；无供应商错误，无 SIGSEGV。不能由本轮推断此前 provider 400 或 native crash 根因已经修复，也不能从一次查询统计得出调查效率提高。

## 结论与后续顺序

真实 `json_parse` 的调用表面简单，但当前流水线仍未在本轮自动产出可验证的 harness。Gate 正确保留缺失证明并阻止生成，主要阻塞点在 Slice 身份稳定、内部实现依赖的调用边界，以及 cleanup 证明到签发候选的连接。

建议先修复稳定 choice 身份，再收紧内部委托的 closure 分类，最后围绕实际 cleanup 对象与调用点验证已有源码证明能否被复用和签发。保留这一冻结版本和原始轨迹作为回归材料，完成可归因的离线检查后再进行少量 targeted native 复测；目前不扩大 blind 实验。

原始材料：[manifest](../artifacts/json_parse_native_20261003T050716Z/manifest.json)、[evaluation](../artifacts/json_parse_native_20261003T050716Z/evaluation.json)、[schema errors](../artifacts/json_parse_native_20261003T050716Z/context_schema_errors.json)、[完整链日志](../artifacts/json_parse_native_20261003T050716Z/native_full.log)、[Context 日志](../artifacts/json_parse_native_20261003T050716Z/native_fixed_json_parse.log)、[integrity](../artifacts/json_parse_native_20261003T050716Z/integrity.json)。原始 artifacts 属于本地实验产物，按仓库规则不进入 Git。

冻结源码和生产文件哈希未变化，目标源码未变化，实验文件未包含 API key 值。此次为测试与文档更新，没有运行新的完整 pytest；之前的离线回归数量不计为本轮验证。
