# Subject Effect 与共享 Input Binding 重构

2026-10-01，基于当前本地 `v0.2`。本轮针对上一轮 30 次 native 的三个边界问题：自由 Slice role/reason、只有类型关系的 SUPPORT，以及 input/length、out cell/pointee 的重复或混淆身份。没有新增 Agent 工具，没有增加预算，没有启动 blind cohort。

最终代码离线回归 **410 passed**。本轮共完成 10 次 fresh native，分属三个冻结版本：首版六类的 Context/compile/runtime 为 **4/6**，中间约束版三例为 **0/3**，修正后的最终版本仅重测 shared-context，为 **1/1**。最终 shared-context 已跑通 `create → feed → parse → destroy`，硬缺口为零；其余类别没有在最终 fingerprint 下重跑，不能把首版成功率当作最终版成功率。callback 尚未得到端到端成功证据。

## 角色与 SUPPORT 提案

Slice native terminal 改为 `choice_id + open_questions`。框架根据当前已签发源码生成 anchor、具备 inclusion proof 的 CORE、具有实际 source effect 的 SUPPORT、已读完整源码的 EXCLUDE 提案，以及 UNRESOLVED。角色、reason 和证明 evidence 由框架展开；模型负责选择，不能通过换 reason 获得一个不存在的 CORE/SUPPORT 候选。EXCLUDE 仍是模型的语义判断：完整源码使该提案可提交，并不自动证明目标之外的行为。未知 API 不会被自动排除。

SUPPORT registry 从 signature profile 改为 exact subject effect：pointer return、out-parameter write、parameter release、目标读取字段的写入，以及 callback processing/registration。候选记录 parent、参数/return/pointee、pointer depth、API 参数和 fields。事实选择的实际 subject 必须匹配候选；canonical dependency 与 API Closure 保留该绑定，不再只记录函数和 role。纯调用链 wrapper 无法凭 byte-pointer 参数兼容成为 configuration。

这些是可重放的有限源码关系，不是所有路径上的必要性证明。`necessity_proven=false` 保留；ownership、状态、实际资源身份和调用顺序仍需独立验证。当前返回指针与 out write 可证明机制存在，不能单独证明有分配、唯一 origin 或 mandatory invocation。复杂别名、间接 setter、C++ 构造器或未知布局仍可能无法签发关系，必须保持 unresolved。

## 参数与资源契约组合

同组 native `buffer_length` 复用 `input_binding` 的同一个 buffer/extent 选择，长度参数、NUL 和 binary-zero 约束只填写一次，框架投影为独立可读 facts。`relation` 与 `element_type` 仍由该 predicate 提出，单位矛盾会保留并阻止生成。单独调查及旧 expanded fixture 经过原有严格校验，不会静默覆盖矛盾。新增 `input_length_binding` 投影记录一致性与诊断，Gate 消费其冲突。

源码中的索引和控制条件只提供 input/length 候选提示，不能自动把 flag 或 offset 认作 extent。真实绑定仍由 semantic proposal 选择，按完整主体源码验证。

ownership 的 resource 枚举与声明 pointer depth 对齐。`PointerParameter` 的 `T **` cell 无法选择 `T *` 产出对象的 origin；`OutParameterPointee` 保留独立主体与 ID。Canonical out storage recipe 需要对象 ID 以生成 `&object`，其 argument view 现在使用 `resource_id=null` 与独立 `pointee_resource_id`；Plan 验证该 pointee 的生命周期，再形成 out_resources。修复了原先把地址 cell 投影成对象 consumer、触发无对应生命周期缺口的问题。

bounded scalar 不再依赖 wrapper 进入 CORE。Graph 可以读取已签发的 excluded caller body 作为 evidence，但仍拒绝调用 excluded API。一个已选择的 direct input binding，可通过 caller 的精确 buffer 转发及未重赋值的 bounded min 表达式重现 input adaptation；External Input Flow 从裁剪前 fuzz size 追踪到 derived scalar。该 seed 表示 harness 构造策略，不断言任意 caller 参数原本就是 fuzz input。非直线控制流、buffer 位移、未知表达式、重赋值和不满足目标 mandatory bound 的 recipe 不会因此获得证明。

## 提示和输出开销

删除 seed/user 双重 registry，工具结果发送 registry 增量；完整目录仍保存在 metadata。Origin catalog 只用于主体约束和必要的 issued_origins，不再随目录反复输出。已闭合参数不再同时完整展开在 Graph candidates 和 canonical recipe 中；construction sources 限定到调查主体。metadata 保存投影前后字符数，供审计。

这减少了确定性的重复内容，不等于已经证明整链 token 效率或模型稳定性改善。Context 成功样本和早退样本应分别报告，不能把阶段未运行计作零成本成功。

## 离线验证

最终全量 **410 passed，86.10 秒**，`pip check`、`git diff --check` 通过。新增/调整回归覆盖签发 Slice choice、伪造 choice 拒绝、pure wrapper SUPPORT 拒绝、错误 target parameter、cell/pointee origin 深度、参数改名、共享 input/length 投影和重复 extent 拒绝、registry delta 重放，以及 construction/state 与 API role 的组合约束。

主体证据规则为：facts 必须包含本主体完整源码证据，同时可以补充其他已签发 API/caller 证据。terminal schema 允许已签发 evidence 枚举并要求包含主体 evidence；独立 semantic validator 再检查本主体完整 body 的实际证据成员。当前本地 schema 子集校验器不实现 JSON Schema `contains`，因此主体成员条件仍由 semantic validator 强制，不能仅凭 schema 枚举视为通过。回归明确验证“主体证据加补充证据通过”和“用补充证据替代主体证据拒绝”。

真实 clang 编译/运行的离线 fixtures 覆盖 creator-with-args、out storage，以及 parse 为唯一 CORE、wrapper 被排除的 bounded scalar。这些 semantic proposals 是明确标注的测试输入，不能计入 native 成功率。部分旧回归的预期改为更早拒绝无 release effect 的 API、以及允许机械 cleanup proof 避免冗余模型调查；没有放宽完整性 Gate。

## 冻结与 native 设计

最终 production fingerprint：`19fbf2ecdba1332e7aae649ea8065267ba1ad8b1da6c85d376f89cb64b16326b`。

每批单独归档 175 个 production/runtime Python 文件，manifest 保存每文件 SHA256；三批均确认运行期间 implementation unchanged，最终 manifest 另与当前源码核对一致。沿用上一轮预算：Candidate/Slice 6 rounds、24 tools、48k source chars、4096 output；Context 24 model calls、64 tools、96k source chars、16 discoveries、depth 2、3 completeness passes、1 terminal repair，Context/code output 8192。首批六类 workers=2，第二批三类 workers=2，最终单例 workers=1。无失败替换、无 Mock fallback、无提高预算。成功生成的 resume 检查独立记录，其 model calls 为零。

类别为 bounded scalar、creator-with-args、out-parameter、shared context、owned return、callback context。仍为合成 C fixtures、parser-only Phase 1、预选 parse anchor 的 Development / Regression；不评价 Candidate recall、真实项目 coverage 或跨项目泛化。此次是定向 fresh smoke，不是重复稳定性 cohort。

## Native 结果：三批独立版本

所有 trial 的 Slice 均 completed，得到的十份 FT 均未将 `usage` 纳入 CORE。不同 fingerprint 的通过率不合并，单次成功不能证明重复稳定性。

### 第一批：source effect 与组合契约

Fingerprint：`29be0064b560434b4130d3f4f1ca0284f8bae257cc4c415127ac7a1c731b2084`。该版本离线 408 passed。

| 类别 | Minimal FT 大小 | Context | hard gaps | Context model / tools | 整链 tokens | 编译 / runtime |
| --- | ---: | --- | ---: | --- | ---: | --- |
| bounded_scalar | 1 | complete | 0 | 3 / 6 | 64,795 | 通过 / 通过 |
| creator_with_args | 3 | complete | 0 | 12 / 32 | 239,076 | 通过 / 通过 |
| out_parameter | 3 | complete | 0 | 9 / 23 | 217,587 | 通过 / 通过 |
| shared_context | 4 | incomplete | 2 | 18 / 41 | 387,922 | 未运行 |
| owned_return | 3 | complete | 0 | 16 / 38 | 297,801 | 通过 / 通过 |
| callback_context | 4 | incomplete | 19 | 23 / 49 | 379,387 | 未运行 |

首批 Slice 6/6，Context/compile/runtime 4/6。bounded scalar 在 wrapper 被排除后仍能生成有界适配；out-parameter 的 cell 与 pointee 未再混作 consumer 资源。四个成功 harness 各运行六个固定 smoke 输入，恢复生成均零模型调用且文件摘要不变。

shared-context 的 active construction 已闭合，但 creator call order 未解决，creator return lifecycle 的 mandatory initialization 又没有对应 API；Gate 保留两项硬缺口并阻止生成。callback 仍缺 userdata 参数构造、callback contract、ownership、返回语义和顺序等。这些不是编译失败，而是 Context 阶段没有获得足够证明。

整链 **130 次真实请求尝试、129 个成功响应、1,586,568 tokens**；callback 有一次 timeout。记录六条 schema failure、十条主体完整源码 evidence 校验失败；这些是提案校验记录，不是六个失败 trial。已接受的 28 条 ownership entry 均通过声明 subject/origin 深度检查，47 条 dependency 均保留 source-issued candidate 与 subject binding；这仅证明边界约束可重放，不能证明所有语义选择正确。

39 个 Context cost-owner attempt 的 Graph + Canonical 提示投影由 186,932 字符减少为 115,294 字符，减少约 38.3%。这是该部分的实测序列化开销，不是整链 tokens 降幅，也没有和旧版本做随机配对成本比较。工具输出中完整 registry 为零、增量 registry 59 条；初始完整目录在 seed 中只发送一次。

### 第二批：约束收紧后的失败版本

Fingerprint：`60402011387af568a7c429ce71ffe1a81e5420bc87b94381862d743ea786411e`。

| 类别 | Slice | Context | hard gaps | Context model / tools | 整链 tokens | 编译 / runtime |
| --- | --- | --- | ---: | --- | ---: | --- |
| shared_context | completed | incomplete | 5 | 17 / 47 | 385,303 | 未运行 |
| callback_context | completed | incomplete | 18 | 24 / 54 | 363,674 | 未运行 |
| owned_return | completed | incomplete | 19 | 15 / 36 | 240,996 | 未运行 |

三例均未完成。整链 **76 次请求尝试、74 个成功响应、989,973 tokens**，callback 和 owned-return 各一次 timeout，六条 schema failure 记录。shared-context 的首次 terminal 与预算内 repair 都返回 malformed JSON；owned-return 也出现 malformed JSON。响应 finish reason 为 tool_calls，不能直接归因为 output 截断。

审计发现本版本把“必须包含主体源码”错误收紧为“只能包含主体源码”。callback 的两个提案已含主体源码，同时补充了 creator/callback API 的已签发证据，却被 evidence enum 拒绝。这是框架的误拒绝，最终代码已修正，并补充正反回归；原始失败结果保留，不通过事后重放改计成功。该错误也不能解释全部未闭合义务和 timeout。

### 第三批：最终代码的 fresh shared-context

Fingerprint：`19fbf2ecdba1332e7aae649ea8065267ba1ad8b1da6c85d376f89cb64b16326b`。最终离线 410 passed。

| 类别 | Minimal FT / CORE | Context | hard gaps | Context model / tools | 整链 tokens | 编译 / runtime |
| --- | --- | --- | ---: | --- | ---: | --- |
| shared_context | 4 / supply, parse | complete | 0 | 12 / 27 | 275,098 | 通过 / 通过 |

最终 shared-context 使用一个 creator resource 和独立的 input_fed invocation precondition，API Closure 完整。HarnessPlan 构建、模型仅按 Plan 翻译、clang 编译、六个固定输入 runtime 均通过；代码生成调用一次模型。Resume 零模型调用，生成文件和 upstream artifacts 摘要不变。19 次请求全部获得成功响应，无 request error、schema failure 或 execution-failed requirement；Context 部分为 219,086 tokens。

这是最终 fingerprint 的一次新鲜成功轨迹，不是首批 artifacts 的重新投影。该单例不能证明最终版本的 callback、owned-return 或其他类别重复稳定，也不能证明其相对首批减少 calls/tokens 的因果效果。

## Provider 与剩余问题

配置模型为 `ark-code-latest`，三批实际响应模型均记录为 `deepseek-v4-flash-ga-260731`。本轮未出现 HTTP 400 或 429，共三次 timeout。首批四次、第二批两次后续真实请求使用了 malformed tool history normalization 并取得成功响应；最终 shared-context 没有触发该路径。可以确认路径实际使用过，不能把“本轮没有 400”解读为供应商根因已消失。

下一瓶颈仍是 callback 的 userdata/input/ownership/lifetime 联合闭合，以及 terminal JSON 和证据选择的稳定性。source effect 只是机制候选，不能自动判定必需调用；mandatory 生命周期义务仍可能无法得到适当 semantic proposal。此轮没有新增任意 callback recipe 或 API 名称规则来掩盖缺口。

与上一轮 30 次的 Context 0/30 相比，本轮出现多类端到端成功轨迹，说明新边界具有工程价值。但样例数量、重复次数、fingerprint 和模型轨迹均不同，不能做显著性或跨项目泛化结论。保持完整 blind cohort 暂停；正式稳定性实验应在同一最终 fingerprint 下对每类做固定预算重复，再考虑真实项目覆盖率。

## 审计产物

Collector 与 independent audit 均为只读统计，不调用模型、不补 facts。audit 从各自归档源码导入规则，校验归档 SHA256，并核对 response ID 去重后的 tokens、ownership subjects 和 dependency bindings；不会使用最终代码重算首批成功。

| 批次 | 原始 native summary | 收集结果 | 冻结源码与离线记录 | 独立审计 |
| --- | --- | --- | --- | --- |
| 首版六类 | [summary](../artifacts/subject_effect_native_smoke_20261001/summary.json) | [report](../artifacts/subject_effect_results_20261001/report.md) | [manifest](../artifacts/subject_effect_validation_20261001/manifest.json) / [offline](../artifacts/subject_effect_validation_20261001/offline_validation.json) | [audit](../artifacts/subject_effect_analysis_20261001/audit.json) |
| 中间三类 | [summary](../artifacts/subject_effect_v3_native_smoke_20261001/summary.json) | [report](../artifacts/subject_effect_v3_results_20261001/report.md) | [manifest](../artifacts/subject_effect_v3_validation_20261001/manifest.json) | [audit](../artifacts/subject_effect_v3_analysis_20261001/audit.json) |
| 最终 shared | [summary](../artifacts/subject_effect_final_native_smoke_20261001/summary.json) | [report](../artifacts/subject_effect_final_results_20261001/report.md) | [manifest](../artifacts/subject_effect_final_validation_20261001/manifest.json) / [offline](../artifacts/subject_effect_final_validation_20261001/offline_validation.json) | [audit](../artifacts/subject_effect_final_analysis_20261001/audit.json) |

三份原始 summary 的 SHA256 依次为 `3e06308b82565a8598170537ea15c60b88cef9db4d9fe7c4ab9efa9015cb074b`、`24cf378470ef4562fa1d00fd2d88656cc2eaef704762ba95debe15adeb3796b7`、`c40c5a3e391bf41d69e1ebc1ce4030c56d46e32abee3eee93bdd79be04738725`。artifacts 保留在本地，不属于提交源码。

## 复现

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/smoke_argument_graph.py \
  --output artifacts/subject_effect_native_smoke_fresh --repetitions 1 --workers 2
.venv/bin/python scripts/collect_argument_graph_smoke.py \
  --smoke-dir artifacts/subject_effect_native_smoke_fresh \
  --output artifacts/subject_effect_results_fresh
```

历史 30 次结果保留在 [CORE / Proposal 报告](CORE_AND_PROPOSAL_BOUNDARY_REPORT.md)，不混合不同 fingerprint 的实验。
