# 证据驱动的主体修复报告

日期：2026-10-02。基于当前本地 `v0.2`；本报告描述[证明可靠性实验](SEMANTIC_PROOF_RELIABILITY_REPORT.md)之后的局部修复。历史冻结版本与真实实验数据保持不变。

## 1. 问题与修改

旧合并器允许 `unknown → known`，但同时保留同一主体的不同具体声明。它没有区分模型提案与已经闭合的证明，因此源码已否定的旧提案也不能退出 active facts。真实实验中，feed 的输入指针先声明为 `during_call`，随后改为 `until_context_cleanup`，两者仍同时进入 Gate。另一个 direct 样例将长度标为 input 和 derived；即使可下沉为同一个源码证明的 recipe，也被原始字段冲突拦住。

新增 `RepairProofEvaluator`，复用 Source Grounding、Canonical Construction 与 Semantic Obligation Graph。模型仍提交原来的 typed proposals，没有新增 Agent 工具、终态字段、contract 类型或预算上限。

## 2. 接受规则

| 情况 | 处理 |
|---|---|
| unknown 被具体值细化 | 合并兼容声明与已签发证据 |
| 旧提案被源码否定，替代声明取得闭合证明 | 只撤回该主体的旧 active fact，保留审计 |
| 旧提案未证明，候选中有唯一源码支持的结果 | 按证明选择；缺证明不标成源码反证 |
| 多个声明证明同一 canonical recipe | 合并等价证据；优先保留历史证明代表，否则按内容确定代表 |
| 历史已闭合的主体遇到非等价声明 | 保留双方并阻塞，回答顺序没有撤回权限 |
| 多个非等价结果都取得证明 | 保留冲突，不任选其一 |
| 替代声明缺证据、缺完整源码或结构校验失败 | 不撤回旧提案，继续阻止生成 |

候选验证临时替换同一 requirement 内的确切 parameter、return 或 field 主体，保留其余 facts，重建 Closure、Context 与义务图。临时投影不写入生产状态。通过后才修改 active facts，最终完整 Gate 仍必须重新通过。候选 facts 按规范顺序排序，避免投影自身触发 canonical identity 错误。

历史保护来自实际调查过程中重算后已经闭合的主体节点；临时候选的 `proved` 不会自动成为历史保护。修复一个主体不会删除其他主体及其证据。

## 3. 正向证明的范围

ownership 节点通过已有语义校验仍不足以授权撤回。本轮对 borrowed pointer lifetime 增加限定的源码检查：

- `during_call` 需要完整路径没有该指针逃逸、释放或未知调用效果。
- `until_context_cleanup` 需要把保留定位到确切参数对象的字段，并连接到已解析的 resource identity、必需 cleanup API、闭合的 cleanup invocation 和同对象释放效果。
- 返回、全局保存与未知逃逸不能当作 context 内保留。cleanup 读取被保留字段而指针效果尚未证明时，也不能授权撤回。

Source Grounding 内部增加保留行为的目标对象和字段，复用现有别名与有限深度调用分析，没有新增模型可选择的来源标签。完整 body、路径和深度边界继续生效。

state 替代声明需要同一对象的必需 incoming fields 已证明初始化；argument construction 使用已经闭合的 canonical parameter recipe。合法引用、非 unknown 枚举或更新的回答本身都不是正向证明。

## 4. 调查与审计

已知的声明冲突可在原配置的 completeness rounds 内继续调查。期间 Context 仍为 invalid，`generation_allowed=false`；未修复则拒绝冻结。结构、证据身份及其他 validation errors 立即停止。

每轮调查结束后再次检查保留的候选。creator/cleanup 等前提稍后取得证明时，可完成修复，无需模型重复提交同一事实。

`subject_repair_history.json` 保存 withdrawn fact、旧证明状态、替代 fact ID、替代证明、原因、源码 fingerprint 和不再被事实支持的 API dependency。文档纳入 publication digests，metadata 记录同一审计与可修复 invalid 轮次。缺证明与源码反证分别记录。

版本：Context policy v4、Agent prompt v17、Source Grounding v3、subject repair v2。Plan 和代码生成职责不变。配置 fingerprint 区分旧策略，旧缓存不能直接作为新版本验证结果。

## 5. 回归验证

新增 `tests/test_evidence_repairs.py` 的 13 个用例，使用真实源码解析、现有证据签发、完整 Gate 与确定性 Plan，模型部分为显式 ScriptedModel。

验证范围：错误 feed 短生命周期可撤回，补 data 不丢 ctx；static 生命周期猜测、全局保留及未知调用不能授权撤回；历史已证明 ownership 被相反声明挑战时继续阻塞；同源长度 recipe 按内容消歧；错误 scalar recipe 和错误 initializer 在替代证明完成后退出；缺源码不能修复；语义 invalid 有预算内追问机会。

完整 loop witness 先提交错误 feed ownership，再仅提交 data 的更正，最终 Context complete/frozen、HarnessPlan 可构建，审计文档与摘要一致，model/tool calls 不超过原配置。另一 witness 第一轮提交两个都缺源码支持的 size recipe，第二轮补正确 derived recipe 后闭合。

最终完整回归 **496 passed**，耗时 299.52 秒；13 个新增针对性用例通过。全量回归与 JUnit 结果见 `artifacts/semantic_repair_20261002/pytest.xml`。包含现有 clang 编译与 sanitizer 固定输入运行回归；这些是离线样例，不是新的真实模型 harness 生成实验。

## 6. 历史真实模型输出离线重放

重放上一轮 revision 的 6 份终态 proposals、FT、源码和 evidence。没有新模型调用、工具查询或 token 消耗；输出写入独立目录，原 trial 与冻结输入不变。

| 历史 trial | 原 Gate | 修复后 Gate | 撤回/合并 | Plan |
|---|---|---|---:|---|
| direct 1 | invalid | complete | 1 个等价 recipe 声明 | 可构建 |
| direct 2 | complete | complete | 0 | 可构建 |
| shared 1 | invalid | complete | 1 个源码否定的短生命周期声明 | 可构建 |
| shared 2 | invalid | complete | 1 个源码否定的短生命周期声明 | 可构建 |
| owned 1 | complete | complete | 0 | 可构建 |
| owned 2 | complete | complete | 0 | 可构建 |

原来三个成功 Context 保持完成，三个冲突失败在已有证据下恢复闭合。**6/6 不能作为新版本 fresh success rate，也没有为修复后的 Plan 新增 compile/runtime 结果。** 这只支持修复提案保留/撤回边界，不能证明模型稳定性、token 效率或跨项目泛化提高。

逐次摘要和审计位于 `artifacts/semantic_repair_20261002/replay/`。复现：

```bash
.venv/bin/python -m pytest -q --junitxml=artifacts/semantic_repair_20261002/pytest.xml
.venv/bin/python scripts/replay_semantic_repairs.py \
  --native-root artifacts/semantic_proof_reliability_20261002/native \
  --output artifacts/semantic_repair_20261002/replay
```

## 7. 边界

自动撤回目前覆盖有精确证明的 argument construction、borrowed lifetime 和 incoming-field state。一般 lifecycle、callback、return semantics 或 aggregate metadata 的矛盾仍保守保留。opaque state、复杂 alias、循环、间接调用与跨模块效果不会由本机制推断正确。

替换 support API 后若现有 obligation universe 仍保留旧 support 的约束，候选会被完整校验挡住；本轮不自动删除整套 support obligations。历史证明遭遇后续矛盾需要重新审查，不能凭新提案自动撤回。

反事实投影增加本地计算量，尚未实现增量 proof cache。模型能否在固定预算内稳定给出正确替代声明，仍需小规模 fresh 测试；本轮没有重启 blind cohort。
