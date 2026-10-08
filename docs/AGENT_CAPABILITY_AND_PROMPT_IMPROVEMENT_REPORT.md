# Agent 能力、提示词与反馈调度改进

日期：2026-10-06（Asia/Shanghai）。本轮按用户要求完善已识别的局限，测试继续暂停。只修改代码、编写回归用例并进行源码和 AST 静态审查；没有运行 pytest、provider、replay、Gate、Plan 重建、build 或 runtime。

原冻结 fingerprint 为 `1da0159676fef323ce5be1fb51aceb9d8f9bacf348a5e7e344418e2d82eaae2c`，170 个生产文件。本轮 Main fingerprint 为 `11c9ce7d57fcacec4645ac12328aa38636abfbe37d2f5330b923657eef348ad6`，171 个生产文件，其中本轮改动 15 个。原 cJSON cohort 保持旧快照和失败记录，不能作为新版的验证结果。

## 1. 改动与验证状态

| 局限 | 本轮实现 | 当前验证状态 |
| --- | --- | --- |
| Candidate 最后一轮继续探索、没有提交 | 程序保留 terminal-only 轮次；循环提示与实际工具列表一致 | 源码审查；回归未运行 |
| 可选探索消耗修订机会 | 优先进入已有 frontier 修订；对可选探索设绝对调用上限 | 源码审查；回归未运行 |
| 清理证据落在通用查询截断之外 | 在已完整发行的主体正文中优先生成精确 returned-local 调用查询 | 源码审查；回归未运行 |
| 自动证据准备先耗光工具预算 | 每次最多新增 8 次准备查询；遵守当前额度并留一条 Agent 查询；组内 cleanup 优先 | 源码审查；回归未运行 |
| cleanup 与 ownership 只修一半 | 按确切主体联动两个槽位，进入既有候选事务 | 源码审查；回归未运行 |
| 不完整旧提案被提示为应保留事实 | 完整行记忆要求精确证书和未变投影；未验证提案仍作为观察展示 | 源码审查；回归未运行 |
| 所有任务携带全部契约规则、重复缺口 | 按 kind 选择显式规则块；缺口任务只发送一次 | 源码审查；回归未运行 |
| 缺证据与能力边界混在一起 | 反馈区分缺 helper 正文、明确 unsupported、上游 scope 和身份歧义，并给出诊断路由 | 源码审查；回归未运行 |

这些状态说明实现已完成静态审查，不说明端到端成功率或稳定性已经提高。

## 2. 提交收敛由程序保证

CandidateValidationAgent 现在设置 `reserve_terminal_round=True`。最后一个普通轮次只提供终态提交工具，不能继续进行源码读取。前一轮的 guidance 根据实际配置说明下一轮是否 terminal-only，避免提示与执行失配。

未知语义仍可提交合法 unresolved。最后一轮提交无效时，沿用既有有界 terminal repair；没有增加普通轮数、修复次数或自动填补模型结论。

Candidate policy 升至 `recall-first-entry-validation-v8`，恢复配置记录 terminal 保留策略。旧策略产物不会混作新策略的兼容结果。

## 3. 关键义务和修订优先使用已有预算

新增 [scheduling.py](../harness_generation/harness_context/scheduling.py)，版本 `frontier-budget-scheduling-v1`。调度仍使用原有最多 3 个 completeness passes，以及每个 requirement 的原有 primary revision / rejected correction 上限。

当必需 frontier 已调查、存在明确的旧契约纠正目标，而剩余队列是可选探索时，当前 pass 可以提前结束，进入下一个既有 pass 修订。它不增加 pass，也不重复购买 provider/protocol 失败。

已有提案需要 helper 证据时，即使整体证据集合未变化，也允许一次定向补读：条件是已有完整主体正文、该槽位有确切旧 fact 的 correction target、先前调查记录且没有执行失败。兼容缓存中的非空旧提案也登记这项资格；空 fallback 不能借其他槽位的 target 获得 primary revision。`unsupported` 和上游 scope blocker 不通过这一条件取得新权限。

默认全局额度仍为 24 次模型调用、64 次工具调用和 96,000 source chars。新增两个配置项：

- `repair_reserve_model_calls=4`，CLI 为 `--repair-reserve-model-calls`。
- `repair_reserve_tool_calls=8`，CLI 为 `--repair-reserve-tool-calls`。

默认可选探索的绝对上限为 20 次模型、56 次工具调用，余下额度供必需调查或修订使用。小预算将 reserve 限制在对应总量的三分之一以内；单 pass 不保留后续 pass 额度；配置 0 可关闭对应保留。

保留额度不是每次调查发一份新预算。必需调查仍可能耗尽全局额度，机制不能保证一定闭合。Grouped 批次也不会把无关可选槽位混进必需批次消耗保留额度；明确的 linked repair group 仍共同提交。

局部守卫停止不会设置全局 `budget_stop`。未发出的预算守卫模型请求保存为 `budget_stop / provider_request=false`，其他明确 pretransport 失败记录为不计请求的 execution_error；工具 trace 的 `tool_executed=false` 区分被守卫阻止的请求与实际执行。真实失败请求、tokens 和工具费用继续保留。

Context 调查的 `tool_calls` 采用实际 MiningState 增量，`bounded_loop_tool_attempts` 单独保存循环尝试数。分组只由首 cost owner 计工具费用。MiningLoop 在 Agent 前进行的 subject bootstrap 也写入 `framework_prelude_tool_calls` 和 trace；读取因源预算或 I/O 失败时仍保留实际费用。持续 I/O 错误返回 typed unresolved，不从 bootstrap/preparation 直接外抛。整个 FT 的 metrics 和 allocation ledger 是累计账本。

metadata 增加 allocations、optional deferrals、frontier revision advances 和 repair routes，便于检查机会实际用在哪里。未调查槽位和 hard gaps 不会因延期而被清除。

## 4. 证据查询聚焦确切返回对象

自动 `prepare_local_evidence` 现在先处理组内 ownership/lifecycle 的确切返回清理调用，再递归通用 helper；即使组首槽是 input_binding，也不会遗漏清理优先级。配置 `max_preparation_tool_calls=8` / CLI `--max-preparation-tool-calls` 限制每次准备的新增调用，0 可关闭额外准备。有效上限还受当前全局/optional 余额约束，并保留一条 Agent 工具查询；已有授权 cache 免费回显。

完整源判断使用当前 visible evidence，旧 helper 正文通过已有工具 cache 重新展示。准备限额停止不设置全局预算耗尽，也不发行额外证明。源字符预算没有独立预留，保留工具次数仍不能保证源码额度充足。

`proof_agenda` 在已完整发行、仍授权且未被 EXCLUDE 的主体正文中，检查直接返回标识符及使用该标识符的调用参数。清理形状的精确调用查询先于通用 helper 枚举；返回对象 cleanup 调查也不再优先发送前六个无关 helper/field 查询。

这能提示类似 `get_call_sites(function=<当前主体>, callee=<正文中的确切调用表达式>)` 的下一步，避免关键调用因通用 callee 列表截断而无法被提示。它只生成查询建议，不发行 helper 证据、目标可调用 ID 或 cleanup 证明。后续仍须经注册工具发现并读取候选正文。

候选按当前 kind、动作、required_by 和精确参数/return/field/ownership subject 过滤。同一个工具和参数的查询建议去重。多个 runtime origins 始终分别保留。

当前优先路径覆盖直接 `return identifier` 和该标识符的精确参数位置。复杂 alias、cast、返回表达式和不可解析宏仍依赖已有工具与证明规则，没有声称这些模式已完整覆盖。

## 5. Feedback 联动同一主体的释放契约

`context-closure-feedback-v4` 为同一确切主体联动 `lifecycle.cleanup.api` 与 `ownership.release_api`。返回值、参数、字段和 out pointee 各自受主体及既有 RID 约束；不同 RID 不能仅凭同声明或类型被关联为同一对象。

反馈同时携带旧值、精确字段路径、未目标字段/行和合法候选。候选按当前动作及主体过滤，返回对象的 cleanup 不会收到其他 buffer 的 creator 选项。未目标事实及证据继续保留。

API mismatch 联动适用于 owned 主体或确切的 mandatory-cleanup 诊断。borrowed/static/transferred 的可选 cleanup 提示不与 `release_api=null` 自动构成矛盾，聚合清理缺口不会重开这些独立主体。

关联组进入原有候选验证、源证书退休、固定点重算与持久化发布协议。Feedback 不自动修改旧事实，也不授权模型撤销证明。局部 committed 仍不等于整个 Context complete。

反馈分类检查 helper 正文是否缺失，主体正文不能替代依赖正文；当前图中已认证的完整 range read 也可作为“正文可用”的调查状态。明确 unsupported 与上游 scope blocker 单独处理。

身份歧义保留 caller、call offset、RID 和 evidence 的投影。存在歧义不自动证明框架不支持该模式，也不允许模型随意选一个来源。`repair_routes` 仅报告应继续调查、修订契约、审查上游 scope 或增强证明能力，**不会自动执行跨阶段回滚或修改冻结 FT**。

## 6. 证明记忆和提示词统一

`retained_entries` 现在要求已有精确完整行证书、覆盖字段一致、投影未变化，并带义务与证据身份。没有 graph/preview 或只有 aggregate proved 的旧提案，不会被展示为已建立记忆；`owned + until_release + release_api=null` 明确不能晋升。

这些提案没有被删除：它们仍存在于活跃事实及带 proof_status 的 `observed_proposals` 中。相同声明主体的不同来源也继续展示为不同观察，不能合并为一个已证明对象。

Context 提示拆为通用原则和十种 kind 的显式规则块。每次选择当前 slots 所需的规则，不依靠关键词裁剪。保留证据、作用域、typed schema、对象身份、冲突和回滚原则；terminal guidance 使用实际 single/group 提交工具名。

`missing_tasks` 按被阻塞根数排序，只发送一次；移除重复 `obligation_focus`。完整持久化 fact ledger 不再逐项复制进模型反馈。

Context policy / prompt / tools 分别更新为 v17 / v30 / v12；investigation 为 v10，prompt projection 为 v9，construction 为 v7。共享 terminal loop 策略更新为 v4，覆盖未请求失败的统计规则。恢复配置同时绑定 single/group system（single 模式也可使用 linked group）、完整 kind 规则、源码指导、terminal guidance、调度版本和预算，防止修改部分提示后误用旧缓存。

## 7. 静态审查和待执行回归

本轮三个分工分别审阅提示/状态机、证据调查及记忆、关联清理反馈；另交叉审阅调度、预算守卫和缓存身份。Root 修正了分组准备优先级、可见源回显、准备/前置失败计费、空 fallback 修订资格、缓存资格和非 owned 可选清理边界。新回归也修正一处预期：同一事实主体的两个不同 RID 不能同时取得完整行证书，应保留为未验证观察。

新增回归定义位于：

- [Candidate terminal 保留](../tests/test_candidate_terminal_round_reservation.py)。
- [Context 按 kind 提示与预算守卫](../tests/test_context_prompt_kind_scoping.py)。
- [精确清理反馈及身份边界](../tests/test_context_cleanup_feedback_precision.py)。
- [调查 frontier 与证明记忆](../tests/test_context_investigation_frontier_memory.py)。
- [预算保留、补读机会及调用统计](../tests/test_context_frontier_allocation.py)。
- [自动准备优先级、限额与失败计费](../tests/test_context_preparation_priority.py)。

6 个新回归文件共有 56 个 test 函数定义（参数化用例未展开），另适配 5 个旧回归文件。15 个改动生产 Python 文件与 11 个回归文件通过 AST 语法解析。

这些回归定义尚未执行。旧断言已按新版本、单份任务投影及未认证记忆适配；不能把此前的 97 项通过结果计入新版。

最终源码摘要、AST 与文本检查记录见 [implementation_manifest.json](../artifacts/agent_limits_improvement_20261006/implementation_manifest.json) 和 [static_review.json](../artifacts/agent_limits_improvement_20261006/static_review.json)。[生产代码差异](../artifacts/agent_limits_improvement_20261006/implementation_changes.patch) 以已核验全部 170 个 hash 的原冻结源码为基线，避免混入更早的工作区改动。分工备份和中途观察清单保存在同目录；中途 hash 不代表最终实现。AST 解析和文本检查只证明静态语法、接口引用及审阅范围，不证明运行行为。

## 8. 尚未消除的能力边界

本轮没有把 framework 扩展为通用程序证明器。复杂宏 ABI、异步 callback、跨函数 escape 和直接 CORE invocation 的资源身份，仍需相应源证明能力支持。诊断能够说明应增强哪里，不会替代证书。

Context Agent 仍面向冻结 FT；代码 Agent 仍翻译冻结 Plan。项目级一键规划、任意 build/runtime 错误向上游自动归因及重新冻结，尚未形成通用执行链。

稳定性需在恢复测试后，分别检验候选提交收敛、精确补证据、联动事务与回滚、预算分配及端到端 fresh 结果。本轮不报告新的成功率、hard gap 减少量或 token 效率收益。
