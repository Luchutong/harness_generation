# json-parser 真实复测失败原因分析

日期：2026-10-03。基于 [真实模型复测报告](JSON_PARSER_CLEANUP_NATIVE_RETEST_REPORT.md) 的已保存轨迹及执行时冻结的生产代码。

本次分析没有发起新的模型请求、没有运行完整回归，也没有修改生产代码或目标源码。新增的局部诊断只重算已保存证据，并进行一个明确不作为合法证据的「全部索引正文可用」敏感性检查。

## 判断

失败分布在四个位置，不能统一归因于模型能力不足或供应商故障。

| 失败 | 已确认原因 | 仍未确定的部分 |
|---|---|---|
| fresh `json_parse` Slice invalid | 第 4 轮长文本输出被 4096 token 上限截断，无终结工具调用；loop 立即退出。长委托函数还遇到单记录完整证据限制 | 模型为何选择长文本，单次轨迹不能证明唯一诱因 |
| 固定 Slice 的 Context cleanup 未闭合 | cleanup 调查未复用父入口正文、缺 `default_free` 正文；补齐所有正文的诊断仍无法证明树遍历释放效果，签发器无 cleanup 候选 | 怎样以通用、可靠的有界证明覆盖这种遍历，尚未实现 |
| lifecycle 局部修复冲突 | 布尔值变更被主体合并视为矛盾；证据撤回器明确不支持 lifecycle | 后续提案的 cleanup API 仍为 null，不能直接视为完整正确事实 |
| fresh `json_parse_ex` SIGSEGV | 本地 Python 进程在 Context 调查中退出 139；尚无 harness | 缺崩溃调用栈，未定位 native 扩展、解释器或其他具体原因 |

## 1. Slice：输出协议失败叠加长函数证据无法闭合

`json_parse` 的最后一次响应记录为：

```text
round = 4 / 6
finish_reason = length
completion_tokens = 4096
assistant content = 17059 characters
native tool_calls = 0
terminal submissions = 0
source chars = 35417 / 48000
tool calls = 10 / 24
```

因此不是总调查轮数、工具或源码预算耗尽。响应以长文本讨论角色选择，没有调用 `submit_semantic_slice`。`BoundedAgentLoop.run` 在无工具调用且不允许文本终结时直接设置 `invalid_output` 并退出；预留的第 6 轮终结机制没有机会执行。`SemanticSliceAgent` 也未为这种纯文本/截断情况安排预算内协议恢复。现有 schema repair 面向已经提交但 schema 错误的工具调用，不能自动修复这条路径。

此外，委托函数 `json_parse_ex` 的索引正文为 **24,632 字符**；实际 `get_function` 只返回 **10,593 字符**并标为 truncated。本轮 `max_chars_per_record=12,000`，还包含记录元数据。

`semantic_slicing/core_proofs.py::source_evidence` 要求某一条非截断记录的 content 包含整个 body；它没有合并 source range fragments。因而在本轮记录限制下，即使按多个 80 行区间读取长函数，也不能通过这一完整正文条件。`choices` 和 `inclusion_proofs` 依赖该条件，委托函数没有获得可选的非 anchor CORE 证明。

已保存轨迹显示 Agent 面对未签发的角色反复解释，最终没有提交工具。证据缺口可能增加了这次输出失败的压力，但不能从单次轨迹断言它是模型长文本行为的唯一原因。即使解决完整正文问题，也仍需处理 native tool submission 的协议可靠性。

`json_parse_ex` 作为 accepted anchor 时能直接取得 anchor CORE，因此该入口 Slice 的 `completed_with_unresolved` 不反驳上述限制；本次两个入口都没有取得该长函数的完整 Slice 正文证据。

相关代码：

- `harness_generation/semantic_discovery/loop.py:63`：无工具响应立即 invalid。
- `harness_generation/semantic_slicing/agent.py:108`：终结轮保留及 fallback。
- `harness_generation/semantic_slicing/core_proofs.py:15`：单记录完整正文判定。
- `harness_generation/semantic_slicing/proposals.py:12`：根据正文及 inclusion proof 签发角色。

## 2. cleanup：已读证据的可见性与证明器表达能力是两个独立阻塞

目标调用链为：

```text
json_parse → json_parse_ex → 返回 json_value 树
json_value_free
  → 局部 settings.mem_free = default_free
  → json_value_free_ex(settings, value)
      → while / switch 遍历子节点及 parent
      → 释放数组、对象或字符串存储
      → settings.mem_free(cur_value, userdata)
default_free → free(ptr)
```

### 2.1 cleanup 义务没有复用所有必要的父主体证据

`json_value_free` 和 `json_value_free_ex` 的 support_decision attempt 保存的 registry 均为 `support_candidates=[]`，其 `issued_function_ids` 均没有父入口 `json_parse`。父入口正文存在于全局已读证据中，但没有在这两个 support 调查的 registry 中成为可用正文。

`tools.activate` 的依赖复用根主要来自当前主体、facts 中的 API 关系及相关 discoveries；它没有直接将 Requirement 的 `required_by` 父主体作为证据复用根。`proposals.registry` 虽会枚举父主体，`support_effects.bindings` 却要求 parent 和 api 的完整正文都在当前 issued 集合内，否则立即返回空。

这说明上一轮跨义务复用已工作，但还没有覆盖「支持 API 的效果必须绑定到父入口精确主体」这一方向。35 个 evidence 的复用数量不能证明所有必要证据已经可见。修复应复用精确父主体的、已认证且有授权的 source records，不能开放全部历史或全仓库。

### 2.2 模型尝试选择 cleanup，schema 因未签发而拒绝

Agent 曾提交：

```json
{"decision":"required","reason":"cleanup","required_by":["json.c:1125:json_parse"]}
```

两个 cleanup support attempts 都因此出现 `one signed subject/candidate alternative` schema error。`terminal.py` 在无候选时只提供 `rejected/unresolved` 分支，只有源码签发候选才添加 `required/optional` 分支。

`json_value_free` 的 repair 改为 unresolved，并说明源码调用者支持 cleanup，但当前没有可选的 required alternative。`json_value_free_ex` 的 repair 仍未通过 schema。这些是本地工具契约拒绝，不能归为供应商 HTTP 400，也不能简单写成 Agent 没发现 cleanup API。

### 2.3 补齐正文仍不足：当前 transfer function 不处理这类树遍历

局部诊断分别使用：

1. attempt 保存的实际 signed visible bodies；
2. 全局实际已读、已认证的 complete bodies；
3. 假设所有索引正文可用，包括 `default_free`。第三项仅为敏感性检查，不签发新证据、不放行 Gate。

两个 cleanup 函数在三个条件下均得到：

```text
paths = 1
uncertain_paths = 1
parameter:value release_counts = [0, 0]
callback_bindings = 0
exact_parameter_release_proved = false
cleanup relation reasons = []
```

这里的 `[0,0]` 只是证明器没有推出释放效果，**不是程序确实没有释放资源的反例**。路径已经 uncertain。

`proof_grounding.analyze.process` 支持声明、表达式、if 和 return 等局部处理；`while_statement`、`switch_statement` 等未建模语句进入 fallback，设置 uncertain，未推导循环中的释放调用。`json_value_free_ex` 的 while 包含子节点下降、长度递减、parent 回溯和指针重赋值。必须证明根及附属存储的覆盖、对象身份、释放次数和回调目标，单纯看见一次 free 不足以成立。

`parameter_release_proof` 要求每条受支持的非空路径释放精确 parameter origin 一次且不逃逸。当前分析得不到这种结果，所以 canonical `cleanup_consumption` 没有生成。假设 `default_free` 正文已提供也没有改变结果。

源码不足和证明能力不足都存在；新增更多通用工具、只提高 token/source budget 或重复请求同一模型，都没有消除后一个确定性阻塞。

相关代码：

- 目标 `json.c:1131`：树遍历 cleanup；`json.c:1181`：默认 allocator wrapper。
- `harness_generation/harness_context/tools.py:89`：源码复用根和依赖闭合。
- `harness_generation/harness_context/proposals.py:71`：可见正文 → signed candidates。
- `harness_generation/semantic_slicing/support_effects.py:39`：parent/api 正文前提及释放效果。
- `harness_generation/harness_context/terminal.py:139`：支持选择的 schema 约束。
- `harness_generation/harness_context/proof_grounding.py:394`：未支持语句进入 uncertain。
- `harness_generation/harness_context/resource_identity.py:20`：精确一次释放判定。

## 3. lifecycle：此前证据撤回修复未覆盖这一 predicate

相同返回主体的两个原始提案分别为：

```text
旧：cleanup = {mandatory: false, api: null}
新：cleanup = {mandatory: true,  api: null}
```

`repairs._combine` 不允许静默替换相反的布尔值，这一点符合保留知识和禁止 last-write-wins 的设计。它保留两条事实，再调用 `RepairProofEvaluator` 判断能否根据源码撤回。

关键是 `RepairProofEvaluator.assess` 的明确条件：

```python
if kind not in {"argument_construction", "ownership", "state"}:
    return proof  # status = missing
```

因此 lifecycle 不会进行这种反事实证明选择。局部诊断将实际保存的两条 lifecycle facts 传入执行副本，二者均返回 missing，reconcile 的 withdrawals 仍为 `[]`。不只是「这次证据不够」，还包括「这个 predicate 尚未接入撤回器」。

两条提案随后归一化到同一个 resource_id。`project_invocations` 比较该 resource 的 type、creation、cleanup、reuse，看到 cleanup 定义不同，输出 `conflicting_resource_identity`。这个名称容易误读成对象身份碰撞；本轮实际是同一主体的生命周期属性冲突。

与此同时，owned return 的 `release_api=null`，新 lifecycle 的 cleanup API 也为 null，独立门禁仍产生 `mandatory_cleanup_unresolved`。因此即使成功撤回旧 `mandatory=false`，也不能立即冻结 Context，更不能把后提交的条目直接当成完整正确事实。

适当的修复边界是：分别证明必要性和具体 cleanup API；在精确资源主体上支持有依据的属性修正，保留其他已证明属性及审计；API 未证明继续保持 missing。不要整体覆盖 Requirement，也不要取消冲突门禁。

相关代码：

- `harness_generation/harness_context/repairs.py:28`：布尔冲突与主体合并。
- `harness_generation/harness_context/repair_proofs.py:158`：支持的撤回 predicate。
- `harness_generation/harness_context/invocations.py:26`：同资源定义冲突。
- `harness_generation/harness_context/semantic_proofs.py:134`：owned/mandatory cleanup 的独立门禁。

## 4. SIGSEGV：目前只能确认进程故障，不能宣称根因

`native_full.log` 最后记录 `hex_value` support 调查完成，Context 累计 model calls 为 12。其后进程退出 139，shell 报告 Segmentation fault。所有已保存的 provider 响应为 HTTP 200，没有对应的供应商失败记录。

Context mining loop 在每次调查之间重建 Context、API closure、义务图及 registry；这些分析调用 tree-sitter。现有日志没有记录确切崩溃步骤或 Python/native 调用栈，不能仅凭该调用关系归因于 tree-sitter，也不能归因于模型输出、目标 parser、OOM 或某个版本缺陷。

执行环境为 Python 3.12.3、tree-sitter 0.26.0、tree-sitter-c 0.24.2、tree-sitter-cpp 0.23.4。当前代码中的普通 `except Exception` 不会使 SIGSEGV 路径恢复，finally 的最终 checkpoint 也没有发布。

之前对保存的部分 Context/13 个初始 Requirement 的零调用重算正常；本次 cleanup/lifecycle 局部诊断也正常。这只说明这些离线路径未复现，不能排除进程历史、其他运行路径或 native 对象生命周期问题。

下一步定位应先加步骤级 checkpoint 和 faulthandler，在独立子进程用保存输入重放完整本地分析路径，必要时采集 native backtrace。没有调用栈前不应以升级依赖或重复付费整链来代替定位。发生崩溃时尚未生成 harness，因此不属于目标/harness runtime 成绩。

## 修复优先级

1. Slice 合并带源码身份认证的分段证据，并在剩余预算内恢复无工具/截断响应的 native terminal submission；保持不完整证据不得签发 CORE。
2. support 调查精确复用 `required_by` 父主体证据，定向取得实际 callback helper；随后用通用、有界且可审计的遍历 effect summary 解决循环释放证明。先区分 unsupported analysis 与真实矛盾，不能按函数名放行。
3. 将精确 lifecycle 属性纳入证据撤回；必要性修正和 cleanup API 选择分开闭合。此项消除额外冲突，但不独自解决 cleanup 缺口。
4. 给本地分析阶段增加崩溃定位与隔离，获得栈后修复；定位时不需要新模型调用。

生成门禁此次拒绝不完整和冲突 Context 是合理行为。问题在于证据取得、可见性、证明能力及修复范围尚未贯通，而不是应该放宽 Gate。由于没有进入 HarnessPlan/代码生成，本轮也没有证据评价 C/C++ 生成模型的能力。

## 可复核诊断

新增文件位于原实验目录：

- `analyze_causes.py`：使用 frozen 实现，无模型调用。
- `error_causal_diagnostic.json`、`.log`：六个 cleanup 条件结果、lifecycle 撤回结果、Slice 协议和正文证据指标。

执行命令：

```sh
PYTHONFAULTHANDLER=1 .venv/bin/python artifacts/json_parser_cleanup_native_20261003T023422Z/analyze_causes.py
```

输出性质为 `offline_causal_diagnostic_not_gate_or_trial`；不记作新真实模型实验、Gate 成功或 harness 成绩。
