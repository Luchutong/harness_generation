# 源码认证、分段证据与调查调度修复报告

日期：2026-10-02。基于本地 `v0.2` 实际实现；目标回归项目为 `/home/luchitong/work/json-parser`。

**本轮修复了源码视图不一致造成的认证误拒，以及长函数证据不能组合的问题，并调整必需证明与支持候选的调查顺序。完整回归 517 项通过。真实模型分层测试确认这两个确定性缺陷已经消除，但尚未生成该项目的 harness。** `json_parse` 剩下一个必需 cleanup 证明缺口；`json_parse_ex` 的 CORE 调查遇到供应商超时，仍未闭合。

本轮没有增加 Agent 工具、预算、contract 类型或项目专用 recipe。`json.c`、`json.h` 与既有 demo 相同，结果属于已知项目开发回归，不能用于宣称跨项目泛化或稳定性提高。此前原始失败保留于 [本地 JSON Parser 测试报告](JSON_PARSER_CURRENT_FRAMEWORK_TEST_REPORT.md)。

## 1. 修复内容与通用边界

### 1.1 Phase 1、源码读取和冻结加载使用同一认证视图

原实现保存经过 `_c_view` 投影的类型声明，却在原始文件中寻找连续声明子串。类型内包含 C++ 条件区域时，原始文件没有改变也可能匹配失败。这个问题同时存在于 `read_source_range` 和生成前的 Frozen Context 加载。

新增共享的 `source_snapshot.authenticated_c_source`，由两个入口共同调用：先检查 Phase 1 保存的原始文件 SHA256，再使用与解析器相同的 C view 验证函数定义、签名、结构声明和 callback typedef。修改被 C view 删除的 C++ 区域，也会因原始文件身份改变而被拒绝，不能通过投影隐藏修改。

Phase 1 在读取文件时记录 `functions.json.source_hashes`；SFG adapter 验证其文件范围与摘要格式，以只读映射保存。Candidate 与 Minimal FT 的 source fingerprint 纳入非空原始文件哈希，源码读取证据携带对应哈希。单个声明的空白归一化不能替代整文件身份检查。

兼容边界：没有原始哈希的旧 artifact 仍执行函数、签名和类型匹配，身份检查弱于新 artifact；不能把旧文件凭空补签为已验证。C view 或 source fingerprint 改变后，应重新产生上游静态与语义 artifact，旧 complete 标签不能直接复用。

相关实现：`harness_generation/source_snapshot.py`、`sfg_builder/parser.py`、`harness_generation/sfg_adapter.py`、`semantic_discovery/tools.py`、`context_generation/persistence.py`。

### 1.2 修复普通 C++ 条件表达式的括号处理

`_cplusplus_branch` 原先使用 `strip(" ()")` 处理 conjunction 中的子表达式，会删掉 `defined(__cplusplus)` 自身的右括号，导致常见条件无法识别。现仅去掉包围整个表达式的成对外括号。

`defined(__cplusplus)`、`defined __cplusplus`、正向 conjunction 和嵌套完整括号按通用语法处理；否定条件、`defined(__cplusplus) == 0` 和不确定 OR 表达式保持保守。C view 保留原始行号与字节偏移。该回归中 `json.h` 的 tree-sitter parse error 从 8 个降为 0 个；`json.c` 仍有 1 个。

### 1.3 组合经过核验的源码片段

原 `complete_bodies` 必须找到一条未截断且包含完整 body 的 evidence。`json_parse_ex` 超过 12,000 字符，因此分段读取仍无法成为 value-flow / source-proof 的完整分析输入。

现在支持组合精确 body 前缀与 `read_source_range`：片段必须对应正确函数和文件，具有合法范围；live-source range 还需原始文件哈希及 `owned_live_source` 来源。逐行对照 snapshot 验证内容，只在无缺口覆盖完整 body 后签出完整输入。不同原始文件版本的片段不能拼接；被截断的最后一行不算完整覆盖。旧的完整函数证据仍可按精确 function ID 重放。

这个改变仅说明分析拿到了完整源码。分支、循环、间接调用或多资源身份不因此变成已证明 ownership / cleanup，原来的保守语义规则继续适用。

相关实现：`harness_context/value_flow.py`、`harness_context/investigation.py`。

### 1.4 在既有工具预算内完成目标与 wrapper 的源码依赖

`prepare_local_evidence` 使用现有 `get_function` 和 `read_source_range` 补全截断的活动目标。若 AST 中出现唯一可解析的 `return project_call(...)`，通过既有 `find_callees` 发现并读取对应 callee；遵守 scope、EXCLUDE、发现深度、引用数量及所有读取预算。

这种 callee 是 wrapper 的源码证明依赖，不因被读取就成为 harness 必须额外调用的 API。自动读取照常计入工具与源码预算，实际证据提供给 Agent，并写入 trace。预算耗尽、单行过长或无法确定目标时保留缺证据状态。

### 1.5 调查顺序采用语义义务与源码 effect 提示

必需 Requirement 和 obligation frontier 优先；可选候选中，存在已知 typed creation / initialization / release effect 的公开 API，优先于只消费同类型的 example；内部 static helper 保持可读，探索优先级较低。有限深度的源码引用也可提示某 API 内部绑定了 deallocator，但它只是排序信息，不能签发 cleanup 或允许生成。

Gate 已重算为 complete 后，不再为可选探索消耗调用。未调查的可选条目保留 open / unknown，不能捏造 rejected 结果。提示补充了 `support_decision` 的提交枚举，以及 CORE 内部已经执行的 helper 与 harness 显式调用之间的区别。

排序不检查目标项目名、函数名后缀或 `ctx/data` 参数名。测试将释放 API 与消费 API 的名称和排序交换，优先级仍由声明、引用与 effect 决定。普通 libc `free` 的语义使用既有 primitive；同名项目函数不视为 libc。

## 2. 离线验收

最终完整测试：**517 passed，341.37 秒**。本轮新增 21 个参数化回归用例，覆盖如下边界。

| 类别 | 正向验收 | 反例或预算边界 |
|---|---|---|
| 条件投影 | 普通与嵌套 `defined`、正向 conjunction | 否定、比较为零、不确定 OR 不错误删除 |
| 共享认证 | C++ 区域内嵌类型在源码工具及 Frozen Gate 均可认证 | 修改被删除区域的原始字节仍拒绝 |
| 分段组合 | 长函数连续片段、兼容的旧 prefix 与 range | 缺口、错误文件、错误内容、混合哈希、截断末行均不闭合 |
| 身份绑定 | raw hash 参与 Candidate 与 FT fingerprint | stale fragments 不作为当前版本证明 |
| 自动读取 | 改名后的长 wrapper 返回依赖可完整读取 | 小预算下保持证据不足 |
| 调查排序 | 两组改名 API 的 creator/cleanup 优先 | 排序不新增 evidence、proof 或模型调用 |

已有初始化错误字段、条件路径初始化、错误对象、userdata 逃逸、错误释放对象等负例随完整测试通过。旧 evidence 缺少 `source` 字段的兼容问题，以及“Gate 关闭后可选项仍为 open”的恢复测试预期，均在首次全量检查后修正；最终全量重跑通过。

测试入口：`tests/test_source_snapshot_closure.py`。最终日志与 JUnit 为 `artifacts/source_closure_fix_20261002/pytest_final.log`、`pytest_final.xml`；首次检查的失败日志也保留，没有作为最终成功结果使用。

## 3. 冻结版本、模型与实验控制

| 项目 | 设置 |
|---|---|
| 框架 HEAD | `59b6afb55e382eec3c62427e3273502455315285`，本地 `v0.2` 含未提交改动 |
| 最终生产 fingerprint | `db608d771bc63d60d7c5bb8982e6e107710874dae8907396fe6fb5a3b5d0a621` |
| 历史比较版本 fingerprint | `147b243d38f0425dcd9b58a445f80d5cd99155bb40ffd37bfc5ae6a53acb57da` |
| Context / Prompt / Tool | `source-grounded-harness-context-v5` / `source-grounded-context-agent-v18` / `ft-scoped-repository-v7` |
| Source / Value-flow | `authenticated-c-source-view-v1` / `resource-value-flow-v2` |
| 目标 HEAD | `9d50ae5ea2cdeef3b75146c621ec7b26e2e3642f` |
| 请求模型 / 实际响应 | `ark-code-latest` / `deepseek-v4-flash-ga-260731`，thinking disabled |
| 静态起点 | parser-only，无 LLM annotations / flows / legacy SFG |

Validation / Slice 保持 6 rounds、24 tool calls、48,000 source chars、12,000 chars/record、80 lines/read。Context 保持 24 model calls、每 Requirement 4 rounds、64 tool calls、96,000 source chars、16 个发现函数、深度 2、最多 3 completeness rounds；grouped 最大输出 8,192 tokens，Slice 配置最大输出 4,096 tokens，timeout 60 秒。没有因失败临时提高预算。

测试拆成两个独立实验臂：

1. 两条公开入口各一次完整 fresh native pipeline。Candidate、Slice 均重新调用真实模型。
2. 固定历史 Slice 角色，每条入口各一次 fresh native Context。原 Slice 的 CORE / SUPPORT / EXCLUDE / UNRESOLVED 与问题保持不变；源码证据对当前 snapshot 重新签发，CORE inclusion proof 重算后由当前 FT validator 验证。Context facts 不手写，Gate 不绕过。这是固定上游的组件实验，不能算新 Candidate / Slice 成功，也不能与端到端成功率混合。

第二臂 `json_parse_ex` 首次准备脚本漏记 unclassified unresolved frontier，被 FT validator 拒绝；当时模型调用为零。准备失败材料保留，修正脚本的 universe 后才启动 Context；已完成的 `json_parse` 没有重跑。所有实际 native 模型轨迹均保留。

## 4. 真实模型结果

### 4.1 完整 fresh pipeline

| 指标 | `json_parse` | `json_parse_ex` |
|---|---:|---:|
| Candidate Validation | accepted | accepted |
| Slice | invalid | invalid |
| Slice termination | invalid_output | invalid_output |
| 最后 Slice finish_reason | length | length |
| Validation / Slice 正常模型响应 | 4 / 5 | 2 / 6 |
| 合计 tokens | 125,190 | 128,974 |
| Context / Plan / harness | 未进入 | 未进入 |
| harness compile / runtime | 未执行 | 未执行 |

两次 Slice 最后响应都达到 4,096 completion tokens，未得到可接受终态；一条发生于 exploration，另一条发生于 terminal_budget。不能因为 deterministic fallback 保存了分类就把 invalid Slice 当作有效 FT。第一条轨迹还出现 `700–780` 共 81 行的读取请求，超过 80 行限制后被拒绝；该拒绝属于工具参数范围限制，不是新的类型认证误拒。

这个实验臂取得 17 个 HTTP 200 响应、254,164 tokens，没有供应商请求失败；但没有测到 Context 修复效果。

### 4.2 固定上游的 Context 组件实验

| 指标 | `json_parse` | `json_parse_ex` |
|---|---:|---:|
| CORE / support candidates | 1 / 1 | 1 / 0 |
| Context | incomplete | incomplete |
| hard_missing 条目 | **1** | 27 |
| 必需根闭合 | **7 / 8** | 0 / 9 |
| `json_parse_ex` 完整 body 可重算 | 是，9 个 evidence IDs | 是，10 个 evidence IDs |
| 当前共享源码认证失败 | **0 / 5 文件** | **0 / 5 文件** |
| Context model calls，含失败尝试 | 10 | 11 |
| 成功模型响应 | 10 | 10 |
| tool calls，框架计数 | 33 | 45 |
| source chars | 89,747 | 94,945 |
| evidence cache hits | 1 | 3 |
| Prompt tokens | 266,555 | 293,989 |
| Completion tokens | 12,922 | 5,958 |
| Total tokens | 279,477 | 299,947 |
| 显式重复调查 | 0 | 2 |
| termination | max_source_chars | max_source_chars |
| generation_allowed / frozen | false / false | false / false |
| Plan / harness / compile / runtime | 未生成或执行 | 未生成或执行 |

两次 `context-generate` 的阻塞原因均为 `Context is not frozen and complete under current validators`，而不是之前的 `live source differs from the frozen type snapshot`。独立共享认证诊断也确认五个 indexed files 全部通过，原始文件哈希及投影行号保持一致。

`json_parse` 首组返回 input、length、argument、ownership、return、order 等七项 resolution；实际门禁只剩 `mandatory_cleanup_unresolved`。模型选择 `json_value_free` 的 support 决策仍与签发候选不一致，terminal repair 未成功。完整源码到位之后，复杂释放语义缺口更明确地暴露出来。

`json_parse_ex` 的 CORE 组第二次请求超时，组内必需证明未提交成功；后续先调查公开 wrapper / cleanup，再进入 examples，最后因累计源码预算停止。此次不支持把 27 个 hard gap 解释为“完整源码无效”或“所有语义都错误”，也不支持声称该入口的稳定性提高。

该组件实验共有 20 个 HTTP 200 响应、579,424 tokens，另有一次 timeout；没有 HTTP 400 / 429。所有响应均来自相同实际模型。本轮仍未实际触发 malformed history normalization。

### 4.3 与历史结果的有限比较

历史默认预算 Context 为 `json_parse` hard_missing 8、必需根 4/9；`json_parse_ex` hard_missing 27、必需根 0/9。历史两份证据均无法重算长函数完整 body。当前固定角色组件实验中，完整 body 和认证问题已经消除，第一条入口硬缺口减少至 1。

不过 active API closure 由实际新语义提交决定，必需根分母从 9 变为 8；不能把它解释为对同一组根的纯消融。第二条还受到 timeout 干扰。Context tokens 从历史 546,503 / 742,912 降为本轮 279,477 / 299,947，但停止原因与调查长度不同，不能据此得出单位证明成本或稳定效率改善。

为统一重复调查口径，本轮 collector 对新旧轨迹都排除 framework bootstrap / construction，按 tool + arguments 完全相同统计：历史 `json_parse` / `json_parse_ex` 为 6 / 2，本轮为 0 / 2。自动证据读取仍计入工具和 source-char 预算；这一描述指标不等于实际冗余读取成本，也不足以证明跨项目收益。

两实验臂成本可相加用于费用审计：37 个成功响应、833,588 tokens，加一次 timeout；它们的成功率不合并。生成模型调用、harness 编译及 runtime 尝试均为零。

## 5. 尚未解决的边界

1. **复杂 cleanup 的源码证明。** `json_value_free` 通过局部 settings 绑定 deallocator，再由 `json_value_free_ex` 遍历树、重赋值并释放节点。当前直接释放 / 有界 wrapper effect 不能完整证明这类字段 callback 与遍历生命周期；共享类型或出现释放函数名不足以授权 cleanup。排序能优先发现它，不能代替资源身份、调用绑定与路径证明。
2. **完整源码后的预算压力。** 自动补全已经复用精确已签发片段，但来源调查、usage 和 registry 仍可能重复携带大量内容。两条组件轨迹都在 source-char 上限停止，没有走完需要的下一轮局部追问。改善必要源码的复用和 prompt 投影仍比增加工具更值得优先验证。
3. **Slice 的终态输出可靠性。** 新完整链两次都被 output length 阻断。需要在固定预算内减少冗余分类说明并可靠提交终态；本轮没有修改 Slice 的语义规则来接受失败输出。
4. **供应商超时和样本量。** 一次 timeout 直接影响 CORE 组，两个实验臂各只有一次每入口试验。没有重复实验或稳定率估计，也没有未见项目对照。
5. **条件编译能力仍保守。** C view 只处理可确定的 C++ 区域，不是完整的宏展开和 build-configuration 分析；目标 `json.c` 仍有一个 parser warning。

下一步可在确定性测试中隔离“字段 callback 的准确目标 + 同资源释放 + traversal 的必需路径”，先验证错误 callback、错误对象、条件释放、别名和重赋值反例。满足通用正反例后，再接入现有 support effect / obligation proof；单个项目跑通不应成为修改 Gate 的依据。当前仍不适合启动 blind cohort。

## 6. 可复核材料

新实验目录：`artifacts/json_parser_source_closure_20261002T143144Z/`。

| 文件 | 内容 |
|---|---|
| `manifest.json`、`frozen/` | 生产代码、版本、模型、预算及文件哈希 |
| `json_parse/`、`json_parse_ex/` | 完整 fresh pipeline 两次失败及原始 trace |
| `fixed_upstream/json_parse/`、`json_parse_ex/` | 固定角色的当前 FT、fresh Context、证据、门禁与生成阻塞 |
| `fixed_upstream/json_parse_ex_setup_failed/` | 未发起模型调用的脚本准备失败 |
| `run_test.py`、`run_fixed_context.py` | 两实验臂执行脚本 |
| `collect_repair.py`、`evaluation.json` | 分臂收集、去重成本及历史对照 |
| `source_authentication_current.json` | 当前共享认证与完整 body 重算结果 |
| `type_authentication_diagnostic.json` | 历史 raw-substring 检查材料，仅用于展示旧规则 |
| `integrity.json` | 框架、冻结代码与目标未改变的核验 |

目标 57 个文件与实验前一致，git status 仍为空；生产代码 fingerprint、冻结文件和 `project_catalog.py` 均与 manifest 相同。目标独立 C 编译重新通过；目录中的原目标 sanitizer 测试记录来自上一轮，未作为本轮重跑结果使用。

只读重算，不调用模型：

```bash
.venv/bin/python artifacts/json_parser_source_closure_20261002T143144Z/collect_repair.py
```

`run_test.py` 与 `run_fixed_context.py` 会调用真实供应商，且不支持覆盖既有 trial 目录；它们不是收集命令。artifacts 保留在本地，不进入源码提交。
