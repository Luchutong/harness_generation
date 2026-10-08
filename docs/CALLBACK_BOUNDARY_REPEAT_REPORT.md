# Callback / semantic-only 边界与冻结重复实验

冻结日期：2026-10-01；实验续行与收集日期：2026-10-02。本轮以本地 `v0.2` 的 `59b6afb` 为对照，冻结修正版 `callback-boundary-v1-20261001`。修正版 production fingerprint：`3d87d1bedce39daab85085da127784c89ef93bd90bc19dbf7784e5e54f31e390`。

这轮只处理已有层之间的边界，没有新增 Agent 工具、Graph 节点类型或 construction certificate 种类。完整框架沿用 `Candidate → Slice → Minimal FT → Context / Closure → Gate → HarnessPlan → Harness → compile → runtime`；模型调查语义，源码图负责可重算依赖，代码模型只翻译冻结 Plan。

## 边界改动

**Callback 的实际执行关系进入现有 Graph 与 Plan。** 函数引用需要签发完整源码、唯一符号解析和精确 callback ABI。图记录 dispatcher、实际 handler、参数逐项转发和每次 dispatcher 调用中的 handler 次数。当前仅证明单语句、无条件的同步转发；条件、循环、重复调用、参数改写、额外存储、早退、shadowed symbol 或 ABI 不符均不生成该证明。

Handler 的 userdata 与 dispatcher、creator、cleanup 复用同一个 runtime resource ID，fuzz bytes/length 沿实际转发传播。已经证明的输入/长度契约可进入 handler 的派生视图，避免要求模型为同一条输入重新提交独立事实；ownership 与 return semantics 继续独立验证。直接传入函数引用是 `function_binding`，不伪造一次先于 dispatcher 的 registration 调用。

HarnessPlan policy 升为 `frozen-context-harness-plan-v9`。handler 保留 CORE 身份，call row 标明 `invocation_kind=callback` 与 `via_function_id`。代码模型传入实际 handler，由 dispatcher 内部执行；校验器拒绝额外直接调用 handler、零返回 stub 替换、错误 userdata 和不同资源实例。若绑定了实际项目 callback 却无法证明执行 schedule，Plan Builder 阻止生成。

**Semantic-only 不再成为 construction 的隐式成功来源。** Reconciler 升为 v4：单独的 stack/zero/constant/callback 标签在没有可重算来源时保持 `unknown`、`recipe=null`，记录 `semantic_only_requires_source_proof` 与 `semantic_recipe_not_reproduced`。活跃参数未 resolved 时 Gate 阻止冻结。图与 mandatory semantic recipe 矛盾时仍为 conflict。

合法构造不会因“缺少示例 caller”一律被拒绝。框架复用已有的完整源码 effect、已签发 return identity、独立重算的唯一 harness creator binding / cleanup consumption，以及现有 public callback object 证据。Graph 可表达 planned creator strategy，但不会宣称它是观测到的 runtime alias；producer 的每个参数仍须递归闭合。出现实际多调用实例时，声明 recipe 不能覆盖或合并它们。

**既有证据与资源规范化保持一致。** Cleanup proof 的 resource ID 和 construction ID 会与规范化后的资源槽同步，argument 的证据引用也随之更新。Canonical 构造给出的资源起点/cleanup 边可约束 type-erased userdata。EXCLUDE caller 可作为已发现、预算内的只读源码证据；它不进入 callable discovery registry，也不能成为 semantic API、SUPPORT 或 Plan 调用。

## 离线验证与开发预检

冻结源码的全量离线检查为 **425 passed，91.90 秒**。新增边界回归覆盖 renamed symbols、参数转发、条件/重复/早退/改写、错误 ABI、shadowing、semantic 标签没有证据、creator 参数未闭合、未签发 resource ID、缺失源码与 EXCLUDE producer。一个 bound callback Context 在没有独立 handler input/length proposals 的情况下完成 Plan；固定 harness 经 clang 与 sanitizer 跑过六个输入。反例 stub、额外 handler 调用与错误 userdata 被拒绝。

离线 Fake/Scripted 模型验证规则和投影，不能计入真实模型成功率。

开发预检与正式 cohort 分开：早期 fingerprint `19fc9197d878a343543071b052ecf4cc08267313800b6cfdf425c4f5b5e04b21` 的两个 fresh 试验中，shared-context 编译/runtime 通过，callback incomplete，暴露 handler 输入重复求证、source scope 和 terminal ownership/schema 问题；该版本源码已归档。随后一次 callback 预检在 FT 后停止：它启动早于 read-only source registry 的负例检查，未计入完成试验。修复后的正式实验只使用下面两份冻结源码，不复用上述 facts 或失败重试。

## 冻结实验协议

实验开始前保存全部调用顺序、fixture hashes、预算、源码/脚本逐文件 SHA256 与运行依赖。对照版为 commit `59b6afb55e382eec3c62427e3273502455315285`，fingerprint `19fbf2ecdba1332e7aae649ea8065267ba1ad8b1da6c85d376f89cb64b16326b`；修正版见本文开头。两版源码位于只读快照，fresh 子进程分别从自己的 module root 导入，避免基线被新规则重算。

这里的对照版是 `59b6afb` 的同一新主链，已包含 Graph/Canonical/Value/Resource/Invocation 等层；不是旧 Stage 1–3 的 `generate`。因此本实验不回答整套分层架构是否优于 legacy，也不分离每层的因果贡献。Candidate / Slice 模块在两版中未改，若上游成功率出现差异，不能归因于下游 callback / construction 边界修复。

六类 API 为 bounded scalar、creator with args、out parameter、shared context、owned return、external callback context。每版每类五次，合计 **60 个预登记 trial**。相同 source、provider 配置、ValidationBudget、ContextBudget（24 次 model / 64 次 tools / 96,000 source chars）、code output 上限 8,192 tokens。按 seed `20261001` 随机排列 30 个 case/repetition block，同一 block 两版并行，workers=2；每个试验从新静态 artifact 开始，不复用既有模型事实、不做失败 retry、不剔除 provider 错误，源码或执行脚本变化即终止。成功生成后的 `--resume` 仅用于验证零模型调用的持久化恢复，不增加试验分母，不重试失败。

实验在会话中断时停止：14 个 trial 已正常结束，另两个 shared-context trial 停在 Context 阶段。续行前保存原始 summary 和行政续行登记，核验冻结源码、原 coordinator、fixture、预算和 provider 配置。两个中断试验保留为 `external_interruption`，不重跑、不推断 Context 失败；只执行原顺序中尚未启动的 44 个试验。完成后共 58 个正常结束、2 个外部中断的记录。主指标沿用全部预登记分母（每版 30）；另报剔除外部中断后的敏感性结果（每版 29）。中断已写盘的成功响应成本计入观测下界，未写盘的在途请求、Context 总工具计数与最终 hard gaps 均记为未知，不填零。

主指标为所有预登记 trial 的整链 runtime_success；同时统计 Slice、Context completion、hard gaps、调用数、成功响应 tokens、compile/runtime。返回成功响应的 tokens 不包含没有 usage 的失败请求，失败请求另报。runtime 是六个固定输入的 sanitizer replay，不是 fuzz campaign 或 coverage 结果。

这是已知合成 fixture 上的 Development / Regression 对照。它比较本轮修复整体的工程效果，不能分离每层 contract 的因果贡献，不能测 Candidate recall，也不能证明跨真实项目泛化。每类 n=5 的区间很宽，不能因 5/5 就宣称稳定。

## 正式结果

正式 cohort 已归档 **60/60 个预登记记录：58 次正常结束、2 次外部中断**。两版源码、worker 脚本、fixture、预算与 provider 配置核验一致，生产 fingerprint 保持冻结值。请求配置为 `ark-code-latest`，记录到的实际 served model 均为 `deepseek-v4-flash-ga-260731`；配置相同不证明供应商内部权重永远不变。

**本轮没有证明整体稳定性提高。** 全部预登记分母下，Context completion 两版均为 14/30；compile/runtime 从 12/30 到 13/30。修正版的 callback 构造关系已可证明，但真实 callback 五次仍全部未完成 Context；不能宣布 callback 端到端已解决，也不能据此启动大规模 blind cohort。

### 各 API 模型结果

表中每格依次为 Slice / Context / compile / runtime，分母均为五个预登记试验。外部中断只发生在 shared-context，两次均已完成 Slice；最终 Context 未观测，未进入生成。

| API 模型 | 对照版 | 修正版 |
| --- | --- | --- |
| bounded scalar | 4 / 4 / 2 / 2 | 5 / 5 / 5 / 5 |
| creator with args | 5 / 3 / 3 / 3 | 5 / 2 / 2 / 2 |
| out parameter | 5 / 1 / 1 / 1 | 5 / 1 / 1 / 1 |
| shared context | 5 / 2 / 2 / 2 | 5 / 2 / 1 / 1 |
| owned return | 4 / 4 / 4 / 4 | 5 / 4 / 4 / 4 |
| callback context | 4 / 0 / 0 / 0 | 5 / 0 / 0 / 0 |
| 总计 / 30 | 27 / 14 / 12 / 12 | 30 / 14 / 13 / 13 |

已构建 FT 的节点数（CORE + support candidates）在每类可观测试验中一致：bounded scalar 为 1，creator-with-args/out-parameter/owned-return 为 3，shared-context/callback 为 4。26 个双方均到 FT 的配对还具有相同 CORE 集合；下游波动不是这组 FT 大小变化造成的。

剔除两次外部中断后，每版 29 个正常结束试验：Slice 为 26/29 与 29/29，Context 均为 14/29，compile/runtime 为 12/29（41.4%）与 13/29（44.8%）。三个对照上游失败为一次 Candidate、两次 Slice 失败，不能归因于下游边界代码。

30 个配对中，6 对均 runtime 成功、11 对均未成功、7 对仅修正版成功、6 对仅对照版成功；描述性 exact McNemar 双侧 p=1.0。进一步看两版均正常走到 FT 的 26 对，其 CORE 集合也相同：runtime 两版均为 **12/26**，成功翻转为 **6 对改善 / 6 对退步**；Context 为 14/26 与 13/26。这一子集分析按观测上游结果筛选，属于探索性诊断，不替换预登记主指标。

bounded scalar 的修正版 5/5 是积极结果，但每类 n=5 的区间很宽：5/5 的 Wilson 95% 区间约 56.6%–100%，0/5 约 0%–43.4%。creator-with-args 出现退步，out-parameter 与 callback 仍低成功；没有跨 API 类别一致的稳定增益。

### Callback 与 semantic-only 的机制证据

修正版五次 callback 均取得一个源码证明的同步 dispatcher 关系。其中两次（repetition 3、4）活跃参数 recipe 全部 resolved，handler 的输入/长度从 dispatcher 派生，userdata/creator/cleanup 同一身份；对照版四个已进入 Context 的 callback 轨迹没有一次活跃 recipe 全部闭合。

这两次修正版最终仍各有五个 hard-gap 条目，涉及独立 ownership、return semantics 与 mandatory call-order requirement。其余三次分别留下输入来源缺失、长度 recipe 与 semantic proposal 冲突、userdata semantic recipe 无法验证。因此有证据支持“转发与构造边界更清楚”，没有证据支持“callback 已稳定生成”。真实 callback 没有进入代码模型，新 Stage4 的 callback 翻译路径本轮仍只有离线 Plan/代码反例/编译验证。

对照版有两个活跃参数以 `semantic_only_not_reproduced` 标记 resolved；修正版为零。这两个对照参数所属 Context 仍为 incomplete，因此本次没有观察到由它们导致的 false complete，不能把该计数当作误完备率下降。源码反例测试证明新的 fail-closed 规则生效；独立必要契约 ground truth 与跨项目误完备仍待评价。

### 缺口与成本

| API 模型 | Hard gaps 中位数 [范围]：对照 → 修正 | Context model / tool 总调用：对照 → 修正 | 成功响应整链 tokens：对照 → 修正 |
| --- | --- | --- | --- |
| bounded scalar | 0 [0–0] → 0 [0–0] | 14 / 31 → 13 / 28 | 336,011 → 361,281 |
| creator with args | 0 [0–7] → 1 [0–4] | 60 / 151 → 43 / 93 | 1,256,723 → 1,045,687 |
| out parameter | 5 [0–19] → 1 [0–17] | 66 / 145 → 75 / 139 | 1,177,460 → 1,447,972 |
| shared context | 0.5 [0–1] → 2.5 [0–7] | 60 / 143 → 49 / 107 | 1,563,111 → 1,442,698 |
| owned return | 0 [0–0] → 0 [0–19] | 38 / 102 → 42 / 102 | 822,018 → 929,017 |
| callback context | 16 [3–18] → 5 [2–26] | 87 / 196 → 76 / 152 | 1,443,456 → 1,300,251 |

Hard gaps 仅对最终 Context 可观测的 trial 统计，未进入 Context 和外部中断均不填零；总调用包括上游早退试验的实际零 Context 调用。shared-context 调用总数仅含每版四次正常结束；该行 tokens 另含中断已写盘响应，因此是观测下界。其余各行均为五个完整 native trial 的已知响应成本。每次调用的范围与逐次原始记录见分析 JSON。

全体可观测 Context 的 hard-gap 条目为 94 → 99，但观测数为 26 → 29，不能直接比较总和。在双方均到 FT 的 26 对中，条目为 **94 → 54**、Context model calls 为 325 → 269、tools 为 768 → 564，runtime 仍为 12/26 → 12/26。这些条目会同时描述同一未满足义务，不是独立失败事件；缺口减少未转化为 Gate 完成率。

只看每版 29 次正常结束，整链 model/tool calls 为 **524/1,060 → 504/923**，成功响应 tokens 为 **6,267,717 → 6,264,508**，几乎不变。Context model calls 为 325 → 298（中位数 12 → 10），tools 为 768 → 621（中位数 28 → 22）。更少调用未带来明确 token 节省，早停与不同上游轨迹也影响成本。

包含中断已记录成本后，成功响应数为 542 → 514，成功响应 tokens 为 6,598,779 → 6,526,906；两个中断分别记录 331,062 与 262,398 tokens。所有失败或在途工作中没有 usage 的成本仍未知。预算匹配指同样的 model/tool/source/output 上限，不是强制相同实际 token 消耗或费用。

### 错误保留与结论

对照版两个 Context complete 的 bounded-scalar 试验在编译时缺少 `malloc/free` 标准声明；修正版一个 Context complete 的 shared-context 试验代码模型请求失败，原始错误为 `OpenAI-compatible request failed: OSError`。这些均保留在主分母，不补代码、不重试。已编译的 25 个 harness 均完成六输入 sanitizer replay，未另出现 runtime failure。

Agent traces 共记录 6 → 8 次 timeout；代码生成另有上述一次无法确定 HTTP 状态的请求错误。Agent 中没有记录 HTTP 400/429，但不能用这点排除未分类代码生成错误的供应商原因。包含中断记录的 terminal schema failure events 为 11 → 10（正常结束部分为 11 → 8）；存在 normalization 的成功请求为 6 → 8（正常结束均为 6）。这是既有 provider normalization 的运行观测，不是本轮新修复的因果证据。

当前框架能让失败更具体、减少部分重复求证，并拒绝未复现的 construction label。本轮重复实验同时表明，ownership、return/order、schema 与代码翻译仍限制整链，尤其 callback 与 out-parameter 尚未稳定。下一轮的重点应是对已有事实复用和最小消融做独立评价；本轮结果不支持宣称整体稳定性或跨项目泛化提高。


## 适用范围与剩余边界

当前 callback 下沉针对实际项目 handler 的直接函数引用，以及每次 dispatcher 调用一次、无条件、同步的薄转发。函数指针 alias、`&handler`、条件/重复 dispatch、回调表、跨调用保留、pull reader、自定义 allocator 和 callback 产生 owned/out resource 均没有该 schedule 证明；Plan 应停止，不能由生成模型补写执行策略。公开 callback object 的既有 construction proof 仍可使用经过约束的 stub，其支持范围不等同于实际项目 handler。

源码 Graph 使用有界局部值流与声明，不是完整 SSA、跨过程 alias 或所有路径的生命周期证明。存在任何观测到的同一 producer 调用实例时，planned creator strategy 不替代它们；这避免错误合并，也可能拒绝本可构造的情况。Semantic-only 收紧也可能增加 false negative，必须与误完备、端到端成功率和成本一起评估。

构造 recipe resolved 不证明 ownership、nullable return、support necessity 或 state/order 已满足。真实模型仍可能没有读取完整主体源码、提交 schema 不合法的 facts，或在预算内无法闭合这些独立义务。减少构造 gap 只能作为机制诊断，不能替代完整链成功。

离线反例校验和六输入 sanitizer replay 提供有限验证。它们不证明任意输入、分支都执行目标 API，也不等同于长时 fuzz、coverage 或一般 C++ ABI 支持。每类五次且样例已用于开发，整体成功率和描述性配对检验均不能外推到真实项目。

下一轮应先固定独立样例与最小消融干预，分别衡量依赖闭合、误完备、模型可重复性及端到端结果，再开始新的跨项目 cohort。已有旧 A/B/C runner 没有完整拆分当前新层，不能直接作为本轮各层的因果证明。现有层的证据优先于继续增加 contract。

## 归档与复现

- [冻结 manifest 与逐文件哈希](../artifacts/callback_boundary_freeze_20261001/manifest.json)
- [冻结版本离线记录](../artifacts/callback_boundary_freeze_20261001/offline_validation.log)
- [调用前预登记](../artifacts/callback_boundary_repeats_20261001/registration.json)
- [逐次原始结果](../artifacts/callback_boundary_repeats_20261001/summary.json)
- [只读分析、审计与逐次成本](../artifacts/callback_boundary_results_20261002/summary.json)
- [机器生成的统计报告](../artifacts/callback_boundary_results_20261002/report.md)
- [中断后行政续行登记](../artifacts/callback_boundary_repeats_20261001/continuation_20261002.json)
- [中断前原始 summary](../artifacts/callback_boundary_repeats_20261001/summary_before_continuation.json)
- [早期开发预检](../artifacts/callback_boundary_development_20261001/summary.json)
- [早期源码归档](../artifacts/callback_boundary_development_source_20261001/manifest.json)

实验 driver 为 `scripts/repeat_callback_boundaries.py`，只读 collector 为 `scripts/collect_callback_repeats.py`。collector 在实验期间补充成本与审计字段，没有进入冻结子进程；其最终 SHA256 独立记录于分析结果，探索性子集分析也明确标记。行政续行执行原 coordinator 的原始 trial 函数，未改变 worker。运行目录必须全新；环境文件只在调用时读取，不纳入源码快照或报告。

```bash
.venv/bin/python scripts/repeat_callback_boundaries.py \
  --baseline artifacts/callback_boundary_freeze_20261001/baseline \
  --revision artifacts/callback_boundary_freeze_20261001/revision \
  --env-file .env --output artifacts/callback_boundary_repeats_fresh
.venv/bin/python scripts/collect_callback_repeats.py \
  --experiment artifacts/callback_boundary_repeats_fresh \
  --output artifacts/callback_boundary_results_fresh
```
