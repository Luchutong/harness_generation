# json-parser 真实模型复测

日期：2026-10-03。目标：`/home/luchitong/work/json-parser`。

**本次仍未生成 harness。供应商请求正常；fresh `json_parse` 被 Slice 输出截断阻止，fresh `json_parse_ex` 进入 Context 后发生本地 Python 段错误。另一次固定历史 Slice、fresh native Context 的 `json_parse` 完成调查，但因 cleanup 未证明与 lifecycle 修复冲突被 Gate 拒绝。**

## 版本与设置

本地分支 `v0.2`，HEAD `59b6afb55e382eec3c62427e3273502455315285`，包含此前未提交实现。执行前复制完整生产 Python 源码；所有模型调用均使用该副本，没有在测试途中修改生产实现。

- 生产 fingerprint：`fbbed199159201cb86f13750693c7d23d24a7f298d10758b9e48a77596f5abdd`。
- 目标 HEAD：`9d50ae5ea2cdeef3b75146c621ec7b26e2e3642f`。
- `.env` 请求模型：`ark-code-latest`；实际响应：`deepseek-v4-flash-ga-260731`；thinking disabled。
- Validation / Slice：6 rounds、24 tools、48,000 source chars、4,096 output tokens。
- Context：grouped，24 model calls、64 tools、96,000 source chars、16 discoveries、depth 2；每 Requirement 4 rounds、最多 3 completeness rounds，输出上限 8,192 tokens。
- 静态起点：parser-only；扫描 `json.c`、`json.h`、`examples/*.c`、`tests/*.c`，27 个函数；未使用手写 annotations、flows 或旧 SFG。

两个公开入口由人工选择；fresh 全链的 Validation、Slice、Context 使用真实模型。只有无法进入 Context 的 `json_parse` 另做一次组件测试：保留此前真实 Slice 的角色，重新签发当前源码证据，通过当前 FT validator，然后 fresh native 调查 Context。该组件没有手写 Context facts、mock 或录制响应，且不计为 fresh Candidate/Slice 成功。

目标与现有 demo 相同，属于已知项目开发测试；每个实验条件只运行一次，不能估计稳定性或跨项目泛化。

## 逐阶段结果

| 实验 | Candidate | Slice | Minimal FT | Context | Plan / harness / compile / runtime |
|---|---|---|---|---|---|
| `json_parse` fresh 全链 | accepted | invalid：末次响应 `finish_reason=length` | 未进入 | 未进入 | 未进入 |
| `json_parse_ex` fresh 全链 | accepted | completed_with_unresolved，4 个未决项 | CORE 1、SUPPORT 0 | 调查中本地进程 SIGSEGV，未发布最终 Context | 未进入 |
| `json_parse` 固定历史 Slice，fresh Context | 历史结果 | 历史角色：仍有未决项 | CORE 1、SUPPORT 1 | invalid，必需根 7/9 闭合 | 生成命令被 Gate 阻止，模型调用 0 |

`json_parse` 的 invalid Slice 保存了 fallback 分类，但没有将 fallback 当成有效 Slice 继续构造 FT。`json_parse_ex` 的 Slice 有效且仍保留未决项，不能写成所有支持语义都已经闭合。

目标 `json.c` 独立 C 编译通过。此项不是生成 harness 的编译成绩；本次没有生成代码模型调用、harness 编译、harness runtime、fuzz 或 coverage 成绩。

## 实际暴露的问题

### 1. 复杂 cleanup 仍然没有达到 canonical 消费证明

固定上游的 `json_parse` 首轮七项 resolution 已提交，包括输入、长度、参数、ownership、return、ordering 和 lifecycle。最终仍有 `mandatory_cleanup_unresolved`。

源码证据能够重算 `json_parse_ex`、`json_value_free`、`json_value_free_ex` 的完整 body，并通过当前源码身份认证。`json_value_free` 的局部 settings 绑定 `default_free`，但 `json_value_free_ex` 使用 while/switch、child/parent 遍历、指针重赋值，并分别释放数组、字符串存储和节点。当前受支持的局部 transfer function 没有证明这种完整资源覆盖。

该次 Context 没有取得 `default_free` 的完整定义，也没有产生源码 callback binding diagnostic 或 canonical `cleanup_consumption`。因而尚未走到“已证明释放效果 → canonical cleanup resource_reference”的验证位置。不能把失败简单解释为新绑定机制无效，也不能说源码调查已经完全充分。

### 2. lifecycle 的局部修正仍出现相反提案共存

初始 lifecycle 提案为 `cleanup.mandatory=false, api=null`；后续调查改为 `mandatory=true, api=null`。API 仍然缺证据，后者不是完整的已证明 cleanup 修复。

主体合并保留了两条提案，两者归一化为同一个返回资源，于是产生：

```text
mandatory_cleanup_unresolved
subject_repair_conflict
validation error: conflicting_resource_identity
```

这里的 `conflicting_resource_identity` 实际来源是同一 resource 的 lifecycle 定义不同，不是确认两个运行时对象被错误合并。修复审计显示 `retained_subjects=1`、`withdrawals=[]`，没有自动撤回初始提案。

框架正确阻止了冻结，但这仍暴露了一个修复边界：在 cleanup 尚未完全证明时，必要性修正与旧提案的处理没有完成消歧。此前小型连接测试没有覆盖到这一真实轨迹。

### 3. `json_parse_ex` 出现本地进程稳定性故障

全链 Context 首组关闭 input binding、buffer length 和 return semantics，argument construction、callback、ownership、state、lifecycle 仍未关闭。后续继续调查支持候选，最后日志记录累计 12 次 Context model calls；随后 Python 进程以 139 退出，shell 报告 `Segmentation fault`。

这是本地框架进程故障，发生时尚无 harness；不能记作生成 harness runtime 崩溃，也没有证据归因于供应商或某个具体 parser 函数。该进程没有生成最终 completeness，因此不给出其最终 hard-gap 数或冻结状态。

未重新付费重跑该全链。使用已保存的 55 条 evidence、4 条 facts，对部分 Context 和 13 个初始 Requirement 的 registry 进行了离线重算，正常完成、模型调用 0；这没有复现段错误，也没有定位根因。局部重算不能代替完整试验。

## 证据复用与调用成本

固定上游 Context 的实际指标：

| 指标 | 结果 |
|---|---:|
| Model calls | 16 |
| Tool calls，包含框架读取 | 34 |
| Source chars | 93,902 / 96,000 |
| Evidence cache hits | 2 |
| Bootstrap 源码读取 / 复用 | 3 / 11 |
| 跨义务恢复的不同 evidence IDs | 35 |
| 必需根闭合 | 7 / 9 |
| Hard-gap 报告条目 | 2 |
| Canonical cleanup sources | 0 |

复用已在真实轨迹发生，但 source budget 仍接近上限；不能仅凭复用计数宣称 Context completion 或效率提升。Model 显式仓库查询 18 次，其中 4 次为重复的 tool + arguments；其中包含 2 次 `get_call_sites`，未调用 `find_field_writes` 或 `get_control_context`。bootstrap/框架读取单独计数。

收集器按响应 ID 去重成本；共享 grouped trace 只计 `group_cost_owner=true` 的副本，避免按 Requirement 重复统计工具查询。

| 实验 | 已保存成功响应 | Prompt tokens | Completion tokens | Total tokens |
|---|---:|---:|---:|---:|
| `json_parse` fresh 全链 | 7 | 77,324 | 7,363 | 84,687 |
| `json_parse_ex` fresh 全链，部分 Context | 21 | 699,628 | 24,091 | 723,719 |
| `json_parse` 固定上游 Context | 16 | 466,961 | 24,369 | 491,330 |
| 合计 | 44 | 1,243,913 | 55,823 | **1,299,736** |

44 个已保存响应的状态均为 HTTP 200，没有保存到供应商请求失败。由于一个进程崩溃，当前内存中的未落盘尝试可能丢失，表中 token 合计是可审计的下界，不保证等于全部计费量。history normalization 计数为 0，本轮没有验证既往 HTTP 400 的修复路径。

## 与之前结果的关系

之前固定历史 Slice 的 `json_parse` 为 incomplete、一个 cleanup gap；本次为 invalid、cleanup gap 加 lifecycle 修复冲突。该轮不能宣称端到端能力提高，也不能仅凭单次更差结果定位为某一连接修复引起的回归：模型轨迹不同，旧提案与后续修正也不同。

这次直接观察到的是：源码跨义务复用确实工作，但仍不足以取得并证明复杂 cleanup；semantic 修复边界仍有真实失败；本地进程稳定性另有需要隔离的故障。下一步应优先处理这三个具体失败位置，继续保持冻结门禁。

## 可复核材料

目录：`artifacts/json_parser_cleanup_native_20261003T023422Z/`。

- `manifest.json`、`frozen/`：生产文件 SHA、默认预算、模型配置和目标快照。
- `json_parse/`、`json_parse_ex/`：fresh 全链结果与已保存的 native traces。
- `fixed_upstream/json_parse/`：历史 Slice 角色、fresh Context、证据、冲突与生成阻塞。
- `native_full.log`、`native_fixed_json_parse.log`、`runner_crash.json`：执行日志与崩溃分类。
- `diagnose_partial.py`、`partial_preview_diagnostic.*`：零模型调用的部分重算。
- `evaluation.json`、`integrity.json`、`collect_native.py`：只读收集与完整性检查。

结束时目标 57 个文件哈希均与实验前一致，目标 git status 为空；框架生产源码和执行副本与 manifest 一致。只读收集命令：

```sh
.venv/bin/python artifacts/json_parser_cleanup_native_20261003T023422Z/collect_native.py
```

`run_test.py` 和 `run_fixed_context.py` 会发起真实模型调用，不属于只读收集。
