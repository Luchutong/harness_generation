# 本地 json-parser 当前框架测试报告

测试日期：2026-10-02。目标：`/home/luchitong/work/json-parser`。

**该项目适合做真实项目开发回归。本轮当前新链接受了两个公开解析入口，但两个 Context 都未闭合，没有生成 HarnessPlan 或 harness，编译和 runtime 因此未执行。** 失败包含语义调查、证据表达和一个独立的源码认证误阻塞，不能统一归因于模型供应商。

`json.c`、`json.h` 与仓库现有 `benchmarks/json_parser/project` 完全相同。因此这是已知项目回归，不能作为未见项目的跨项目泛化证据。每个入口只有一次 fresh trial，也不能估计稳定成功率。

## 1. 版本与实验边界

| 项目 | 本轮设置 |
|---|---|
| 框架 | 本地 `v0.2`，HEAD `59b6afb55e382eec3c62427e3273502455315285`，包含现有未提交实现 |
| 生产代码 fingerprint | `147b243d38f0425dcd9b58a445f80d5cd99155bb40ffd37bfc5ae6a53acb57da` |
| 目标 HEAD | `9d50ae5ea2cdeef3b75146c621ec7b26e2e3642f` |
| Context / Agent | `source-grounded-harness-context-v4` / `source-grounded-context-agent-v17` |
| 模型请求名 | `.env` 中的 `ark-code-latest`，thinking disabled |
| 实际响应模型 | `deepseek-v4-flash-ga-260731`，66 个响应一致 |
| 调查方式 | 固定工具、默认预算、grouped Context；每条入口独立生成 upstream artifacts |
| 静态起点 | CProjectParser；解析 `json.c`、`json.h`、`examples/*.c`、`tests/*.c`，27 个函数；annotations、flows、旧 SFG 为空 |
| 测试路径 | `candidates → candidate-validate → semantic-slice → minimal-ft → harness-context → context-generate` |

入口 `json_parse` 和 `json_parse_ex` 由人工选择，但 Candidate Validation、Slice、Context 均为新的真实供应商调用，没有手写 FT、semantic facts、mock、recorded response 或生成代码。两次均实际调用了生成命令并保存阻塞原因；没有绕过冻结门禁。

执行使用单独冻结的生产代码副本，保留文件级 SHA256、runner 和收集脚本。结束时核对：目标全部 57 个文件未改变，目标 git status 仍为空；框架生产代码、`project_catalog.py` 和冻结副本均与 manifest 一致。

环境：Clang、ASan/UBSan；Python 包 `openai 2.54.0`、`tree-sitter 0.26.0`、`tree-sitter-c 0.24.2`。静态解析报告 `json.c` 1 个、`json.h` 8 个 tree-sitter parse error，实际 C 编译通过。这些前端限制保留在结果中。

## 2. 固定预算

| 阶段 | 模型调用限制 | 工具调用限制 | 源码字符预算 | 单条证据限制 |
|---|---:|---:|---:|---:|
| Candidate Validation | 6 rounds | 24 | 48,000 | 12,000 chars |
| Semantic Slice | 6 rounds | 24 | 48,000 | 12,000 chars |
| Context | 24 calls；每 requirement 4 rounds | 64 | 96,000 | 12,000 chars |

Validation / Slice 使用既有 terminal repair 策略，Context 每次提交最多一次 terminal repair；没有临时增加预算。Context completeness 最多 3 rounds，发现函数最多 16，依赖深度 2。分组 Context 最大输出 8,192 tokens；代码生成配置也为 8,192，本轮实际代码生成调用为零。

## 3. 逐阶段结果

| 指标 | `json_parse` | `json_parse_ex` |
|---|---:|---:|
| Candidate Validation | accepted | accepted |
| Slice | completed_with_unresolved | completed_with_unresolved |
| Slice 未决 frontier | 4 | 9 |
| Slice termination | final_decision | max_source_chars |
| Minimal FT CORE / support candidates | 1 / 1 | 1 / 0 |
| Context | incomplete | incomplete |
| Context hard_missing 条目 | 8 | 27 |
| 义务节点 proved / missing / blocked | 9 / 7 / 2 | 7 / 18 / 3 |
| 必需根闭合 | 4 / 9 | 0 / 9 |
| generation_allowed / frozen | false / false | false / false |
| HarnessPlan / harness | 未生成 | 未生成 |
| compile / runtime / fuzz | 未执行 | 未执行 |

两份 FT 都是 `completed_with_unresolved`，并非完整 Slice 成功。`hard_missing` 是门禁报告条目数，同一 obligation 可能被多个检查报告，不能理解为 8 或 27 个完全独立的源码缺陷。`proved` 节点数也不能替代必需根闭合：第二条入口有 7 个局部成立节点，仍没有任何必需根闭合。

没有编译尝试，因此不能把结果写成“生成的 harness 编译失败 2 次”。本轮验证到的是：**默认预算下，当前新链还不能自动完成这两个真实公开接口的 Context 与冻结生成入口。** Plan 表达能力、代码模型质量、生成 harness 的运行表现都未在这次测试中得到评价。

## 4. 失败归因

### 4.1 源码未变，却被类型认证拒绝

两次生成命令均返回：`live source differs from the frozen type snapshot`，且 `model_calls=0`。

独立离线复现发现唯一不匹配的声明是 `json.h:108–263` 的 `json_value`。Phase 1 使用 `_c_view` 去掉部分 `__cplusplus` 区域后保存类型声明；`load_frozen_inputs` 却在原始文件中做去空白后的连续子串匹配。该声明与解析器 C view 匹配，但与原始文件不匹配。

目标文件哈希始终一致。这是前端投影与生成认证之间的表示不一致，是确定性误阻塞。即使后续补齐 Context，该认证问题仍会阻止进入 Plan。修复应统一认证使用的源码视图并保留原始文件身份核验，而不是取消认证。

### 4.2 长函数的分段证据无法形成完整分析输入

`json_parse_ex` 跨 791 行，包含声明的源码范围约 24,828 字符，超过单条 12,000 字符限制。

本轮分别在两份 Context evidence 上直接重算 `complete_bodies`：两次都无法得到 `json_parse_ex` 的完整 body。该实现要求一个未截断 record 包含整个 body，不能合并分段读取；两份 evidence 分别仍有 3 和 2 条该函数的截断记录。Slice 第二例也因累计源码预算终止。

这不等于所有 semantic facts 必须读取整个函数，但依赖该入口的 value-flow / source-proof 分析存在结构性缺证据边界。应在既有读取工具内，验证文件身份、范围覆盖与内容一致性后组合证据；缺失范围和条件路径仍需保留为未知。

### 4.3 内部实现依赖与 harness 必需支持 API 的边界不稳定

`json_parse` 的 Slice 把内部 `new_value` 列为 support，保留 `hex_value`、`json_parse_ex` 和两个 cleanup API 为未决。Context 又逐个调查这些对象。`new_value` 创建解析器内部输出节点，不意味着 harness 要额外调用它来准备输入；这些事实需要与公开入口内部已经执行的工作区分。

第二例首次调查 CORE 后，模型调用计数为 4；随后调查三个 example 消费函数，累计到 15。预算最终在 24 耗尽，CORE 的参数、callback、ownership、state 等证明仍未闭合。说明调查调度仍会被广泛 frontier 消耗，未始终优先补阻塞公开调用的证明。

应使用现有依赖与 obligation frontier 优先处理必需根，合并相关源码读取，并判断候选是调用内部的证明依赖还是需要 harness 显式执行的支持 API。这次不支持继续扩大工具集合或直接提高预算的结论。

### 4.4 语义提交与签发候选仍有摩擦

`json_parse` 在首轮获得 input binding、length、argument proposal 后，仍未闭合返回值 ownership、failure semantics 和 cleanup lifecycle。后续提交出现不属于 signed alternatives 的 `support_decision` 值，以及被拒绝的生命周期候选组合；例如模型尝试用 `json_parse` 返回资源并由 `json_value_free` 清理，未被当前签发的候选组合接受。

部分 terminal repair 仍未成功，最后一轮 repair 因本地总调用预算停止。第二例三个 schema repair 成功恢复提交，但 CORE proofs 仍然 unresolved。不能将“schema 修复成功”计为“语义证明成功”，也不能从一个被拒绝的组合就认定其源码语义错误。

下一步应定位 registry 签发范围、Agent 选择格式和跨 wrapper 的返回/cleanup 证明之间的具体缺口，保留 Gate 的证据要求。

## 5. 调用成本与调查行为

| 指标 | `json_parse` | `json_parse_ex` | 合计 |
|---|---:|---:|---:|
| 模型调用：Validation / Slice / Context | 5 / 6 / 24 | 2 / 5 / 24 | 66 |
| 工具调用（框架阶段计数之和） | 59 | 61 | 120 |
| Prompt tokens | 681,825 | 814,006 | 1,495,831 |
| Completion tokens | 26,481 | 22,365 | 48,846 |
| Total tokens | 708,306 | 836,371 | 1,544,677 |
| Trial elapsed，monotonic 秒 | 278.3 | 240.5 | 518.8 |
| Context source chars | 89,777 | 91,605 | 181,382 |
| Context evidence cache hits | 10 | 5 | 15 |

按 response_id 去重，66 个供应商响应均为 HTTP 200；没有记录到供应商请求失败。一个 `model_error` 明确属于本地 `budget_exhausted`，并非 HTTP 错误。本轮没有触发 malformed history normalization，不能据此证明既往 HTTP 400 路径已经根治。

按每阶段 tool_call_id 去重、排除 framework bootstrap，再按 tool + arguments 完全相同统计，重复显式查询为 Validation `0 / 0`、Slice `2 / 1`、Context `16 / 6`。这只是重复请求描述：部分查询可能命中 evidence cache，不能全部当作新增源码读取，也没有旧版对照足以证明调查效率提升。

本轮 `retired_semantic_proposals=0`、`recoverable_invalid_rounds=0`。之前的错误事实替换机制没有在这两次轨迹中得到实际验证，不能把本次失败或缺少成功直接作为该机制的消融结论。

## 6. 目标本身的构建和原有测试

独立构建 `json.c` 成功。将 `tests/test.c` 与目标源码链接，在 ASan/UBSan、LeakSanitizer 下运行，退出码 0：36 个 JSON 文件及原有字符串检查通过。

此项定义 `JSON_TEST_NO_ALLOC_LIMIT_FUZZ`，禁用了原测试中的 max_memory / arena 额度压力循环。它证明本机可以构建和运行目标的基本测试；不是生成 harness 成功证据，也不排除未执行路径的目标缺陷。本轮没有 fuzz、coverage 或新漏洞结果。

## 7. 建议的后续验收

先修复并单独验证三件事：类型投影认证一致；长函数分段证据可重算；公开调用的必需证明优先于无关与内部实现候选调查。然后在相同入口、模型与预算下重跑这两条回归。

验收顺序是 `完整或合理保留未决的 Slice → Context 义务闭合 → frozen 认证 → Plan → 模型生成 → ASan/UBSan compile/runtime`。达到端到端后，再做每个入口少量预算匹配重复，并测试自定义分配器、error buffer 和设置字段。这个项目仍应保留 development/regression 标签，跨项目泛化要另选未参与开发的目标。

## 8. 可复核材料

本轮目录：`artifacts/json_parser_current_20261002T132400Z/`。

- `manifest.json`：源码与预算、模型配置、目标哈希、冻结版本。
- `frozen/`、`run_test.py`、`collect.py`：执行源码与脚本。
- `evaluation.json`：去重后的逐阶段结果、成本、错误与完整性摘要。
- `json_parse/`、`json_parse_ex/`：各自的 Candidate、Slice、FT、Context、evidence、trace 与生成阻塞 artifact。
- `type_authentication_diagnostic.json`：源码哈希未变、raw source 匹配失败、parser C view 匹配成功的独立复现。
- `target_probe.json`、`target_original_tests.json`、`target_original_tests.log`：目标独立编译与原有测试结果。
- `integrity.json`：框架、冻结副本与目标未改变的核验。

复核结果不需要模型调用：在仓库根目录运行 `.venv/bin/python artifacts/json_parser_current_20261002T132400Z/collect.py`。`run_test.py` 会发起新的真实调用，不应当作只读收集脚本运行。
