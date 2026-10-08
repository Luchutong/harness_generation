# Agent 源码细节工具增强与测试报告

日期：2026-10-02，基于本地 `v0.2`。

**新增三个有界源码查询，并接入 Agent 提示、proof agenda、发现范围和证据缓存。最终完整回归 533 项通过。工具增强可以改善源码获取，但本轮尚未证明 cleanup 语义闭合率或 harness 成功率提高。**

真实 `json-parser` 的确定性查询已经能发现并读取内部默认 deallocator、定位四个间接释放调用；现有 support effect 仍未签发对应 cleanup。真实模型组件测试也显示：仅增加工具没有自动改善结果；加入查询指引后，取得全部必需 helper 定义的诊断指标从 0/2 到 1/2，严格终态输出仍为 0/2。源代码到位与语义闭合必须分别验收。

## 1. 新工具解决什么

此前已有 `get_function`、`read_source_range`、类型查询、caller/callee、资源线索等 15 个 Context 仓库工具。其中 `find_assignments` 实际复用符号引用查询，不能直接区分准确的字段 receiver、赋值 RHS 和条件；`find_callees` 主要发现直接调用，不能通过保存到字段的函数地址发现内部 helper。

现在 Context 仓库工具为 18 个，另有既有 terminal submission 工具。Candidate / Slice 的工具集合没有扩大。

| 工具 | 参数 | 返回细节 |
|---|---|---|
| `get_call_sites` | 精确 function ID、callee 表达式/字段名或 `*` | 调用表达式、位置实参、直接/间接语法、控制上下文、可能的项目函数引用 |
| `find_field_writes` | 精确 function ID、字段名或字段表达式 | receiver、赋值 RHS、操作符、designated initializer、条件上下文、函数地址引用 |
| `get_control_context` | 精确 function ID、绝对源码行号 | 该行最小语句及外围 if/else、短路条件、循环、switch/case、预处理语法 |

不同对象的同名字段不合并。局部变量或参数遮蔽函数名时，不将它签为项目函数目标。条件赋值同时保留 then / else；字段中的函数地址是 discovery reference，不能当成已解析的 runtime callback binding。

查询只检查一个已授权函数，使用同一 Phase 1 snapshot、源文件哈希和 evidence ID。单次返回数、单条记录字符、总源码字符、工具调用、函数发现数量、深度限制保持原机制；EXCLUDE 和无法发现的函数不能借新工具任意读取。缓存命中不重复计源码成本，但查询仍消耗工具调用。

`control_context` 明确标记 `lexical_ancestors_only`。它不是完整 CFG，不覆盖此前提前返回、跨函数路径、循环不变量或必然执行性；截断、候选歧义和空结果均不能变成正面证明。新片段也不能替代完整函数证据。

实现：`harness_context/source_queries.py`、`harness_context/tools.py`。

## 2. 让 Agent 实际使用这些细节

工具描述与系统提示说明了三个查询的用途；proof agenda 在相关 ownership / lifecycle / callback / state / support 缺口上建议窄查询，并复用已有未截断证据。

第一轮真实模型测试没有充分使用字段写入工具，仍多次直接读取未发现函数。最终补充通用导航：从已授权 parent 查询直接调用，再用返回的精确 ID 读取 helper；字段函数地址则先查询 owner 的字段写入，再读取目标定义；读取被 scope 拒绝后，应先发现或报告 unavailable，避免换工具重复同一越界读取。

这些指引基于语法与 scope，不依据项目名、函数名后缀、`ctx/data` 参数名或特定字段。完整性 Gate、support effect、cleanup proof、Canonical Contract 和 HarnessPlan 没有放宽，也没有新增 semantic contract。

## 3. 版本和离线验证

| 项目 | 版本 |
|---|---|
| 工具初版 fingerprint | `6c4b20142d3445749393bb7af31942f72cf5c10f20a8db8201b746a1a7fddef2` |
| 最终 fingerprint | `31a62f5ad4d5738d60e18f68707fd3a1dc0c730f61b7da38a47f42b2bcdacf6c` |
| 对照工具版本 fingerprint | `db608d771bc63d60d7c5bb8982e6e107710874dae8907396fe6fb5a3b5d0a621` |
| Context policy | `source-grounded-harness-context-v5`，证明规则未变 |
| Prompt / Tool | `source-grounded-context-agent-v19` / `ft-scoped-repository-v8` |
| Source queries / Investigation | `bounded-source-detail-queries-v1` / `proof-focused-investigation-v5` |

Context configuration 纳入 query version、tool registry digest 和更新后的 prompt digest；旧调查不能因标签相同而直接恢复。生产默认预算保持 24 model calls、64 tool calls、96,000 source chars、最多 16 个发现函数和深度 2。

新增 `tests/test_source_detail_tools.py` 共 **16 个回归用例**：精确 receiver、条件分支、实参顺序、循环上下文、绝对行号、designated initializer、函数名遮蔽、三个工具的 scope 拒绝、发现预算、结果截断、缓存、源码预算失败回滚、短路条件、注释/字符串排除、同主体重用、proof agenda 和禁止 callback reference 直接签发 cleanup。

最终完整回归：**533 passed，288.21 秒**。初始化错误字段、错误对象、userdata 逃逸、错误释放对象等既有反例一起通过。工具初版也完成一次 533 项全量检查；最终提示与 agenda 修改后重新跑完整测试，版本和日志分别保留。

## 4. 真实模型组件实验

这是源码细节获取实验：两个合成开发片段，分别含无条件 callback 字段赋值和条件分支的两个函数地址。固定 FT 是显式 fixture；不运行 native Candidate / Slice，也不评价完整 Context Gate、Plan、compile 或 runtime。

每个 trial 固定 4 model calls、12 tool calls、24,000 source chars、12,000 chars/record；每轮使用同一 `.env` 提供商，请求 `ark-code-latest`，实际响应 `deepseek-v4-flash-ga-260731`。模型需要报告字段写入、实际 callback 参数及目标 helper 的直接调用，附已签发 evidence。ground truth 只在退出后评估。

实验保留两批，不能合并为最终成功率：

| 批次 / arm | 必需 helper 完整定义全部取得 | 严格终态细节全部正确 | model calls | tool calls | tools 返回错误 | total tokens |
|---|---:|---:|---:|---:|---:|---:|
| 初轮：旧工具 | 0/2 | 0/2 | 8 | 20 | 8 | 34,429 |
| 初轮：仅增加工具 | 0/2 | 0/2 | 8 | 17 | 7 | 35,634 |
| 后轮：旧工具 + 查询指引 | 0/2 | 0/2 | 8 | 18 | 6 | 37,138 |
| 后轮：最终工具 + 相同查询指引 | **1/2** | **0/2** | 8 | 19 | **1** | 45,486 |

“完整定义取得”是事后诊断，要求 evidence 中有所有目标 helper 的未截断 `get_function` body。最终条件片段取得完整定义；无条件片段读到目标的直接调用线索，但未取得其完整 body，不能算全部源码到位。两次最终轨迹均实际调用 `find_field_writes`，此前两次工具初版没有使用它。

严格终态仍失败：有的定义已读到，模型却没有在对应数组中完整报告；有的将 `free(p)`、`opts->drop (indirect)` 等带参数或注释的表达式填进要求精确 callee 的字段。不能把信息出现在 narrative / open questions 就计作完整结构化提交。collector 使用既有 `record_functions` 核对 citation，允许合法源码 range，不只检查直接 function_id；原始 runner 判定也保留。

后轮工具返回错误下降不等于整体成本下降：tokens 从 37,138 增加到 45,486，约增加 22.5%；更多定义被读取，实际 source chars 从 8,245 增加到 15,697。每个 case 每版只有一次，不足以估计稳定性、方差或泛化。

两批共 8 个 trial、32 个 HTTP 200 响应、152,687 tokens，没有记录到供应商请求失败。一次 artifact runner 的目录准备失败发生在模型调用前，单独保留；没有用 mock 或重放替代失败响应，也没有提高预算。

这里验证的是查询接口和窄证据导航。完整 Context Agent 的新系统提示与 agenda 已做离线集成测试，但本轮 native 组件 driver 使用单独的源码观察终态，不能当作完整 Agent 的 semantic contract 成功率。

## 5. 真实 json-parser 的确定性查询

在上一轮真实项目的有效 Minimal FT 与当前 snapshot 上，使用默认 Context budget 执行以下查询，不调用模型、不注入 semantic facts：

```text
get_function(json_parse)
→ find_cleanup_candidates(json_value)
→ get_function(json_value_free)
→ find_field_writes(mem_free)
→ get_function(default_free)
→ get_call_sites(default_free, free)
→ get_call_sites(json_value_free, json_value_free_ex)
→ get_function(json_value_free_ex)
→ get_call_sites(json_value_free_ex, mem_free)
```

结果：**9 tool calls，16,493 source chars**；取得内部 `default_free` 定义，并定位数组、对象成员、字符串与当前节点的四个间接释放调用，保留实参与循环 / 分支上下文。

`json_value_free` 的 signed cleanup candidate 仍为 **0**。因此新工具解决了一部分“怎么找到、怎么读”的困难，却尚未解决“字段 callback 确切绑定、同资源释放、allocator 配对、复合对象遍历路径能否重算证明”。本轮没有生成 harness 或执行编译 / runtime，不能宣称真实项目已经跑通。

## 6. 后续重点与材料

下一步应先让已经得到的函数地址、实参和控制上下文参与现有 proof 的重算，区分 unknown 与 contradiction；再验证 callback 绑定、对象别名和条件释放的正反例。完整树遍历需要额外的资源与路径分析，不能通过工具结果直接签发 cleanup。

实验目录：`artifacts/source_detail_tools_20261002T153508Z/`。

- `manifest.json`、`revision/`、`revision_v2/`：两个工具版本及文件级哈希；旧版读取此前冻结代码。
- `run_native.py`、`run_guided.py`：独立两批 native driver；`summary.json`、`guided_summary.json` 保存原始结果。
- 四个 arm 目录：每个 trial 的 evidence、trace、结果与 fixture。
- `collect.py`、`evaluation.json`：严格终态与源码获取指标分开统计。
- `json_parser_query_probe.json`：真实项目的九次工具查询及 evidence。
- `pytest_initial_533.*`、`pytest_final.*`：两个版本完整回归。
- `integrity.json`：冻结代码及当前生产代码一致，真实目标 57 个文件未改变、git status 仍为空。

只读收集：`.venv/bin/python artifacts/source_detail_tools_20261002T153508Z/collect.py`。native driver 会调用供应商，不能当作收集脚本重跑。README 的历史结果按各自冻结版本保留；没有启动 blind cohort。
