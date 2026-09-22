# 通用 LLM 的反馈驱动 Fuzz Harness 生成研究

> 在不进行专用模型微调的情况下，能否通过结构化执行反馈、Harness 评分与分支搜索，使通用 LLM 持续生成更高质量的 fuzz harness？

本项目围绕这一问题构建实验平台：保持模型权重不变，通过编译与运行证据指导候选 Harness 的生成、评估和迭代。当前使用 DeepSeek API，以独立 C 函数和 libFuzzer 为起点。

Protocol-aware Stage 1–4 的 HarnessPlan 优化入口、构建配方、正式发布门槛和非帧输入契约见 [HarnessPlan 优化闭环](docs/PLAN_OPTIMIZATION.md)。

“持续生成更高质量”指在固定预算内，通过多轮候选评估与选择，提高保留下来的 Harness 的有效性和测试能力；不假设每次生成都会变好，也不意味着模型本身通过实验更新了权重。上述研究问题仍待对照实验验证，现有示例不能构成有效性结论。

## 研究目标与假设

计划检验三个相互关联的问题：

1. **结构化执行反馈**：将编译错误、运行异常、目标触达和覆盖信息整理为明确诊断，是否比仅提供原始日志更有助于模型修正 Harness？
2. **Harness 评分**：结合有效性门槛、目标覆盖与执行成本，是否比仅按编译成功选择候选更可靠？
3. **分支搜索**：在相同预算下，保留多个候选并选择性扩展，是否优于单路径反复修复和独立重复采样？

这里的“分支搜索”指 **Harness 候选方案的搜索树**，例如对参数映射、输入解析和初始化策略生成不同后继；目标程序的分支覆盖则是评估信号之一，两者含义不同。

## 当前运行逻辑与实现边界

当前代码支持一次实验独立采样 N 个候选，逐个执行以下流程：

```text
目标源码 + 函数名
    → tree-sitter 提取含 pointer 参数的函数
    → 三种 ISF Prompt 分类 + 2/3 多数投票
    → 仅用通过筛选的函数构造 Harness 提示词
    → DeepSeek 独立请求生成一个 Harness（重复 N 次）
    → 格式与结构检查 → 词法审阅提示
    → 可选的 Clang 编译及 Sanitizer 插桩
    → Smoke Test（启用 fuzz 时必跑，也可单独启用）
    → Short Fuzz Run（Smoke 通过后）
    → Collect Metrics → 保存评估报告
```

`--generate-only` 在生成和初步审阅后停止；默认逐候选编译。`--harness` 可直接输入一个已有候选，跳过 API，复用后续检查与执行步骤。每次命令使用新的实验目录，不覆盖之前的候选记录。

| 能力 | 当前状态 | 对研究的作用 |
| --- | --- | --- |
| 通用 LLM 独立生成 N 个候选、单个离线候选输入 | 已实现 | 提供独立采样与复查基线 |
| tree-sitter C 语法摘要 prompt | 已实现 | 让模型基于确定语法事实生成 Harness，避免直接读取完整源码 |
| ISF 指针预筛选与三 Prompt 投票 | 已实现 | 排除明显的标量、结构体和上下文指针，避免向生成阶段投喂完整函数列表 |
| 实验汇总、候选编号与完全相同代码标记 | 已实现 | 追踪候选来源和已知请求成本 |
| 结构检查、编译、限时 fuzz、Sanitizer 报告 | 已实现 | 提供执行证据 |
| Smoke Test 与统一原始指标采集 | 已实现 | 在评分前检查可运行性，保存各阶段证据 |
| 状态、token 用量、耗时、引擎统计与文件指纹 | 已实现 | 支持追踪单次实验 |
| 直接调用与 `volatile` 的词法提示 | 已实现，需人工复核 | 暴露部分明显质量风险 |
| 结构化反馈校验、prompt 构造和单轮再生成 | 已实现 | 将给定反馈转成下一轮生成条件 |
| 从执行结果自动提取反馈 | 已实现 Python 默认策略 | 自动组织事实、假设、建议和证据 |
| 有界 feedback → LLM → 评估闭环 | 已实现 | 从自动反馈生成子候选、筛选 1 个父候选继续迭代 |
| 多维 Harness 质量信号 | 部分实现 | tree-sitter 静态可达性/输入映射/资源/隔离/崩溃保真、短 fuzz 速度及可选 target-only coverage |
| 十项指标的评估接口、注册机制与报告 | 已实现 | 未提供对应 probe 的维度显式为 `unavailable`，不伪造分数 |
| 综合评分、候选选择、反馈和下一轮规划 | 已实现 Python 默认策略 | `feedback-loop` 已在固定宽度和轮次内接入 |
| 分支搜索执行 | 部分实现 | 有界单谱系闭环已实现；多父候选搜索与全局预算仍待实现 |
| 对照实验、消融实验与多随机种子评测 | 待实现 | 检验收益及其来源 |

初始独立采样不是分支搜索：候选互相不可见，`parent_id` 为空。指定 `--parent-candidate` 和 `--feedback` 后，可从一个父候选生成下一轮 N 个子候选；`feedback-loop` 则会在明确的 `--rounds` 和 `--children-per-round` 预算内自动执行“反馈 → LLM revision → 评估 → 筛选”循环。`review.json` 是检查提示，不是 Harness 质量分数；`fuzz_result.json` 的 `cov`/`ft` 也不是目标函数覆盖率。

新候选会保存 `evaluation.json`：Harness 存在时，默认会产生 tree-sitter 静态的
Reachability、Input Expressiveness、Crash Fidelity、Resource Bound 和 Target Isolation
信号；短 fuzz 与 target-only coverage/replay artifact 只在真实证据存在时加入其余信号。
同时保存 `automatic_feedback.json`，将低分/错误维度和证据绑定为下一轮可审计反馈。
未知项不会打 0 分，编译失败也不会把所有指标归零，fuzz 未崩溃更不等于有效性满分。详见
[评分与反馈扩展接口](docs/EVALUATION.md)。

## 计划中的反馈与搜索闭环

以下是研究设计；其中评分、去重选择、自动反馈和下一轮请求规划，以及有界单谱系的自动循环均已实现；完整多父候选预算搜索仍待实现：

```text
目标源码与调用约束 → 初始候选集合
                         ↓
                   编译与短时执行
                         ↓
                结构化反馈 + 有效性检查
                         ↓
                  评分、去重与选择
                         ↓
              扩展多个候选策略 → 再次评估
                         ↓
          预算耗尽或达到停止条件 → 独立复评最佳候选
```

### 结构化执行反馈

计划将反馈分为编译、调用与参数、运行异常、覆盖和成本几个维度。每项诊断关联原始日志位置、候选标识与父候选标识，并区分“已观察到的事实”“可能原因”和“待验证建议”。没有测量的字段记为未知，不补成成功或零值。

例如，编译成功但目标未触达时，应反馈目标调用路径问题；Sanitizer 报告发生在 Harness 分配或参数构造中时，应反馈驱动自身错误。无法归因的崩溃暂列为待分析，不直接作为发现目标漏洞的奖励。原始日志继续保留，便于核查反馈提取是否失真。

### Harness 有效性与评分

有效性需要多层证据，不能仅靠编译成功、没有崩溃或关键词匹配来保证：

| 层次 | 计划验证的内容 |
| --- | --- |
| 构建有效 | 可编译链接，使用原始目标实现，没有替换目标或伪造依赖 |
| 调用有效 | 运行时确实到达目标，输入影响实参，关键计算未被优化删除 |
| 参数与资源有效 | 遵守 API 的内存和调用约束，正确处理长度、初始化、生命周期及释放 |
| 测试有效 | 探索目标内部路径，而非仅在 Harness 中执行或提前返回 |
| 发现可信 | 失败输入可复现，区分目标缺陷、Harness 缺陷及环境问题 |

合法的内存与调用约束不等于只生成业务有效输入：例如解析器需要测试格式错误的数据，但传入的缓冲区仍应满足接口的内存契约。

评分计划先使用有效性门槛，再比较目标覆盖、相对已有候选的覆盖增益和执行成本；编译失败或明确存在 Harness 缺陷的候选不进入最佳有效候选集合，但可保留用于修复扩展。未通过验证的候选保留未知状态。目标缺陷引发的崩溃不应自动判为 Harness 无效。

初期保留各维度原始指标与排序依据，具体权重或排序规则在预实验后固定，不预设未经验证的综合分数。覆盖测量应限定到目标代码并在同一目标内比较，避免通过增加 Harness 自身分支提高分数。复评时使用独立预算和不同随机种子，检验搜索阶段的高分能否保持。

### 分支搜索与预算

计划以候选 Harness 为节点，记录父节点、生成策略、反馈、评分及成本。优先实现有宽度限制的候选搜索：对被选中的候选生成多个后继，执行后去重并保留少量候选继续扩展，同时保存最佳已验证候选。首轮编译失败时仍可扩展修复分支。

搜索总预算覆盖所有候选的 API 调用与 token、编译和 fuzz 时间，包含失败尝试。按预算耗尽、最大轮数或连续无改进停止。搜索宽度、扩展数及停止阈值作为待开展实验的配置变量，不将更大计算量带来的收益直接解释为方法优势。

## 实验设计与评价

计划在固定模型配置、目标源码、工具链、资源限制和初始语料条件下比较：

| 组别 | 方法 | 主要用途 |
| --- | --- | --- |
| A | 单次生成 | 衡量初始质量与最低成本 |
| B | 独立重复采样，使用相同评估器选择 | 排除仅增加生成次数带来的收益 |
| C | 原始日志反馈的单路径迭代 | 基础执行反馈基线 |
| D | 结构化反馈的单路径迭代 | 检验反馈组织方式 |
| E | 结构化反馈 + Harness 评分 + 分支搜索 | 检验完整方案 |

主要预算匹配比较面向 B–E；A 作为单次参考单独报告成本。进一步消融评分维度与候选保留策略，并同时报告调用次数、实际 token、执行时间及质量随预算的变化。模型别名可能发生更新，实验需保存请求与响应中的模型信息和实验时间。

评价包括编译成功率、经验证的有效 Harness 比例、目标触达与覆盖、单位成本收益，以及经复现和归因的独立目标缺陷数。重复崩溃按根因去重，不能把 artifact 文件数量当作漏洞数量。所有失败候选计入记录；API 或环境失败单独分类并说明统计分母。

现有三个小型 C 示例和刻意越界测试用于验证实验管线。后续需要扩展目标集合，覆盖不同参数类型、内存所有权和调用约束，并将用于调整反馈与评分的开发目标和最终评测目标分离。手写参考 Harness 作为对照，不向模型提供其实现。对同一目标运行多次，报告逐目标结果、汇总统计与波动，避免以一次短时 fuzz 的结果作结论。

建议实施顺序：统一反馈记录 → 目标有效性与覆盖测量 → 固定评分规则 → 单路径反馈基线 → 候选分支搜索 → 预算匹配与消融实验。暂不引入专用模型微调或复杂多文件项目支持。

## 当前工具使用说明

以下命令描述已有实现，可以直接运行；上面的研究闭环将在这些能力上逐步构建。

### Structural Flow Graph（Phase 1）

项目级 SFG 构建器是独立的 `sfg_builder` 包，只执行 C AST 解析、候选发现、语义标注、struct 方向分析和 SFG 构建。它不会导入或启动本仓库原有的 Harness 生成、Stage 1~4、fuzz、coverage feedback 或 rollback 流程，也不实现 Function Triplet。

安装 Python 3.10+ 后，建议在虚拟环境中安装项目：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

核心依赖只有 `tree-sitter` 和 `tree-sitter-c`。Graphviz 不是硬依赖；只有传入 `--render` 时才尝试调用系统的 `dot` 命令生成 `sfg.svg`。

默认使用确定性的 `MockSemanticAnalyzer`，不需要 API key：

```bash
python -m sfg_builder \
  --project tests/fixtures/simple_project \
  --output artifacts/simple
```

命令生成：

```text
artifacts/simple/
├── functions.json
├── candidates.json
├── annotations.json
├── flows.json
├── sfg.json
└── sfg.dot
```

测试依赖不属于运行时依赖，可单独安装并运行：

```bash
python -m pip install pytest
python -m pytest -q
```

对于需求没有规定唯一映射的多输入或多输出函数，第一版保留原始 `FunctionFlow`，设置 `complex_flow=true`，并生成用于检查的笛卡尔候选边。每条候选边均设置 `inferred=true`、携带 `inference_reason`，同时输出 warning。这一行为明确标记为：**engineering choice, not specified by SynapseFlow Phase 1**，不会静默把候选边当成确定事实。

六类产物内容、LLM backend、目录过滤、决策追踪、其他保守图规则和可选 Graphviz 渲染见 [SFG 使用说明](docs/SFG.md)。

### 项目骨架

```text
harness_generation/
  cli.py          参数校验与入口
  config.py       不可变的单候选配置 CandidateConfig
  experiment.py   N 候选顺序调度、重复标记和实验汇总
  candidate.py    单候选生成、审阅、编译和可选 fuzz
  core.py         提示词、API 请求、响应检查与编译
  source_analysis.py tree-sitter C 语法摘要提取
  isf.py          pointer 参数预筛选、三 Prompt 分类与多数投票
  fuzz.py         libFuzzer 限时运行
  records.py      原子 JSON 记录
  evaluation/     十项指标定义、tree-sitter/运行期质量信号、上下文和评估器
  iteration.py    综合评分、选择、反馈与再生成请求的协议和默认策略
  feedback.py     父候选校验、反馈证据快照和下一轮 prompt 构造
  feedback_loop.py 有界 parent→feedback→LLM revision→evaluation→selection 调度
  assessment.py   编译、Smoke、短时 fuzz 的阶段控制与原始指标收集
  smoke.py        固定输入重放和逐输入日志
```

调度层调用 `run_candidate` 获取候选结果和退出状态，并保存评估报告与自动反馈。通过 Python 的 `evaluation_engine` 参数可替换默认的 multi-dimensional evaluator；CLI 暂不提供动态插件加载。给定结构化反馈可执行单轮再生成；`feedback-loop` 则会在明确轮次和每轮 child 数预算内自动推进并选出一个下一轮父候选。完整多父候选的搜索调度仍待实现。

## 环境与配置

- Python 3.10+；依赖 `tree-sitter` 和 `tree-sitter-c`。
- Clang 及 libFuzzer、AddressSanitizer、UndefinedBehaviorSanitizer 运行库。
- DeepSeek API 密钥及可用余额。

建议使用虚拟环境安装项目依赖：

```bash
cd ~/work/harness_generation
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

在同一个终端配置密钥：

```bash
read -rsp "请输入 DeepSeek API Key: " DEEPSEEK_API_KEY
echo
export DEEPSEEK_API_KEY
python3 -c 'import os; print("已配置" if os.getenv("DEEPSEEK_API_KEY") else "未配置")'
```

密钥只对当前终端和其子进程生效。程序仅从环境变量读取，不自动加载 `.env`；`.env.example` 仅用于说明变量名。不要将密钥写入源码或提交到版本库。

安装后也可使用 `harness-generation` 入口。没有安装 tree-sitter 依赖时，API 生成会在发请求前失败并保存诊断；离线 `--harness` 复查仍只依赖 Clang。

## 生成一次 Harness

```bash
python3 -m harness_generation \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --output runs/mini_parser
```

输入必须是自包含的 UTF-8 `.c` 文件，包含所需标准库头文件、类型和辅助函数；不包含 `main`，不依赖其他本地文件或外部库。明确指定目标函数名，支持 `static` 函数。生成前会用 tree-sitter 解析 C 源码，先把具有 pointer 参数的函数写入 `isf_candidates.json`，不把完整函数清单直接交给 Harness 生成模型。随后针对这些参数执行三种独立分类：直接提取、Yes/No、以及 A Binary data / B Text data / C Struct/object / D Float/scalar / E Other 多选。A、B 作为 byte stream 正票，每个参数至少得到 2/3 正票才通过。指定目标函数若没有任何参数通过投票，本次生成会在 Harness 请求前失败。

筛选后的 `source_summary.json` 仅包含通过投票的 `isf_functions`、目标函数自身的语法事实，以及目标函数体实际调用到的必要辅助函数；仍不会包含完整函数体或源码注释。`isf_classification.json` 保存三份请求、原始响应、参数类别、逐项投票、最终结论和分类 token 用量，便于审计误判。多候选实验对同一源码只分类一次，后续候选复用结果。

默认模型为 `deepseek-v4-flash`，可通过 `--model deepseek-v4-pro` 更换。请求发送到官方 `https://api.deepseek.com/chat/completions`，使用非流式、关闭思考模式、max_tokens=4096。单候选默认 temperature=0.2，多候选默认 0.8，可用 `--temperature` 显式指定 [0, 2] 内的值；提高温度只是采样配置，不保证多样性或质量。请求超时参数为 120 秒，无自动重试或重定向；底层 HTTP 超时是 socket 等待超时，不是整个请求的硬性总时限。接口和模型参数见 [DeepSeek 官方文档](https://api-docs.deepseek.com/api/create-chat-completion/)。完整目标源码会本地保存为 `target.c` 供编译使用，但默认不发送给 DeepSeek。

每次使用**尚不存在的输出目录**，包括重试失败实验时，以免覆盖记录。存在 pointer 候选时，ISF 阶段固定发出 3 次分类请求；之后每个 Harness 候选各发出 1 次生成请求。因此一次正常的 N 候选实验会调用 `N + 3` 次 API，并按全部请求产生费用。没有 pointer 候选时不会发送分类请求，目标也会被 ISF 筛选拒绝。

## 生成 N 个 Harness 候选

在已配置密钥的终端执行，例如只生成并初步审阅 5 个候选：

```bash
python3 -m harness_generation \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --output runs/mini_parser_candidates_5 \
  --candidates 5 \
  --generate-only
```

移除 `--generate-only` 将逐个编译；再加 `--fuzz-seconds 10` 则为每个编译成功的候选运行 fuzz，时间预算按候选数累加。`--generate-only` 不能与正的 `--fuzz-seconds` 同时使用。`--harness` 只允许 `--candidates 1`。

```text
runs/mini_parser_candidates_5/
  experiment.json
  candidates/
    candidate_0001/
      target.c
      isf_candidates.json
      isf_classification.json
      source_summary.json
      prompt.json
      response.txt
      harness.c
      review.json
      result.json
    candidate_0002/
      ...
```

N>1 时每个候选目录保存完整记录，编译、Smoke 和 fuzz 产物也互相隔离；N=1 保留原有平铺目录布局，并新增 `experiment.json`。候选 `result.json` 使用 schema 8，记录 ISF 分类状态、API 尝试数及原有执行信息；实验汇总使用 schema 2。旧实验记录不自动迁移。

当前采用相同源码、提示词和模型配置的 N 次独立请求，按顺序执行，不使用服务端一次返回 N 个答案的参数。一个候选解析或编译失败不会丢弃其他候选；不重试、不额外生成替补。缺少密钥时批量实验不发送请求；HTTP 401/403 时停止后续候选。普通请求失败记录后继续下一候选。Ctrl+C 保留已完成结果并将未执行候选留为 `not_started`。

`experiment.json` 在每个候选开始和结束时更新，记录状态、产物目录、API 尝试次数、成功生成数量、代码唯一数量和 token 汇总。重复检测仅比较提取后代码的 SHA-256，不判断语义等价；重复候选保留，`duplicate_of` 指向首次出现的候选。`reported_usage_totals` 汇总分类和生成请求完整返回的三个标准 token 计数；生成用量缺失列入 `usage_missing_candidates`，分类用量缺失列入 `usage_missing_isf_classification`，不能把缺失项当作已确认的零费用。

所有候选完成所请求的阶段时退出 0；部分候选失败或 fuzz 有发现时退出 1，中断退出 130。候选执行状态 `passed` 不代表已证明语义有效。独立采样允许得到重复或失败候选，因此 N 表示请求的候选槽位数，而非 N 个不同且有效的 Harness。

## 复查与改进已有 Harness

需要调用 LLM 根据反馈改进时，使用下节的反馈再生成入口；本节 `--harness` 仅检查已有代码。

`--harness` 使用本地代码，跳过 API 和密钥检查，执行同样的格式检查、审阅提示与编译。新产物写入独立目录，原实验不变：

```bash
python3 -m harness_generation \
  --source runs/mini_parser/target.c \
  --function mp_parse \
  --harness runs/mini_parser/harness.c \
  --output runs/mini_parser_review
```

针对纯计算函数，如果调用结果未使用，`-O1` 可能删除关键计算。提示词 v2 要求将非 void 标量返回值和有效、已初始化的输出保存到类型匹配的局部 `volatile` 变量；仅写 `(void)result` 不能保护普通变量的计算。不要通过修改目标实现或给目标指针参数添加 `volatile` 来解决。

`benchmarks/mini_parser/` 是当前唯一维护的测试样例，来自 `/home/luchitong/work/mini_parser`。`benchmarks/mini_parser/harnesses/structured.c` 是 `fuzz/fuzz_structured.cpp` 的 C11 等价版本，可作为手写参考 Harness 与模型输出比较；它不是模型生成结果。用下面命令验证参考 Harness：

```bash
python3 -m harness_generation \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --harness benchmarks/mini_parser/harnesses/structured.c \
  --output runs/mini_parser_structured_reference
```

每次编译前保存 `review.json`，提示是否缺少直接目标调用或 `volatile`。检查忽略注释和字符串中的关键词，但只是词法启发式，可能误报或漏报（例如函数指针调用、无关 volatile、不可达调用）。始终标记为 `needs_review`；没有提示也不代表语义正确。审阅提示不改变编译成功的退出码。

## Feedback 驱动的下一轮生成

新增 `--parent-candidate` 和 `--feedback`：校验父候选身份与代码哈希后，将父 Harness、结构化反馈和证据片段组成新 prompt，调用 LLM 生成下一轮候选。每次命令仅推进一轮，仍可使用 `--candidates N`。完整格式、命令和限制见 [反馈再生成说明](docs/FEEDBACK.md)。

## 实验产物

| 文件 | 内容 |
| --- | --- |
| `experiment.json` | 实验根目录的候选索引、状态与成本汇总 |
| `target.c` | 输入源码的原样副本 |
| `isf_candidates.json` | tree-sitter 仅按 pointer 参数得到的语法候选 |
| `isf_classification.json` | 三种分类请求、响应、类别、投票结果与 token 用量 |
| `source_summary.json` | ISF 投票筛选后的语法摘要；Harness prompt 使用它而非完整源码 |
| `prompt.json` | 完整请求参数和提示词，不含密钥 |
| `response.txt` | API 响应正文，若意外回显密钥则脱敏 |
| `harness.c` | 提取后的 C Harness |
| `input_harness.txt` | 离线复查时的输入 Harness，即使验证失败也保留 |
| `review.json` | 自动审阅提示及人工检查清单 |
| `evaluation.json` | 十项指标结果、证据、评估器版本和仅基于已测维度的综合评分 |
| `automatic_feedback.json` | 自动提取的低分/错误质量维度反馈；不覆盖再生成父级反馈 |
| `compile_result.json` | 编译状态和耗时 |
| `smoke_result.json` / `smoke/` | 固定输入列表、逐输入状态、命令、日志及失败产物 |
| `metrics.json` | 各阶段原始观测、单位、测量范围和证据路径，不是综合分数 |
| `feedback.json` / `feedback_evidence.json` | 再生成时使用的结构化反馈和证据文本快照 |
| `parent_harness.c` | 再生成时的父 Harness 副本 |
| `compile_command.json` | 编译参数列表，相对于实验目录执行 |
| `compile_stdout.txt` / `compile_stderr.txt` | 编译诊断 |
| `fuzz_target` | 成功编译的可执行文件，仅在启用 fuzz 时自动运行 |
| `result.json` | 状态、失败阶段、模型、耗时、token 用量、提示词版本和源码/Harness SHA-256 |
| `fuzz_command.json` / `fuzz_result.json` | 启用 fuzz 时的执行命令和结果 |
| `fuzz_stdout.txt` / `fuzz_stderr.txt` | fuzz 日志、Sanitizer 诊断与统计 |
| `corpus/` / `artifacts/` | 工作语料和崩溃、超时等触发输入 |

尚未进行的阶段不会产生对应文件。缺少密钥时仍保存源码、提示词及失败结果；输入路径错误或输出目录已存在时，直接报告错误，不改变已有目录。

Harness 应包含一次 `#include "target.c"`，并定义 `int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)`。只编译 Harness 一个翻译单元：

```bash
clang -std=c11 -g -O1 -Wall -Wextra -Wpedantic -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all harness.c -o fuzz_target
```

编译限时 30 秒，保存超时前的诊断。命令成功返回 0，生成或编译失败返回 1，参数错误返回 2。`result.json` 分别记录 `generation` 与 `compilation.status`，编译失败不会被误记成生成失败。原始响应会在解析之前保存，便于检查空输出、截断、格式错误及 HTTP 错误。

离线模式记录 `mode=offline`、`generation=skipped`，不记录模型或 token 消耗；不要将离线编译算入模型首次生成成功率。候选结果保留原有阶段状态字段，新增来源字段；实验与候选结果 JSON 通过临时文件替换写入。Ctrl+C 返回 130 并尽量保留中断阶段。编译器警告保留在诊断中，不统一视为错误。

代码检查仅包括输出格式、包含文件和入口等基本结构；不是语义验证。模型仍可能生成错误参数、无效调用或重复实现，需要人工审阅。编译成功不等于 Harness 正确，更不等于发现漏洞。

## 启动 libFuzzer

先用已审阅的参考 Harness 运行 10 秒，不需要 API 密钥：

```bash
python3 -m harness_generation \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --harness benchmarks/mini_parser/harnesses/structured.c \
  --output runs/mini_parser_structured_fuzz \
  --fuzz-seconds 10 \
  --corpus benchmarks/mini_parser/corpus/structured
```

去掉 `--harness` 即为“API 生成 → 编译 → fuzz”。也可指向自己修改后的 Harness。`--fuzz-seconds` 默认 0，保持只编译行为；编译失败不会启动 fuzz。执行的是本机程序，时间和内存限制不构成沙箱，应先审阅模型生成的代码。

当前正的 `--fuzz-seconds` 会自动启用 **Compile → Smoke Test → Short Fuzz Run → Collect Metrics**：7 个固定输入逐个重放并通过后才运行 fuzz。只检查 Smoke 可用 `--smoke-test` 而不指定 fuzz 时间；`--smoke-test` 与 `--generate-only` 互斥。具体通过条件和指标解释见 [评分执行链路](docs/SCORING_PIPELINE.md)。

可用 `--corpus path/to/seeds` 提供初始语料：仅复制该目录直属的普通文件，忽略子目录与符号链接，按内容哈希命名，原语料不变。未提供时从空语料启动。默认最大生成输入长度 4096 字节、单输入超时 2 秒、RSS 限制 512 MB、随机种子 1。libFuzzer 按 `-max_total_time` 停止；外层在请求时长加 7 秒后强制清理进程组。固定种子不能保证按时间停止的实验完全相同。参数含义见 [LLVM libFuzzer 文档](https://llvm.org/docs/LibFuzzer.html#options)。

运行子进程仅继承必要的路径和语言环境，不传递 API 密钥；Sanitizer 设置由工具固定，发现错误即停止。日志直接写入文件，结束后提取执行次数、速度、峰值 RSS、`cov` 和 `ft`。这些是引擎报告的边/块与特征计数，包含 Harness 和插桩影响，不是目标源码覆盖率百分比。

| `fuzzing.status` | 含义 |
| --- | --- |
| `skipped` / `not_started` | 未启用 / 启用了但尚未运行 |
| `blocked` | 因编译或 Smoke 未通过而未启动 |
| `completed` | 在限时内正常结束，本次未报告错误 |
| `finding` | 检测到 Sanitizer/libFuzzer 错误或保存了失败输入，需要定位目标或 Harness 中的原因 |
| `wall_timeout` | 外层总超时，进程组已终止 |
| `interrupted` / `error` | 用户中断 / 启动或其他运行错误 |

`finding`、超时、运行错误返回 1，中断返回 130。没有发现错误不代表目标无漏洞。崩溃复现无需再次调用 API，在对应实验目录将保存的文件作为参数传给二进制：

```bash
cd runs/mini_parser_structured_fuzz
# 用 artifacts/ 中实际的文件名替换下面的占位名称。
./fuzz_target artifacts/crash-实际哈希
```

当前实现保存原始失败输入与报告，暂不做自动最小化、根因分析或修复。

## 离线验证

```bash
python3 -m unittest discover -s tests -v
```

测试不联网、不使用真实密钥。覆盖代码提取、截断和异常响应、单次 API 请求、密钥脱敏、缺失密钥、已有目录保护、编译超时，以及使用固定 Harness 的真实 Clang 编译成功与失败。Clang 存在但运行库缺失时，编译测试会失败，便于发现环境问题。

另外覆盖 `mini_parser` 参考 Harness 的离线编译、审阅提示、字符串与注释处理、中断记录，并检查 Clang `-O1` 生成的 LLVM IR，确认参考 Harness 保留了 `volatile` 观测。此回归只针对该样例，不构成任意模型输出的优化保留证明。

fuzz 测试实际运行 libFuzzer，验证正常限时结束，以及刻意构造的堆越界能被 ASan 捕获、保存并复现；另验证外层超时与中断清理、运行环境不携带密钥、缺少二进制时的错误分类。刻意越界样例仅存在于测试代码中。

多候选测试用模拟 API 验证 N 次独立请求、目录隔离、重复标记、温度配置、token 汇总、部分失败后继续、认证错误与中断停止，以及纯生成模式不启动编译。这些测试不代表真实模型的多候选生成效果。

## mini_parser 的真实 API 实验

在已配置密钥的同一个终端中执行。以下命令对 `mini_parser/mp_parse` 发起一次真实 DeepSeek 请求，编译成功后做 smoke 与 10 秒 fuzz：

```bash
experiment_dir="runs/mini_parser_api_$(date +%Y%m%d-%H%M%S)"
python3 -m harness_generation \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --output "$experiment_dir" \
  --fuzz-seconds 10 \
  --corpus benchmarks/mini_parser/corpus/structured

python3 - "$experiment_dir" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
result = json.loads((root / "result.json").read_text())
print("generation:", result.get("generation"))
print("compilation:", result.get("compilation", {}).get("status"))
print("smoke:", result.get("smoke", {}).get("status"))
print("fuzzing:", result.get("fuzzing", {}).get("status"))
PY
```

人工检查 `harness.c`：是否初始化并销毁 `mp_context`，是否调用 `mp_parse`，参数是否来自 fuzz 输入，是否构造合法 frame 的 magic、version、length 和 checksum，是否能在同一输入内执行多帧序列以触达 STORE → RELEASE → USE 这类状态路径。检查是否有提前返回导致目标调用不可达。将检查结论写入实验目录的 `review.md`，与编译结果分开记录。

一次请求的编译和 fuzz 结果只是本次候选的观测；保留网络和 API 失败，不通过反复生成挑选成功结果。离线模拟结果不算真实 API 实验结果。当前范围不包括源码覆盖率报告、自动修复、项目构建依赖解析或基于 AST 的项目级自动切片。
