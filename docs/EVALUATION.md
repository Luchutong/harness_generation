# Harness 评分与反馈接口

评分部分已包含 target-only coverage 测量器、tree-sitter Harness 静态质量信号、
短 fuzz 执行速度信号，以及默认的聚合、候选选择、自动反馈和下一轮规划策略。
Determinism / State Reset 仍只在存在专门的 in-process replay artifact 时测量，
不会由 Smoke 伪造。给定反馈的单轮再生成已接入，见 [反馈再生成](FEEDBACK.md)。
前七项是主要研究指标，后三项保留独立接口；主要指标标记不等于必须测得分数。

## 指标目录

`evaluation.registry.METRIC_SPECS` 按以下顺序定义目标和预期证据，每项由一个 `MetricId` 对应的评估器负责。预期证据描述质量维度，并不表示每一次候选执行都已采集。

| 优先级 | 指标 ID | 目标 | 后续评估器的输入证据 |
| --- | --- | --- | --- |
| 主要 | `reachability` | 大多数 testcase 真正进入目标 API | 总 case 数、目标实际进入次数及对应输入 |
| 主要 | `coverage` | 探索目标 edge / branch / function | 目标范围覆盖、执行预算、初始语料 |
| 主要 | `execution_speed` | 单 case 执行快，避免昂贵初始化和 I/O | 执行时间、case 数、初始化成本、环境 |
| 主要 | `determinism` | 同一输入路径和结果稳定 | 重复输入、路径签名、结果与随机种子 |
| 主要 | `state_reset` | case 之间互不污染 | 不同 case 顺序、进程内重放与新进程对照 |
| 主要 | `input_expressiveness` | 输入控制多个关键参数及其关系 | 输入到参数映射、参数变化、API 契约 |
| 主要 | `deep_reachability` | 触达深层或安全敏感逻辑 | 指定敏感函数集合、调用轨迹、深层触达记录 |
| 扩展 | `crash_fidelity` | 不吞掉 Sanitizer 和崩溃信号 | 已知故障探针、信号、诊断及退出码 |
| 扩展 | `resource_bound` | 输入、内存与循环等资源有界 | 配置限制、实际资源观测及边界压力测试 |
| 扩展 | `target_isolation` | 直接调用核心 API，减少 CLI 等中间层 | 调用图、入口轨迹与封装依赖 |

三种触达相关信号应分开：Reachability 衡量入口触达比例，Coverage 衡量目标代码探索广度，Deep Reachability 衡量指定深层目标是否被进入。当前 libFuzzer 的进程级统计不能直接替代这些目标范围的测量。Determinism 需要同输入重放，State Reset 还需要改变历史 case 序列；两者不能相互代替。

## 单项接口与结果

每个评估器实现 `MetricEvaluator`：提供 `metric_id`，实现 `evaluate(context) -> MetricResult`。注册到 `EvaluationEngine` 后，在固定目录顺序执行，不能重复注册同一个指标。

`EvaluationContext` 提供候选编号、父候选、轮次、目标函数、源码/Harness 哈希、候选目录与阶段结果快照。通过 `context.artifact("fuzz_result.json")` 获取本候选内的路径；文件可能不存在。评估器应只读原始源码、Harness 和既有结果；将未来新增探针的产物单独保存，并记录其成本。

每个 `MetricResult` 包含：

- `metric_id`、`status`、`evaluator`、`version`、`reason`。
- `measurements`：带名称、值、单位和作用范围的原始观测。
- `evidence`：产物路径、解释及可选的行号、JSON pointer 或 testcase 标识。
- `score`：可选的 [0, 1] 归一化质量分数，统一为越高越好。原始速度或内存指标仍保留自己的单位与方向，具体归一化方法由未来评估器定义和版本化。

| 状态 | 语义 |
| --- | --- |
| `not_implemented` | 尚未注册该项评估器 |
| `unavailable` | 已有评估器，但所需证据缺失 |
| `measured` | 已有原始观测和证据；可暂不提供归一化分数 |
| `not_applicable` | 有理由确认不适用，不能用来隐藏未实现功能 |
| `error` | 评估器失败或返回结果不合法 |

未测量的指标不允许写分数；`measured` 必须包含观测与证据。框架检查结果格式，不验证证据真实性或测量方法科学性。评估器普通异常转换为该指标的 `error`，其他指标继续；Ctrl+C 向上层传递。评估器错误单独记录，不把已成功的生成/编译阶段改成失败；需要读取 `evaluation.status` 判断评估是否完整。

## Target-only Coverage

`TargetCoverageCollector` 使用 LLVM source-based coverage 构建单独的 coverage 版 libFuzzer executable，运行有界输入预算，然后通过 `llvm-profdata` 与 `llvm-cov export` 生成 JSON。汇总时只保留 `TargetBuildConfig.source_files` 对应的目标源码文件，排除 generated harness 和 libFuzzer runtime，因此它与 libFuzzer 进程级 `cov/ft` 不是同一类信号。

FT artifact 输出位置：

```text
artifacts/<project>/coverage/<ft_id>/run_001/
  commands.json
  coverage_export.json
  target_coverage.json
  stdout.txt
  stderr.txt
```

simple 项目示例：

```bash
python3 -m harness_generation measure-target \
  --artifacts artifacts/simple \
  --ft ft_parser_from_memory_a5265df23ba0 \
  --project-root tests/fixtures/simple_project \
  --runs 64
```

如果 C 参考 harness 已经直接 `#include` 目标实现文件，例如 `benchmarks/mini_parser/harnesses/structured.c`，使用 `--harness-language c` 和 `--harness-includes-target`，让目标源码只作为 coverage 过滤范围而不重复编译。生成的 Harness 默认按 C++17 编译和链接：

```bash
python3 -m harness_generation measure-target \
  --artifacts artifacts/mini_parser \
  --ft ft_mini_parser_structured \
  --project-root benchmarks/mini_parser \
  --harness benchmarks/mini_parser/harnesses/structured.c \
  --target-source benchmarks/mini_parser/target.c \
  --include benchmarks/mini_parser \
  --corpus benchmarks/mini_parser/corpus/structured \
  --harness-language c \
  --harness-includes-target \
  --runs 64
```

`TargetCoverageEvaluator` 可注册到 `EvaluationEngine`，读取 `target_coverage.json` 并输出 `scope="target_code"` 的函数、行、region、branch 覆盖观测。它不会自动触发生成、rollback 或 fuzz 优化；后续 feedback/候选迭代应把该 artifact 当作质量证据，而不是 validation pass/fail 条件。

## 接入示例

下面只展示接口接入，仍未实现 Reachability 测量：

```python
from harness_generation.evaluation import (
    EvaluationEngine, MetricId, MetricResult, MetricStatus,
)

class ReachabilityEvaluator:
    metric_id = MetricId.REACHABILITY

    def evaluate(self, context):
        return MetricResult(
            metric_id=self.metric_id,
            status=MetricStatus.UNAVAILABLE,
            evaluator="reachability_probe",
            version="0.1",
            reason="目标入口探针尚未实现，没有进入次数和总 case 数。",
        )

engine = EvaluationEngine([ReachabilityEvaluator()])
# 已有配置与源码的调用方可注入：
# run_experiment(config, source_bytes, count=5, evaluation_engine=engine)
# 或 run_candidate(config, source_bytes, evaluation_engine=engine)
```

默认候选执行会注册标准 multi-dimensional evaluator：Harness 存在时可测 tree-sitter
静态 Reachability、Input Expressiveness、Crash Fidelity、Resource Bound、Target
Isolation；短 fuzz 成功写入 executions/s 时可测 Execution Speed。target-only
coverage 仍需通过 `measure-target` 或 Python API 显式运行，并将 summary 放入候选目录
才会进入该候选报告；Determinism / State Reset 要求专门 replay artifact。每个已开始
处理的候选，即使生成或编译失败，也尝试保存 `evaluation.json`；拥有 Harness 的候选还会
保存 `automatic_feedback.json`。未启动候选没有报告。`result.json` 和实验候选索引保存
报告状态。默认候选报告使用 versioned weighted aggregation；直接创建的空
`EvaluationEngine()` 仍保持 `not_configured`，便于自定义实验。

在评估器调用前，现有执行链路收集 `metrics.json`，包含编译、Smoke 和短时 fuzz 的阶段结果及原始观测。评估器可用 `context.artifact("metrics.json")` 读取它；测量范围必须保留，不将 Smoke 完成率或引擎整体 cov 当作目标触达/覆盖。参见 [评分执行链路](SCORING_PIPELINE.md)。

## 综合评分、选择与反馈契约

`iteration.py` 中定义以下 Python Protocol、数据类型和默认策略。候选生成 CLI 默认不自动调用这些策略；研究调度器可以在同目标、同预算的候选报告上显式调用：

| 接口 / 默认实现 | 输入 → 输出 | 责任 |
| --- | --- | --- |
| `AggregationPolicy.aggregate` / `WeightedAggregationPolicy` | `EvaluationReport` → `AggregateResult` | 对已测且有分数的指标做加权平均；缺失项不补零 |
| `CandidateSelector.select` / `ScoreCandidateSelector` | 候选报告列表及 limit → `SelectionResult` | 按总分降序、候选 ID 升序稳定选择，可按 Harness 哈希去重 |
| `FeedbackBuilder.build` / `AutomaticFeedbackBuilder` | 上下文与报告 → `FeedbackPacket` | 从阶段失败、review warning 和低分/错误指标提取事实、假设、建议与证据 |
| `IterationPlanner.plan` / `FeedbackDrivenIterationPlanner` | 选择结果与反馈列表 → `RegenerationRequest` 列表 | 描述下一轮从哪些父候选生成多少子候选，并限制总子候选数 |

`AggregateResult` 默认仍为 `not_configured`，因为单候选执行本身不假设可比较的预算或完整指标。`WeightedAggregationPolicy` 可返回 `insufficient_evidence` 或带策略版本的 `scored`，但只使用 `measured` 且带 `score` 的指标；未知、不可用或未实现指标不会被补成 0。默认权重覆盖十项指标，主要指标权重较高，且策略版本记录在结果中。存在 `error` 指标时仍可计算已测分数，但 `eligible=False`。

反馈条目用 `observation`、`hypothesis`、`suggestion` 分开事实与推测，事实必须附证据；`metric_id=None` 支持编译等非指标反馈。反馈包绑定候选、轮次和代码哈希。`RegenerationRequest` 校验反馈属于指定父候选且下一轮索引恰好加一，并要求生成数为正。

`CandidateConfig` 使用 `parent_id` 与 `round_index` 记录来源，初始采样使用空父候选和第 0 轮。`--parent-candidate` 与 `--feedback` 已支持哈希匹配校验和下一轮独立请求；`feedback-loop` 进一步将自动反馈、评分、选择和再生成接成有界的单谱系多轮执行。它每轮只从通过阶段门槛的 child 中稳定选择一个父候选，所有选择和拒绝原因都写入 `feedback_loop.json`。完整的多父候选预算搜索仍待实现。

## 验证

```bash
python3 -m unittest discover -s tests -v
```

新增测试验证十项默认空分数、主次指标顺序、单项注册、缺失证据、异常隔离、错误指标返回、非法分数、报告落盘、反馈父子关系、默认聚合/选择/自动反馈/下一轮规划策略，以及 target-only coverage 的 JSON 过滤、评估器消费和真实 LLVM coverage 构建路径。测试中的分数只用于验证数据契约，不代表任何真实 Harness 的最终评分。
