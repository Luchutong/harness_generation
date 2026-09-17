# 评分之前的执行与指标采集链路

```text
Harness
  ↓
Compile
  ↓ 成功
Smoke Test
  ↓ 通过
Short Fuzz Run
  ↓
Collect Metrics
  ↓
Multi-dimensional MetricEvaluator → aggregate → evidence-bound feedback
```

这是评分的数据准备层。当前不会把执行成功直接换算成质量分数；编译失败、Smoke 发现异常、fuzz 超时等情况仍收集已得到的证据，而不是丢弃候选或给所有维度填零。

## 1. Compile

编译原始 `target.c` 和 Harness 所组成的单翻译单元，沿用 Clang C11、`-O1`、libFuzzer、ASan、UBSan，以及发现未定义行为即停止的配置，限时 30 秒。

生成 `compile_command.json`、`compile_result.json` 和编译日志。编译成功才可进入 Smoke；失败时后续启用的阶段记录为 `blocked`。编译警告保留，暂不统一视为失败。

## 2. Smoke Test

目的：快速发现启动失败、明显崩溃、Sanitizer 错误、卡死以及常见输入边界问题，不证明 Harness 语义有效。

固定套件 v1 包含 7 个输入：

| 输入 | 大小 |
| --- | --- |
| 空输入 | 0 |
| `00` | 1 |
| `FF` | 1 |
| 两字节全零 | 2 |
| 八字节全零 | 8 |
| `00` 到 `1F` 的递增字节 | 32 |
| 全 `FF` | 4096 |

每个输入使用新的进程，通过 libFuzzer 的文件重放模式执行，不变异；每例外层限时 7 秒，libFuzzer 单输入限时 2 秒、RSS 限制 512 MB。保存输入文件及其 SHA-256、命令、退出码、时间和 stdout/stderr。原语料不参与这一固定套件，`--corpus` 只作为后续短时 fuzz 的种子输入。

全部进程正常退出、没有检测到 Sanitizer/libFuzzer 错误，并观察到引擎报告重放完成时为 `passed`。否则在首个异常处停止，保留后续输入的 `not_started` 状态。异常区分 `finding`、`wall_timeout`、`interrupted` 和 `error`。

一个 Smoke `finding` 可能来自真实目标缺陷，也可能来自 Harness 参数错误，不能自动认定 Harness 无效。这里暂停后续 fuzz 以保留证据，等待归因；不会吞掉异常并继续把结果标为成功。

进程可能执行引擎初始化回调，因此“7 个固定输入完成”不是目标被调用 7 次的证明。新进程隔离能避免测试间污染，但不能测量持久进程中的 State Reset，也不能作为 Determinism 的证据。

## 3. Short Fuzz Run

Smoke 通过后，复用限时 fuzz 模块。用 `--fuzz-seconds` 配置每候选的 fuzz 时长，例如 10 秒；现有单输入、内存、最大生成长度和随机种子限制保持不变。

产物仍为 `fuzz_result.json`、运行日志、`corpus/` 和 `artifacts/`。当前 API 中的低层 `run_fuzzer` 可单独调用，正式候选执行入口通过 `execute_pipeline` 保证 Smoke 在前。同一组候选应使用一致时间、初始语料及环境进行比较。

## 4. Collect Metrics

`assessment.collect_metrics(result)` 汇总已有阶段结果，保存 `metrics.json`。各观测包含 `name`、`value`、`unit`、`scope` 和 `evidence`。缺失观测不填零；真实测得的零值会保留。

| 原始指标 | 作用范围 | 当前可以说明什么 |
| --- | --- | --- |
| 编译时间 | build | 构建成本，不是执行速度 |
| Smoke 请求、尝试、完成 case 数 | fixed_input_replay | 固定套件完成情况，不是目标入口触达率 |
| Smoke 耗时 | processes_including_startup | 包括进程启动和插桩开销的检测成本 |
| 执行次数、平均 executions/s | instrumented_program | 整体 fuzz 引擎执行统计，不是隔离后的目标 API 延迟 |
| cov、ft | instrumented_program | 目标、Harness 和插桩共同影响的探索信号，不是目标源码覆盖率 |
| 峰值 RSS | instrumented_program | 实际引擎进程观测，不证明所有输入下资源有界 |
| fuzz 墙钟时间 | process_including_startup | 实際运行成本，可能略超过引擎设置的时长 |

`metrics.status=collected` 只表示收集到了至少一个观测；例如编译失败后也可能只有编译耗时。应同时读取 `stages` 和具体观测，不能推断完整链路通过。

随后候选执行链使用默认的 multi-dimensional `EvaluationEngine`，把
`harness.c`、`metrics.json`、可选的 `target_coverage.json` 和可选的
`replay_quality.json` 转为 `evaluation.json`。候选拥有 Harness 时会再保存
`automatic_feedback.json`：每个改进建议都保留对应 metric、观测、假设、建议和
artifact evidence，供下一轮受谱系校验的再生成使用。默认聚合只计算已经实际测得
且有分数的维度；未知项永远不会补为 0。

当前默认信号如下。`harness_static` 是 tree-sitter AST 的保守启发式，用来筛选或
定位改进方向，不能替代动态 probe；`instrumented_program` 的速度也不能声称是
隔离的目标 API 延迟。

| 指标 | 当前信号 | 证据范围 | 限制 |
| --- | --- | --- | --- |
| `reachability` | Entry point 内直接 target call、是否受 guard 包围 | `harness_static` | 静态潜在可达性，不计真实进入次数 |
| `coverage` | LLVM target-only coverage | `target_code` | 需显式运行 `measure-target` 并提供 artifact |
| `execution_speed` | 短 fuzz 的 executions/s | `instrumented_program` | 需相同预算与环境比较 |
| `determinism` | in-process replay artifact | `in_process_replay` | 当前没有 replay artifact 时为 `unavailable` |
| `state_reset` | in-process sequence replay artifact | `in_process_replay` | fresh-process Smoke 不能替代它 |
| `input_expressiveness` | Data/Size 到 target 参数的 AST 依赖、字段/控制点 | `harness_static` | 不证明实际 target 分支被执行 |
| `deep_reachability` | target-only entered functions 与 target call graph 的最大深度 | `target_code` | 不是安全敏感性结论 |
| `crash_fidelity` | 是否有 signal/longjmp/exit 等明显屏蔽调用 | `harness_static` | 静态缺失不证明 sanitizer 一定保留 |
| `resource_bound` | input-dependent loop / allocation 的静态边界迹象 | `harness_static` | 不能证明全部运行都受限 |
| `target_isolation` | 直接 target call 与明显 I/O/process detour | `harness_static` | 不等于完整调用图证明 |

要让 Coverage / Deep Reachability 进入同一候选的报告，需将 target-only summary
保存为候选目录的 `target_coverage.json`；要让 Determinism / State Reset 成为
`measured`，in-process probe 必须写入候选目录的 `replay_quality.json`，其中分别有
`determinism`、`state_reset` 的 `attempted_cases` 与 `matching_cases`。框架不会把
Smoke 成功伪造成这两项证据。

## 使用方法

完整链路，不调用 API：

```bash
python3 -m harness_generation \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --harness benchmarks/mini_parser/harnesses/structured.c \
  --output runs/mini_parser_assessment_example \
  --fuzz-seconds 10 \
  --corpus benchmarks/mini_parser/corpus/structured
```

只编译并 Smoke：将 `--fuzz-seconds 10` 替换为 `--smoke-test`。只生成仍使用 `--generate-only`，默认不加上述参数仍只编译。多候选和反馈再生成共用这条执行链路。

## 下一步评分工作

优先补实际 target-entry probe 与 in-process replay collector，再校准 Execution
Speed 的分母和初始化成本。静态 Input Expressiveness / Resource Bound / Isolation
信号应与 target-only coverage 联合用于候选选择，不能单独证明 Harness 的语义质量。
策略层已经提供 versioned weighted aggregation、稳定选择和 bounded feedback-driven
planning；完整的多轮预算调度仍由上层研究控制器负责。
