# v0.1 架构与所有权

## 项目级流水线

```text
C 项目
  └─ sfg_builder ──> functions / annotations / flows / sfg
                         │
                         └─ triplet_extractor ──> triplets.json
                                                  │
目标源码 ──> protocol_miner ──> protocol_ir.json ─┤ 可选
                                                  ▼
                              orchestrator ──> Stage 1–4
                                                  │
                              pipeline_validation ─┘
                                                  ▼
                                harness + pipeline_result + 测量
```

`sfg_builder/` 只负责项目级源代码解析、候选发现、语义标注和图构建。
`harness_generation/` 中的 `sfg_adapter.py` 把这些 JSON 读入，
`triplet_extractor.py` 建立 FT，`triplet.py` 定义 FT 的磁盘表示。
`protocol_miner.py` 静态抽取帧与常量事实；`protocol_conventions.py` 可用 LLM
推断调用惯用法；`protocol_ir.py` 合并为类型化契约。`project_functions.py` 与
`protocol_reconciliation.py` 在 Stage 4 前核对项目可链接函数与 IR 声明。

`stage1.py` 到 `stage4.py` 分别生成函数说明、片段、初稿与最终 harness。
`orchestrator.py` 管理阶段状态、重试与回滚；`pipeline_validation.py` 管理阶段
验证和构建/运行检查；`pipeline_result.py` 汇总结果。`artifacts.py` 拥有项目级
产物路径及写入约定。入口在 `generation_cli.py`，由 `cli.py` 分发。

`protocol_ir.json` 与 FT 是平行输入：协议挖掘不会自动提取 FT；生成命令也不会
自动挖掘协议。缺少 IR 时采用 FT-only 路径，存在但无效时报告错误。

## 候选与反馈路径

```text
单文件源码 + 函数名 ──> source_analysis / isf ──> candidate
                                               └─> experiment
                                                    └─> assessment / evaluation
                                                         └─> feedback / feedback_loop
```

这条路径由 `cli.py` 的 `--source` 参数入口启动，实验配置在 `config.py`，
候选生成与执行由 `candidate.py`、`experiment.py`、`core.py` 组织。
`evaluation/` 保存指标与信号类型，`feedback.py` 和 `feedback_loop.py` 实现
反馈再生成。它与项目级 FT 流水线的输出目录、协议输入和运行状态不同，不能把
一条路径的 `protocol.json` 当作另一条路径的 `protocol_ir.json`。

## 共用组件与边界

| 组件 | 所有权 |
| --- | --- |
| `llm.py`、`llm_config.py` | 模型客户端、mock/录制响应与配置解析 |
| `prompts.py`、`policy.py` | 分阶段 prompt 与策略常量 |
| `compiler_validation.py`、`fuzzer_build.py`、`target_build.py`、`runtime_validation.py` | 构建、链接和运行校验 |
| `target_coverage.py`、`coverage_arms.py`、`generation_variance.py` | 目标代码覆盖与对照测量 |
| `records.py` | JSON 记录写入工具 |

包内模块在 v0.1 保留现有 import 路径；以上分组是维护边界。改动阶段逻辑时检查
`orchestrator` 与 `pipeline_validation` 的契约，改动 IR 时检查对账、plan 校验和
Stage 4 消费者。命令行参数以 `harness-generation <subcommand> --help` 为准。

## 目录与记录

项目级产物根目录由 `--output` 或 `--artifacts` 指定，记录目录下的
`functions.json`、`triplets.json`、`protocol_ir.json`、`generation/<ft_id>/`、
`harnesses/<ft_id>.c` 各有独立用途。`pipeline_result.json` 是一次 FT 运行摘要，
attempt 目录保留阶段失败证据；覆盖报告不能从“没有测量”推导为低覆盖。

`benchmarks/` 存放目标与参考实现，`tests/fixtures/` 存放测试可复现的录制输入，
`artifacts/simple` 和 `artifacts/deepseek_real` 是已跟踪的历史运行样例。
新实验默认写入 `runs/`，避免把本地临时产物混入发布内容。
