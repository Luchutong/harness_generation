# 文档索引

先读[项目首页](../README.md)了解安装、命令和仓库结构，再按任务选择文档。
本文档中的路径均相对仓库根目录；实验报告记录的是指定目标、模型和预算下的结果。

## 使用与架构

| 文档 | 内容 |
| --- | --- |
| [架构说明](ARCHITECTURE.md) | 模块所有者、数据流、两条运行路径及产物边界 |
| [SFG](SFG.md) | 项目解析、语义分析和图构建 |
| [Harness Pipeline](HARNESS_PIPELINE.md) | FT、Stage 1–4、校验、回滚与 CLI |
| [候选与反馈实验](CANDIDATE_WORKFLOW.md) | 原首页保存的单文件候选路线与研究设计 |
| [评分接口](EVALUATION.md)、[反馈](FEEDBACK.md)、[评分执行](SCORING_PIPELINE.md) | 候选路线的评估和反馈 |

## 协议模型与工程设计

| 文档 | 内容 |
| --- | --- |
| [Protocol Format Mining](PROTOCOL_FORMAT_MINING.md) | A/B/C 块抽取与落地映射 |
| [ProtocolIR Related Work](PROTOCOL_IR_RELATED_WORK.md) | 相关工作和核实记录 |
| [ProtocolIR Method Transfer](PROTOCOL_IR_METHOD_TRANSFER.md) | 类型化事实、状态关系与评测方法 |
| [Framework Pain Points](FRAMEWORK_PAIN_POINTS.md) | P0–P5 问题、实施状态与证据 |
| [SFG Phase 1 Spec](sfg_phase1_spec.md)、[Pipeline Spec](harness_pipeline_spec.md)、[E2E Closure Spec](e2e_closure_spec.md) | 详细设计和实施记录；以当前代码与使用说明为运行接口 |

## 测量与故障复盘

| 文档 | 内容 |
| --- | --- |
| [Coverage Equivalence](COVERAGE_EQUIVALENCE.md) | 固定 benchmark 的覆盖对照；由测量 JSON 渲染 |
| [Generation Variance](GENERATION_VARIANCE.md) | 三次独立生成与 seed 内波动 |
| [Direct Source Baseline](DIRECT_SOURCE_BASELINE.md) | 一次源码直喂模型的对比 |
| [ProtocolIR Contract Path Blocker](PROTOCOL_IR_CONTRACT_PATH_BLOCKER.md) | 真实 Stage 4 交互故障及修复背景 |

报告及录制 fixture 保留原路径，便于复核文中的 provenance 和再生成命令。
