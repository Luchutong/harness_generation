# HG v0.3 新链架构与阅读导航

日期：2026-10-08。此文件是 HG 抽取后的导航。原工作区同名的历史架构基线报告保留在 `/home/luchitong/work/harness_generation/docs/FRAMEWORK_ARCHITECTURE_AND_LIMITATIONS.md`，其中的旧 fingerprint 和实验成绩不绑定此次抽取版本。

HG 当前流程为：

```text
源码解析 → 候选目录 / 入口验证 → Semantic Slice → Minimal FT
  → Context 调查与候选修订 → API Closure / Canonical Construction
  → Semantic Obligation Graph → Closure Gate
  → Frozen HarnessPlan → C/C++ 翻译 → build / runtime
```

| 层次 | 职责 | 主要资料 |
| --- | --- | --- |
| 源码与入口 | 解析函数、类型与源码 identity；保存宽候选，受限 Agent 验证入口语义 | [Candidate Validation](CANDIDATE_SEMANTIC_VALIDATION.md)、[数据流](FRAMEWORK_EXECUTION_AND_DATA_FLOW.md) |
| Slice 与 FT | 区分 CORE / SUPPORT / EXCLUDE / UNRESOLVED；确定性投影 Minimal FT | [Semantic Slice](SEMANTIC_SLICE_IMPLEMENTATION_REPORT.md)、[Minimal FT](MINIMAL_FT_IMPLEMENTATION_REPORT.md) |
| 构造与调查 | 组织参数、资源、callback、input、ownership 与 lifecycle；查询和复用已签发证据 | [Argument Graph](ARGUMENT_CONSTRUCTION_GRAPH_REPORT.md)、[Canonical Construction](CANONICAL_CONSTRUCTION_REPORT.md)、[Agent 补证据](AGENT_PROOF_INVESTIGATION_REPORT.md) |
| 修订与门禁 | 校验候选事务，失败回滚；重算语义义务与必需根闭合，核验冻结 identity | [修订事务](CONTEXT_REPAIR_TRANSACTION_REPORT.md)、[Semantic Closure](SEMANTIC_CLOSURE_FRAMEWORK_REPORT.md) |
| Plan 与执行 | 由闭合 Context 确定性构建 Plan；代码模型翻译，框架校验代码并构建运行 | [Context 生成](CONTEXT_GENERATION_IMPLEMENTATION_REPORT.md)、[数据流](FRAMEWORK_EXECUTION_AND_DATA_FLOW.md) |
| Agent 后端 | native 为默认；DSH 执行一次受限 Context 调查，沿用模型账本、工具、预算和 Gate | [DSH 接入](DEEPSEEK_HARNESS_INTEGRATION.md)、[Agent 改进](AGENT_CAPABILITY_AND_PROMPT_IMPROVEMENT_REPORT.md) |

静态分析采用源码证据驱动的有界规则，签名匹配和源码已读取不自动产生效果证明。复杂间接调用、全局 hook、宏/ABI、条件所有权、别名、递归和循环仍存在覆盖缺口。Gate 要求所选方案的 mandatory roots 全部闭合，并拒绝输入身份错误和契约冲突；模型的 `resolved` 标签不能代替重算。

反馈、回滚和预算内重新调查已经存在，但不能自动创造静态层尚不支持的证明。模型重复错误字段、schema/JSON 修复失败、prompt 容量和预算停止也可能导致不生成 harness。当前 cJSON native 与 DSH 均为 Context 0/3，完整证据与局限见 [cJSON 缺口分析](CJSON_AGENT_BACKEND_GAP_ANALYSIS.md)。

此次只抽取新链，没有恢复测试或实施上述补齐。历史报告及原始 artifact 的使用边界见 [工作区抽取说明](WORKSPACE_EXTRACTION.md)，安装和七步 CLI 示例见 [README](../README.md)。
