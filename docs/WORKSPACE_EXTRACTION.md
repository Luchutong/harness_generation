# HG v0.3 工作区抽取说明

整理日期：2026-10-08。此次任务只整理当前开发的新链、建立独立工作区并发布新分支；没有补齐分析规则、改变生成门禁或恢复测试。

## 来源与 Git 边界

来源目录为 `/home/luchitong/work/harness_generation`，抽取目录为 `/home/luchitong/work/HG`。来源是含未提交开发改动的工作区，因此此次内容来自磁盘上的当前快照，而不是把原 `v0.2` 已提交版本直接复制后当作最新版。

HG 使用独立的 Git worktree 和 `v0.3` 分支。原 `v0.2` 工作区、未提交修改及历史实验产物保留在原目录；抽取提交仅位于新工作区。Git 的历史仍保留既有版本，当前 `v0.3` 工作树中排除旧执行链。目录抽取、提交和推送不等同于框架行为验证。

来源父提交为 `59b6afb55e382eec3c62427e3273502455315285`。逐文件来源、目标摘要、保留和排除清单见 [抽取清单](WORKSPACE_EXTRACTION_MANIFEST.json)。清单为此次 HG 内容单独计算源码身份，包含 Python 模块、项目目录模型、打包配置和 DSH 资产；这是一份抽取身份记录，不是 fresh-run 注册或验证报告。

## 保留的新链

```text
parser-only 静态产物
  → Candidate Discovery / Validation
  → Semantic Slice
  → Minimal FT
  → Harness Context / API Closure / Canonical Construction
  → Semantic Obligation Graph / Closure Gate
  → Frozen HarnessPlan
  → 代码翻译 / 代码契约校验 / build / runtime
```

保留上述阶段的传递依赖，包括源码索引与证据签发、类型和结构模型、值流与资源身份、原生模型适配器、预算与账本、候选修订事务、DSH 受限 Context 后端、目标构建支持，以及选定的测试、脚本和 benchmark 资料。代码模型仍只消费已冻结 Plan。

共享结构层中的 `LegacyStructuralClosure` 是对既有弱结构图的遍历及关系投影。名称中的 `Legacy` 表示兼容已有图表示；它没有恢复旧 FunctionTriplet 构造、ProtocolIR 或旧生成调度。新链不以这种弱关系作为完整语义证明。

## 排除的旧链与本地产物

旧 SFG 语义工作流、legacy FunctionTriplet 构造与排序、Protocol Mining / ProtocolIR、旧 Stage 1–4 生成调度、旧反馈优化流程及其入口不随抽取保留。共享解析、模型数据结构和目标构建组件仅按新链实际依赖保留。

没有整体复制旧 README 和明确旧链文档；HG README 与架构导航独立整理。旧 `run_minimal_demo.sh` 等执行入口、直接要求旧执行器的测试也不进入新工作区。测试的选择兼顾测试间 fixture 依赖，不将缺少 fixture 的测试文件作为完整回归套件。

原 `artifacts/`、虚拟环境、缓存、构建输出、嵌套 worktree 和实际凭据均不作为抽取内容。benchmark 源码及其许可证可保留，ground truth 和 reference 是独立评测资料，不能输入生产语义调查来补事实。

## 文档与证据边界

本次选取 42 份新链相关历史文档。HG 的 `FRAMEWORK_ARCHITECTURE_AND_LIMITATIONS.md` 改为当前新链导航，其原报告仍完整保留在来源工作区；其他历史报告保留原阶段、日期、失败、版本和结论。用户当前阅读的 [Canonical Construction](CANONICAL_CONSTRUCTION_REPORT.md)、[Agent 补证据](AGENT_PROOF_INVESTIGATION_REPORT.md)、[Semantic Closure](SEMANTIC_CLOSURE_FRAMEWORK_REPORT.md) 均属于保留范围。

历史报告中的旧 fingerprint、policy、commit 和测试数字绑定当时冻结版本。此次裁剪入口和依赖后的 HG 内容具有自己的身份，不能沿用旧 fingerprint 宣称兼容恢复或新版本通过。原版本的暂停记录、失败和成本不重新归类。

报告中的相对 `../artifacts/` 链接没有随迁移变成 HG 内的有效原始证据链接。原始数据只能在来源工作区的对应位置查阅，例如 `/home/luchitong/work/harness_generation/artifacts/`。部分历史运行脚本默认读取这些外部输入；保留脚本表示保留评测工具，不表示从 HG 空目录即可复现旧 cohort。依赖原工作区绝对路径的单项历史重放测试已从抽取测试定义中排除。

保留的旧 `scripts/blind_eval/freeze.py` / `identity.py` 只覆盖原有 Python 清单，没有纳入 DSH 运行资产。这是历史工具的已有边界，不能作为完整 DSH 冻结器；此次整理没有开发新的盲测冻结规则。

## 此次没有形成的新验证结论

此次整理没有安装依赖、执行 pytest、fixture、provider 请求、fresh run、Gate / Plan 重建、build 或 runtime。任何文本、AST、导入依赖或 Git 完整性检查，都只是抽取完整性检查，不能代替行为回归。

抽取完整性检查覆盖 238 个 Python 文件的 AST 语法、DSH 桥接文件的 JavaScript 语法、打包配置、本地模块依赖和七个 CLI 入口。保留 86 个测试文件但没有执行。来源工作区的 557 个快照文件逐一核对摘要，确认本次整理未修改这些原文件。

当前测试继续暂停。2026-10-08 原工作区 cJSON 已完成 parse 中，native 和 DSH 各 Slice 3/3、Context 0/3，Plan/build/runtime 未到达。DSH 会话能正常完成，但端到端稳定性尚未改善；详见 [缺口分析](CJSON_AGENT_BACKEND_GAP_ANALYSIS.md)。既不能把此历史失败抹去，也不能把其他旧版通过记录当作 HG `v0.3` 通过。

恢复评测时，应为 HG 登记新的源码和配置 identity、目标源码、预算、后端与完整 trial 计划，使用新运行目录并保留全部失败和中断。此次工作区整理不启动该评测。
