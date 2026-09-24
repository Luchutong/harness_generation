# Harness Generation

面向 C 项目的 LLM-assisted libFuzzer harness generation 研究原型。
项目把静态结构分析、语义角色判断、Function Triplet、HarnessPlan、代码生成和编译运行反馈串成一条可审计流水线。

## 项目现状

仓库当前保留一条最小真实项目路径：以 `benchmarks/json_parser/project` 作为目标，完成真实 LLM 语义分析、Structural Flow Graph（SFG）、Function Triplet 抽取与选择、Stage 1–4 harness 生成、编译、链接、runtime 检查和 fuzz smoke。

最小 demo 的输入是 `json.c`、`json.h` 和 `target_build.json`；生成结果属于运行时 artifact，不作为版本库内容维护。

这条路径已经完成真实 API 验证：语义决策完整返回，目标 FT 被选中，Stage 1–4、Intermediate、Compiler、Linker、Runtime 和 Fuzz smoke 均通过。模型响应、源码摘要、生成 harness 和阶段状态由脚本输出到独立 artifact 目录，便于复核但不会进入提交历史。

## 已取得成果

- 建立了从项目级静态分析到可编译、可运行 harness 的端到端流程。
- 用 SFG 和 Function Triplet 表达输入、处理、释放及结构关系，减少生成阶段直接面对完整源码的依赖。
- 将编译、链接、runtime、smoke 和结构验证纳入生成闸门，能够拒绝明显缺少目标调用、输入连接或资源处理的候选。
- 在真实项目 `markdown-wasm` 中复现了一个真实的 memory-safety / semantic defect：fork 中的 Unicode case-folding signedness 修改把失败索引 `-1` 保存为 `unsigned`，native 64-bit + ASan 可触发越界读和 SEGV，wasm32 产物则出现 silent label confusion。
- 通过 reference harness 和源码分析完成了该 finding 的独立归因，区分了目标缺陷、生成 harness 缺陷和环境问题。
- 在 `json_parser` 实验中确认了 `json_parse_ex` 的 `max_memory` 二阶段失败路径存在资源泄漏，并验证了修复方向；这类发现需要独立复现和人工归因，不能把 fuzz artifact 数量直接当作漏洞数量。
- 真实 fuzz 也暴露了生成质量闸门的盲区：一个被标记为 `stable_promoted` 的 harness 仍可能包含 ABI 错配、长度与缓冲不一致、栈对象生命周期错误和每次执行泄漏等问题。修补后同一目标的覆盖从 661 条边提高到 1033 条边，且长时间运行无 artifact。

## 局限

- 当前展示路径集中在一个小型 C 项目，不能代表跨项目泛化能力。
- callback table、typedef callback、ownership、生命周期、派生缓冲和长度污点仍是生成与验证中的高风险区域。
- 编译通过、runtime 通过、没有崩溃或覆盖增长，都不能单独证明 harness 语义正确。
- smoke 输入可能没有执行所有控制分支；静态 validator 也无法覆盖所有 API ABI 和资源契约。
- fuzz 覆盖统计混合了 harness 与目标库的插桩边，不能直接解释为目标源码覆盖率。
- markdown-wasm 案例的 native crash 和 wasm 语义后果已经复现，但其在具体应用中是否形成稳定可利用漏洞仍未确认。
- 当前缺少跨项目、预算匹配、不同随机种子和系统消融实验，尚不能据此宣称方法优于其他 harness generation 基线。

## 可能的推进方向

1. 扩大到不同解析器、编码器和资源生命周期模型的独立项目评测，并固定工具链、语料和预算。
2. 强化 callback ABI、callback table 初始化、ownership、释放顺序、长度一致性和派生缓冲污点的静态与运行时验证。
3. 让 smoke 阶段根据控制字节、错误路径和资源增长自动生成覆盖更全面的输入，而不是只依赖空输入和单个最小输入。
4. 增加 reference harness、差分测试、wasm/native 对照和平台感知的语义检查，覆盖 silent output mismatch 等非崩溃 finding。
5. 引入目标代码限定的 coverage、独立复评、预算匹配对照和消融实验，区分模型采样、反馈机制、评分器与搜索策略的贡献。
6. 将已确认的生成失败模式转化为可执行的 Stage 4 约束和 regression corpus，避免“能编译但不可安全运行”的 harness 被晋升。

## 保留内容

当前展示分支只保留运行最小 demo 所需的代码与输入：

- `harness_generation/`：harness 生成与验证流水线
- `sfg_builder/`：项目级静态分析与语义图构建
- `scripts/run_minimal_demo.sh`：最小真实项目 demo 入口
- `benchmarks/json_parser/project/`：demo 目标源码
- `benchmarks/json_parser/target_build.json`：demo 构建描述
- `pyproject.toml`、`.env.example`、`project_catalog.py`：项目元数据与运行配置模板

详细过程记录、实验日志、历史 artifact、开发测试和其他 benchmark 不属于展示分支。
