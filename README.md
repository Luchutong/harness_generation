# Harness Generation

面向 C 项目的 LLM-assisted libFuzzer harness generation 研究原型。
项目把静态结构分析、语义角色判断、Function Triplet、HarnessPlan、代码生成和编译运行反馈串成一条可审计流水线。

## 项目现状

当前新主链为 `Static Analysis → Candidate Validation → Semantic Slice → Minimal FT → Harness Context / API Closure → Completeness Gate → HarnessPlan → C/C++ → compile → runtime`。参数构造由 Argument Graph 与 semantic proposals 经 Reconciler 形成 Canonical Construction Contract；只有 `generation_allowed=true && frozen=true` 才允许生成。代码模型只翻译 Plan。

当前框架各层职责、支持范围、验证证据、主要不足和后续验收标准见 [框架与局限报告](docs/FRAMEWORK_ARCHITECTURE_AND_LIMITATIONS.md)。最新离线 410 项回归通过；最终 fingerprint 的 native 证据只有 shared-context 单例端到端成功，尚不能宣称跨项目稳定性。

旧 `generate` 保留最小真实项目 baseline：以 `benchmarks/json_parser/project` 为目标，执行 SFG、FunctionTriplet、Stage 1–4、编译链接和 fuzz smoke。新链的 `context-generate` 跳过旧 Stage 1–3，不加载 legacy ProtocolIR。

最小 demo 的输入是 `json.c`、`json.h` 和 `target_build.json`；生成结果属于运行时 artifact，不作为版本库内容维护。

## 阶段演进与实验记录

以下记录对应各阶段当时的实现和冻结版本；当前接口与限制以框架报告为准。

Candidate Discovery 与 FT Construction 现在可以独立执行：`harness-generation candidates --artifacts <目录> --policy legacy` 生成完整的入口假设目录，`harness-generation triplets --artifacts <目录>` 消费它。新目录位于 `candidate_discovery/candidates.json`，保留未选择和 oversized 的候选；现有 SFG 的根目录 `candidates.json` 继续保留。接口、宽候选策略和兼容路径见 [架构说明](docs/CANDIDATE_DISCOVERY_ARCHITECTURE.md)。

新增独立的 DeepSeek 候选语义验证：`harness-generation candidate-validate --artifacts <目录> --provider deepseek`，通过受限源码查询工具产生 `validated_candidates.json`、证据和对话 trace。它保留宽候选，执行后停在验证 artifact，尚未接入 FT 筛选。配置、预算、resume 语义和手工 smoke 见 [实现报告](docs/CANDIDATE_SEMANTIC_VALIDATION.md)。

候选验证现冻结为 `recall-first-entry-validation-v3`，增加一次独立的 terminal schema repair。后续命令 `harness-generation semantic-slice --artifacts <目录> --provider deepseek` 消费 accepted 验证记录，区分 CORE / SUPPORT / EXCLUDE / UNRESOLVED，并保存独立的 `semantic_slices/<candidate-id>/`。共享类型仅用于调查；该阶段停在 slice artifact。接口、101 项测试和真实 DeepSeek smoke 见 [本轮报告](docs/SEMANTIC_SLICE_IMPLEMENTATION_REPORT.md)。

新增无 LLM 的确定性投影阶段：`harness-generation minimal-ft --artifacts <目录> [--candidate <function-id-or-candidate-id>] [--resume]` 消费已有 Semantic Slice，原样投影 CORE 集合，保存 SUPPORT 候选、已有关系和未知依赖。结果位于 `minimal_fts/<ft-id>/`，允许 1 至 N 个 CORE；该阶段停在 Minimal FT。schema、身份、恢复规则、146 项测试及四组已有真实 Slice 的无模型 smoke 见 [Minimal FT 实现报告](docs/MINIMAL_FT_IMPLEMENTATION_REPORT.md)。

下一阶段 `harness-generation harness-context --artifacts <目录> --provider deepseek --model deepseek-flash --thinking disabled [--resume]` 围绕 frozen FT 生成确定性 requirements，通过有界只读工具调查 input/lifecycle/ownership 等契约，保存独立 API Closure，并由 deterministic Completeness Gate 决定是否冻结 Context。hard missing 阻止生成；本阶段止于 Context。187 项测试、预算与恢复规则、真实 smoke 结果及 HTTP 402 复测限制见 [Harness Context 实现报告](docs/HARNESS_CONTEXT_IMPLEMENTATION_REPORT.md)。

新入口 `harness-generation context-generate --artifacts <目录> --env-file .env --build --runtime [--resume]` 消费实际的 `minimal_ft.json + harness_context.json + api_closure.json`，重新验证冻结输入及 Completeness Gate，再确定性构建独立的 HarnessPlan。只有 `generation_allowed=true && frozen=true` 才可进入生成；模型仅将 Plan 翻译为 C/C++。新链跳过 Stage 1–3，且不加载 legacy FunctionTriplet 或 ProtocolIR。旧 `generate` 和 Stage 1–4 保留为 baseline；新链的 Stage 4 位于 `harness_generation/context_generation/stage4.py`。

Candidate、Slice 和 Context 支持 `--provider openai-compatible --env-file .env`，读取 `LLM_API_KEY / LLM_BASE_URL / LLM_MODEL / LLM_THINKING`，通过原生 tool calling 调查。Context 默认按同一函数合并模型请求，保留每条 requirement 的独立证据和门禁；`--requirement-mode single` 可运行逐条 baseline。重复 support 问题按精确 API ID 合并，已取得的证据复用，creator/cleanup 的结构候选定向排序。输入、模型配置、构建输入及输出摘要用于恢复验证；凭证不进入 artifact。

新链命令、230 项回归测试、模型实测、编译运行结果和保守限制见 [Frozen Context 生成报告](docs/CONTEXT_GENERATION_IMPLEMENTATION_REPORT.md)。复现脚本为 `scripts/smoke_harness_context.py` 和 `scripts/smoke_context_pipeline.py`。后者从新的 parser-only 静态 artifact 开始执行真实 Candidate → Slice → FT → Context → Plan → Harness → compile → runtime；其中小型 API 样例是合成 fixture，不能代替跨项目实验。`scripts/smoke_plan_translation.py` 单独评价真实 Plan 翻译，冻结输入为显式 fixture 契约，不代表整链模型完成度。

本轮增加源码值流资源身份、精确 callback ABI/userdata、无显式 length 的 NUL string 契约，以及有来源的 hard/soft ordering graph。269 项离线回归通过；真实首轮 direct/NUL 完整链通过，owned-return 后续重试通过，shared-context 和外部 callback context 仍被严格 Gate 阻止。schema 的真实 prompt-token 开销下降约 26–30%；完整结果分类、成本和保留的失败见 [Harness Context 语义边界报告](docs/HARNESS_CONTEXT_SEMANTICS_REPORT.md)。

新增可重算的 construction source，连接局部 creator-return/consumer/cleanup 与字段状态转换，并明确公开 callback context 的 stack、字段初始化和有效期；不新增 Agent 工具。284 项离线回归通过。五类 API 模型各 5 次固定预算真实实验，Slice 24/25、Context 14/25、compile/runtime 13/25；后续保留原始事实的框架配对重放为 Context 19/25、compile/runtime 17/25。仍有返回语义、wrapper 和代码 cleanup 缺口，不能宣称跨项目稳定。逐次成本、修复、独立 Plan 复测及边界见 [参数构造与重复实验报告](docs/CONSTRUCTION_AND_REPEAT_REPORT.md)。重复 runner 为 `scripts/repeat_context_pipeline.py`，配对 runner 为 `scripts/repeat_context_reproject.py`。

上述 direct buffer、NUL string、shared context、owned return、callback 五类 fixture 现正式归入 **Development / Regression Set**。新增盲测框架位于 `scripts/blind_eval/`：先冻结生产源码、版本、模型和预算，再使用 `benchmarks/blind/` 的独立样例进行 fresh native A/B/C 消融。Ground truth 只供 worker 退出后的评估使用。正式 V2 盲测完成 240 次 fresh attempts：Slice 127/240、Context 0/240，生成/编译/runtime 未执行；104 次受到 HTTP 429 影响，不能视为每模式五次完整模型轨迹的稳定性验证。十二种新语义结构和四个真实项目的入口分开统计；显式 anchor 实验属于 semantic pipeline evaluation，不报告 Candidate recall。实验方法、逐次结果、false complete 和能力边界见 [盲测泛化报告](docs/BLIND_GENERALIZATION_EVALUATION.md)。

2026-09-29 服务恢复后的独立复测已按用户要求暂停：完成 52/240 次、中断 4 次、未启动 184 次；Slice 45/52，Context complete 0/52，生成/编译/runtime 未执行。全部完成试验均取得模型响应，但仍有请求错误；这轮部分结果不能作为五次重复稳定性验证。见[复测暂停报告](docs/BLIND_GENERALIZATION_RETEST.md)。

Harness Context 新增确定性的 Argument Construction Graph 与递归依赖解析：参数、creator-return/out origin、局部 alias/字段、cleanup 和有证据的 state ordering 共享可重算图，Agent 围绕图缺口调查，ownership 仍单独验证。发布 `argument_graph.json` 并通过原 Gate 重算校验；provider 请求失败与模型明确 unresolved 分开记录。351 项离线测试通过；五类 fresh native 开发 smoke 均保存并实际使用图，owned-return 跑通编译和六个固定输入运行，其余样例仍被严格 Gate 拦截。另有两个固定预算的请求回放修复补测，分版本保留。实现、逐次结果和未支持情况见 [Argument Graph 实现报告](docs/ARGUMENT_CONSTRUCTION_GRAPH_REPORT.md)。未启动新的完整 blind cohort。

Graph 与 semantic proposals 现经 `GraphContractReconciler` 形成唯一 Canonical Construction Contract，Gate 与 HarnessPlan schema 2 共用同一 recipe；支持递归 creator 参数、独立 out cell/pointee 和有界 scalar IR，并验证生成代码的资源与表达式绑定。六类固定预算 fresh native smoke：Slice 6/6，Context/compile/runtime 1/6；shared-context 七个 canonical 参数闭合，仍因独立资源身份冲突 invalid。真实供应商对照复现 malformed history 的 400 → normalization 后 200，native terminal repair 也实际触发并通过该路径。实现、离线编译回归、逐次成本、冻结 fingerprint 和剩余限制见 [Canonical Construction 报告](docs/CANONICAL_CONSTRUCTION_REPORT.md)。这些合成样例仅属 Development / Regression，完整 blind cohort 继续暂停。

资源身份现与调用点 initialization/state 义务分开发布；proposal 阶段拒绝 input 携带 resource ID，强制参数范围参与 canonical recipe 筛选，CORE 输入可达由独立 External Input Flow 重算。未增加 Agent 工具或预算。最终离线回归 384 项通过；六类各两次固定预算 native trial 为 Slice 11/12、Context/compile/runtime 1/12，仍被 ownership、支持 API 契约及 callback 缺口限制。整链 249 个成功响应、2,671,396 tokens，另有九次 timeout。原始冻结实验与事后函数指针遮蔽修复的 fingerprint 分开记录，后者没有重跑 native；完整证据与局限见 [Value / State Contract 报告](docs/VALUE_STATE_CONTRACT_REPORT.md)。

CORE 现要求可重放的源码 inclusion proof；Context 使用声明签发的 ownership subjects 和 source-issued support registry，scalar 无 ownership 主体，native dependencies 由同一 semantic API 选择派生。离线回归 399 项通过；六类各五次 fresh native 为 Slice 14/30、Context 0/30，编译/runtime 未运行。有效 FT 的 usage CORE 为 0/14，但 support wrapper、terminal JSON 和 lifecycle 仍造成失败；整链 420 个成功响应、5,885,838 tokens，不能据此宣称端到端稳定性或泛化提升。逐次成本、冻结版本及剩余边界见 [CORE / Proposal 边界报告](docs/CORE_AND_PROPOSAL_BOUNDARY_REPORT.md)。

Slice 进一步改为选择 source-issued role choice，SUPPORT 绑定源码 effect 与确切参数/return/pointee，input/length 同组共享一次选择，out storage 与产出对象身份分开；提示改为初始 registry 加增量。最终离线 410 项回归通过。本轮三个冻结版本分别完成六类 fresh native（Context/compile/runtime 4/6）、中间约束版三例（0/3）、最终修正版 shared-context 单例（1/1，零硬缺口）。十份 FT 均未将 usage 纳入 CORE；callback 仍未跑通，中间版误拒绝已修复，terminal JSON 和 timeout 仍有失败记录。不同版本不合并成功率，未恢复完整 blind cohort。实现、固定预算成本、失败及源码归档见 [Subject Effect / Binding 报告](docs/SUBJECT_EFFECT_AND_BINDING_REPORT.md)。

旧 `generate` 展示路径已完成开发目标的真实 API 验证：语义决策完整返回，目标 FT 被选中，Stage 1–4、Intermediate、Compiler、Linker、Runtime 和 Fuzz smoke 均通过。模型响应、源码摘要、生成 harness 和阶段状态由脚本输出到独立 artifact 目录，便于复核但不会进入提交历史。

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

当前开发分支保留主链、baseline、测试与评测输入：

- `harness_generation/`：harness 生成与验证流水线
- `sfg_builder/`：项目级静态分析与语义图构建
- `scripts/run_minimal_demo.sh`：最小真实项目 demo 入口
- `benchmarks/json_parser/project/`：demo 目标源码
- `benchmarks/json_parser/target_build.json`：demo 构建描述
- `pyproject.toml`、`.env.example`、`project_catalog.py`：项目元数据与运行配置模板
- `benchmarks/json_parser/LEAK_REPORT.md`、`docs/CASE_STUDY_MARKDOWN_WASM.md`：两个已确认 bug case study 的报告
- `tests/`：契约、负例、协议、Plan、编译与 runtime 回归
- `benchmarks/blind/`、`scripts/blind_eval/`：历史独立评测样例、带许可证的目标源码、reference/ground truth 和冻结评测工具
- `docs/`：架构、阶段实现、实验结果及局限报告

模型对话、生成 harness、构建产物和原始实验 artifacts 保留在本地 `artifacts/`，不进入源码提交。报告中的本地 artifact 链接需配套运行数据才能复核；历史评测样例用于开发后，不再作为新盲测的未见数据。
