# 当前框架的执行机制与数据流

日期：2026-10-06（Asia/Shanghai）。本文说明当前 Main 实现，生产 fingerprint 为 11c9ce7d57fcacec4645ac12328aa38636abfbe37d2f5330b923657eef348ad6，共 171 个生产文件。测试已按用户要求暂停；本文通过读取源码和已保存产物编写，没有恢复测试、模型请求、重放或构建。本日后续的调度、反馈和提示改进见 [Agent 能力与提示改进报告](AGENT_CAPABILITY_AND_PROMPT_IMPROVEMENT_REPORT.md)；下文 cJSON 观察仍来自此前 170 文件的冻结版本。

框架先把项目源码转换为可查询的函数和类型索引，再调查候选入口及其关联 API，形成有来源的语义提案。确定性代码将这些提案整理为参数、资源、状态和调用依赖图；所有必需语义义务闭合后冻结 Context，构建可执行 HarnessPlan，最后由代码模型翻译成 C/C++ harness，并检查代码、编译和固定输入运行结果。

最终 harness 的直接输入是经过验证的 Plan。项目源码、Agent 的回答和中间提案，要经过多层校验才能进入这个 Plan。

## 1. 当前有两条执行链

当前开发主链是：

~~~text
项目源码
  → Static Analysis
  → Candidate Discovery / Validation
  → Semantic Slice
  → Minimal FT
  → Harness Context / API Closure
  → Semantic Obligation Graph / Completeness Gate
  → HarnessPlan
  → C/C++ harness
  → code validation
  → compile / fixed-input runtime
~~~

旧链使用 SFG、legacy FunctionTriplet、Stage 1–4 和 ProtocolIR，由 generate、generate-all、run 等命令组织，保留作 baseline。新链的 context-generate 跳过旧 Stage 1–3，不把 legacy ProtocolIR 当作执行依据。新链中某些旧关系可以用于比较，但不能凭旧 FT 或旧 complete 标签授权生成。

各个新阶段提供独立 CLI，并且多数支持批量消费已有产物。目前完整项目的源码边界、构建配置、全局成本和阶段串联仍由实验脚本组织。给出项目目录后自动完成所有这些决策的通用调度层，尚未完善。

~~~mermaid
flowchart TD
    A[项目源码与解析范围] --> B[函数和类型索引]
    B --> C[自动候选目录]
    C --> D[Agent 验证入口]
    D --> E[Agent 调查 Semantic Slice]
    E --> F[确定性 Minimal FT]
    F --> G[Context requirements]
    G --> H[Agent 查询源码并提交 typed proposals]
    H --> I[契约归一化与依赖图]
    I --> J{必需义务是否闭合}
    J -->|缺失证明且预算可用| K[精确反馈与候选修订]
    K --> H
    J -->|未闭合或输入无效| L[保存缺口与停止原因]
    J -->|闭合| M[Frozen Context]
    M --> N[确定性 HarnessPlan]
    N --> O[代码模型翻译]
    O --> P[代码校验]
    P --> V[编译链接]
    R[构建配置] --> V
    V --> Q[固定输入运行与结果归档]
~~~

构建配置沿另一条路径进入编译器：它说明源文件、头文件、include path、compiler flags 和 link flags，不替代 Context 中的 API 语义证明。

## 2. 数据分为哪几类

| 数据 | 表达什么 | 能否直接授权生成 |
| --- | --- | --- |
| Function / type record | 函数身份、签名、参数、正文、结构体等静态信息 | 不能，知道函数存在不等于知道安全调用方式 |
| Candidate | 可能的 fuzz 入口及排序信号 | 不能，尚需语义验证 |
| Slice | CORE、SUPPORT、EXCLUDE、UNRESOLVED 分类及其来源 | 不能，还没有完整调用契约 |
| Minimal FT | 固定核心目标、支持候选和未决依赖 | 不能，确定了调查对象但未完成构造 |
| Requirement | 必须回答的输入、参数、生命周期等问题 | 不能，它是任务 |
| Evidence | 工具发行的源码、类型、调用点或语义选项记录 | 单条证据不能；必须证明具体主体和谓词 |
| Fact / resolution | Agent 提出的有类型的语义结论及调查状态 | 不能仅凭 resolved 标签 |
| Canonical contract / graph | 框架整理的参数 recipe、资源来源、状态和依赖关系 | 仍需义务闭合检查 |
| Completeness report | 必需根、阻塞叶、证明状态、验证错误和生成许可 | 满足当前验证器和冻结身份后才能授权 |
| HarnessPlan | 明确的 API 调用、参数构造、资源绑定、顺序和清理 | 代码模型据此翻译 |
| Harness / build / runtime | 生成代码及各层实际执行结果 | 文件存在、编译成功、运行成功分别记录 |

Evidence ID、fact ID、requirement ID、resource ID 和 invocation ID 表达不同身份。某两个值类型相同，或者由同一个 creator API 产生，并不意味着它们是同一个运行时对象。

## 3. 项目怎样进入框架

### 3.1 输入首先需要有明确边界

项目输入包含 project root、待索引的 C/头文件范围、排除目录，以及构建需要的源文件和配置。CProjectParser 支持 source_globs 和 ignored_directories；默认排除部分构建、版本控制和依赖目录。

源码目录可能同时存在库、测试、vendor、历史 harness 和生成产物。把它们全部扫描会引入重复定义、测试辅助入口和不属于目标的调用样例。因此“确定分析范围”是项目接入的一部分。当前有默认发现能力，也支持显式配置；仍不能自动保证任意仓库的边界和构建选项都正确。

本轮 cJSON 使用 project/cJSON.c 和 project/cJSON.h，是因为该目录只包含目标库的两个文件。父目录的旧 harness 和 framework 产物没有进入新模型输入。

### 3.2 Parser 产生静态索引

Parser 使用 tree-sitter 提取函数定义和声明、参数、返回类型、pointer depth、结构体、类型别名、部分 callback typedef、访问提示，以及原始源码范围和正文。函数身份通常包含相对文件、行号和符号名，例如：

~~~text
cJSON.c:1091:cJSON_ParseWithLengthOpts
~~~

functions.json 当前为 schema version 3，保存项目和源文件身份。查询与恢复阶段会利用源文件摘要核验当前代码是否仍与索引一致。

Parser 的结构信息具有能力边界。它不是完整的编译器预处理结果；宏包装声明和条件编译可能留下 error nodes，或者包含当前构建条件下未启用的定义。当前 cJSON 的 CJSON_PUBLIC 返回类型可以归一化，但 CJSON_CDECL 包装的 hook 字段仍存在结构化解析缺口。完整函数索引不意味着所有 callback ABI 都已识别。

### 3.3 完整 SFG 与 parser-only 输入

完整 SFGPipeline 可进一步构建 annotations、flows、sfg、ownership 和 usage_patterns；语义后端可以是 mock、LLM 或受约束的 replay。默认 mock 的结果不能被解释为真实模型已经调查项目。

当前 fresh 主链也支持 parser-only 输入：写入真实 functions.json，并提供空的 annotations、flows 和 SFG 容器，让 Candidate、Slice、Context Agent 从源码重新取得必要证据。cJSON 本轮使用的就是这一方式，没有把旧语义结论作为前提。

这里的 parser-only 由实验 runner 调用 Parser API 并写入配套容器实现；当前 SFG CLI 没有公开 --parser-only 参数。

根目录 candidates.json 属于 SFG 阶段；candidate_discovery/candidates.json 属于后续新入口发现阶段，二者不能混用。

## 4. 自动发现入口与验证入口

### 4.1 Candidate Discovery 自动保留和排序

discover_candidates 遍历解析函数，生成完整候选目录。其信号包括字节指针、疑似长度参数、上下文参数、解析类函数名、返回资源、访问提示和已有 usage 信息。

这些信号是候选排序依据。例如参数名像 length，能够产生 buffer/length 候选，但此处明确没有证明该长度的单位或语义。优先级取信号分数，不是成功概率。

broad 策略选择有定义的函数，并可通过 max_candidates 限制处理数量；未选中的函数保留 deferred reason。legacy 策略依据已有 ISF 标签选择下一批处理对象，仍保留完整目录。

候选发现没有模型调用，也不生成 FT。

### 4.2 Candidate Validation 调查入口语义

CandidateValidationAgent 通过受限 repository tools 读取函数、类型、源码范围、调用关系和引用。模型必须用已发行证据回答入口是否成立，以及外部输入以何种方式进入处理过程。

结果保存在 validated_candidates.json 和各候选的调查文档中，包含 accepted、rejected、unresolved 等状态、input_mode、reason_codes、open_questions、预算和 trace。

不指定 --candidate 时，CLI 会处理 catalog 选中的候选；指定时可以只验证某个已登记函数。每个候选独立受预算约束。批量运行不等于具备全项目总预算管理；115 个候选各自用足预算，可能远超一次指定入口的成本。

**命令 exit 0 表示该批处理正常完成，不保证候选 accepted。** unresolved 是合法的调查结果。下游 Slice 只接受已通过验证的候选，调度器需要检查语义状态。

### 4.3 本轮为什么手动固定入口

cJSON 的候选目录自动包含 115 个函数；ParseWithLengthOpts 排名 1，PrintPreallocated 排名 3，PrintUnformatted 排名 61。目录包含 37 个 static 函数，说明宽候选策略尚未等同于最终公开可调用入口选择。

本轮指定三个 anchor，是为了重复同一目标并覆盖不同结构。框架具备自动候选发现和批量验证能力，但这轮指定入口实验没有测量入口召回率、排序质量或全项目调度成本。

## 5. Semantic Slice 如何形成 Minimal FT

SemanticSliceAgent 从 accepted anchor 扩展有界调查 frontier。关联函数、共享类型和调用关系帮助决定调查哪里；函数的实际角色必须由源码支持。

框架发行带身份和证据的 role choices，模型选择这些选项，不能任意填写一个角色便把函数提升为 CORE。主要分类如下：

| 角色 | 在数据流中的作用 |
| --- | --- |
| CORE | 需要完成语义调用闭合的核心目标集合 |
| SUPPORT | 可用于构造、初始化、清理、callback 或配置的候选 |
| EXCLUDE | 已有依据排除；后续不能随意重新纳入 |
| UNRESOLVED | 暂无足够证据；必须保留具体缺失证明问题 |

上表用大写表示概念；持久化的 classification.role 实际使用 core、support、exclude、unresolved。原生 Slice 提交选择已发行的 choice_id，并填写 open_questions，而不是任意提交角色文字。

CORE 的 inclusion、SUPPORT 的 effect 和 EXCLUDE 的依据都受到确定性规则约束。共享类型可以提示调查，但不能单独证明角色。Slice 保存分类、源码选项、证据、未决 frontier、预算、metadata 和 trace。

MinimalFTBuilder 消费已有 Slice，确定性地投影核心集合、支持候选、已有关系和 unresolved_dependencies。它不调用模型，也不重新扫描项目来补全未知结论。结果写入 minimal_fts/<ft_id>/minimal_ft.json，并绑定 Slice 与 ProjectSnapshot 的身份。

Minimal FT 允许多个 CORE，名称中的 triplet 不代表当前实现永远只有三个函数。它也不承诺 SUPPORT 都必须执行。

**support_candidates 为空表示 Slice 没有提供支持候选，并不自动关闭后续 Context 的项目内来源发现能力。** Context 仍可在授权源码范围和 discovery budget 内寻找 creator、feeder、initializer 或 cleanup，随后验证它们。

## 6. Context 怎样把调查结果整理为调用契约

### 6.1 先建立 requirements

HarnessRequirementBuilder 根据 CORE、签名、静态主体和已知关联，建立带稳定身份的调查任务。主要 kind 为：

| Requirement | 要证明的内容 |
| --- | --- |
| input_binding | fuzz bytes 如何到达 API，是否经过复制、NUL、scalar 或 context |
| argument_construction | 每个参数来自输入、常量、stack、creator、callback 或已有资源 |
| buffer_length | 长度与哪个 buffer 关联，单位、capacity、NUL 和派生关系 |
| lifecycle | 资源的创建、初始化、复用范围和清理 |
| ownership | owned、borrowed、transferred、static 及释放责任 |
| return_semantics | 成功条件、nullable、owned return 和错误清理 |
| state | 调用前是否需要 initialized、input_fed、reset 等状态 |
| call_order | 创建、初始化、使用和清理的必要顺序 |
| callback | ABI、绑定来源、userdata、nullable 和有效期 |
| support_decision | 支持 API 是否确有必要、属于哪一种 effect |

任务不是只按函数名建立。参数、return、field、out-pointee 和 runtime origin 都可能成为独立主体；一种 API 下可有多个需要分别证明的对象。

### 6.2 Agent 看见的是有范围的调查材料

HarnessContextAgent 接收 FT、任务、已知提案、证明 agenda、可用源码选项和剩余预算。当前支持同函数 grouped 调查，也保留 single 模式。

分组可以一次取得多个 requirement 的回答，但每条仍有独立 resolution 和证据。真实 provider 请求由 group cost owner 计一次，其余成员保存引用和投影。

当前提示按调查 slots 的 kind 选取显式规则块，missing_tasks 只发送一次。retained_entries 只展示精确证书覆盖且投影未变的完整行；其他旧提案仍带 proof_status 作为 observed_proposals 展示。

主体 bootstrap 后的自动证据准备，默认每次最多新增 8 次工具操作，并受当前 global/optional 余额约束、保留一条 Agent 查询。整组包含 ownership/lifecycle 时，先调查已发行主体正文里的确切返回清理调用，再递归通用 helper；旧授权正文通过 cache 回显给 Agent。

Agent 通过工具读取源码，工具返回发行的 evidence records、查询截断信息和来源身份。每次工具操作、源码字符和模型请求都受 MiningState 的全局预算约束。

“索引中存在函数”和“Agent 已经取得证明该函数作用的证据”是两件事。工具的 max_references_per_query、max_lines_per_read、max_chars_per_record 可能截断结果。Agent 应使用精确 callee、调用点或源码范围补读，不能把截断列表当作完整项目。

### 6.3 原生提交先经过严格解析

模型 terminal 必须提交有类型的 resolution，包含状态、facts、已发现 API 依赖、证据引用和未决问题。输入约束、ownership、lifecycle 等有各自的 schema，不能把任意自由文字当作契约。

框架在局部 merge 之前捕获 native_submission 和 digest，保存真正的模型提交。无合法原生提交时产生的 unresolved fallback，标记为 no_validated_native_submission，不冒充模型提出的事实。

facts 通过 schema 和引用校验，只说明它们是合法提案。模型填写 resolved，也不意味着语义义务已 proved。提示投影区分 observed_proposals 和已有证明覆盖，避免把尚未证明的回答重新展示成确定事实。

### 6.4 API Closure 递归补充实际依赖

如果 CORE 需要 creator、初始化、feeder 或 cleanup，框架解析其依赖和 effect，将有依据的支持 API 纳入 required_support_apis，并建立这些 API 自身的 requirements。

例如树对象需要先创建，creator 又需要输入 buffer，cleanup 必须收到原来创建的树。这些依赖会递归展开，直到达到支持函数数量、深度或其他预算上限。

SUPPORT candidate、required support、optional support、rejected support 分别保存。没有被证明必要的候选不能仅因名字相似而进入最终调用序列。API Closure 要回答“为了调用 CORE，还必须执行哪些 API”；这些 API 的参数和生命周期也必须闭合。

进入 required_support_apis 不等于该调用已经 proved；它的参数、effect 和生命周期仍接受后续图与 Gate 检查。

### 6.5 多种图把事实变成规范契约

框架围绕统一的对象和调用主体建立、重算并协调多个投影：

- Argument Graph 表达参数依赖、creator-return/out origin、局部 alias、字段和 callback forwarding。
- GraphContractReconciler 结合语义提案与源码图，形成唯一 canonical construction recipe；多个冲突来源不能静默选一个。
- Resource Contract 表达运行时对象身份、产生位置、借用关系和清理绑定。
- Invocation Contract 表达某次调用的前置状态和状态转换；对象“存在”与对象“已初始化/已喂输入”分开。
- External Input Flow 检查 CORE 的输入是否确实来自 fuzz input，或由有来源的有限路径传播。
- Ordering Graph 表达有依据的 hard/soft 顺序及 cycle；同类型对象不自动共享顺序或生命周期。

out-parameter 的 pointer cell 与其产出的 pointee 分开建模。Cell 可能在 harness stack 上，pointee 可能由库分配并需要库清理；释放责任不能混到一起。

框架的 source evaluators 为受支持的源码模式生成可重算证书，例如明确的字段初始化、同对象清理、有限输入转发或调用范围。不受支持的宏、alias、分支或 ABI，可能仍保留 unknown。确定性验证器有自己的覆盖边界，并不是完整程序正确性证明系统。

## 7. Completeness Gate 如何决定闭合

SemanticObligationGraphBuilder 把规范契约组织为义务节点。节点包含主体、谓词、证据、局部证明、依赖、诊断和 proof_status；mandatory_roots 表示生成前必须成立的根义务。

一个参数构造根可以依赖 creator 调用，creator 调用再依赖其输入、状态和资源来源。父义务自身已有局部证明，但依赖尚未成立时，父义务仍不能闭合。Frontier 定位应补的阻塞叶，避免重新调查整个父任务。

HarnessContextCompletenessValidator 重新计算图闭合、必需覆盖和摘要，生成：

~~~text
status = complete | incomplete | invalid
generation_allowed
hard_missing
soft_unknowns
validation_errors
resolved_requirements / unresolved_requirements
semantic_obligation_graph
~~~

invalid 表示契约或图存在验证错误；incomplete 表示有效但必要证明还缺失；complete 要求无验证错误且所有必需根闭合。非必需 soft unknown 单独保留。

Context 的 frozen 字段由框架在闭合后发布。生成阶段还会重新加载和核验真实源码、FT、Context、API Closure、义务图和最新 resolution。保存过 complete 标签不能绕过当前验证器。

## 8. 错误如何反馈、修订和回滚

### 8.1 几种修复不是同一个操作

terminal/schema repair 处理合法 JSON、必需字段、类型和发行选项等输出问题。Context semantic revision 处理已有提案与证明缺口。Framework source reconciliation 根据既有源码证书重算提案。Code repair 修正已生成代码与 frozen Plan 不一致的问题。

这些操作分别计数。source-only 发布没有模型调用；schema 修复成功不代表 Context 已闭合；带 unresolved fallback 的 attempt 目录也不代表一次真实 provider 请求。

### 8.2 Context 的修订路径

Completeness 反馈包含最早未闭合主体、缺失谓词、旧提案字段、关联 requirement、证据和合法选项。需要共同修改的 argument/input/extent 等槽位进入 linked repair group，不能先提交半套修改。

首次调查没有旧基线时，框架接收严格解析的提案并归一化。后续修订以 local merge 前捕获的 native_submission 为 incoming；候选从全量旧 resolutions 的副本开始，把整个关联组的新旧提案合并，保留未提交和批外槽位。仅在现有源码验证器提供撤销证书时退休旧提案，再固定点协调并重算 API Closure、Context 和义务图。

候选必须满足现有校验：不产生新验证错误或主体冲突，不丢失已经 proved 的义务，并补齐明确反馈要求的局部证明。仅仅减少 hard gap 数量不足以授权替换。

~~~text
修订前的活跃基线（可能尚未闭合）
  → 原生候选提交
  → 独立候选投影与证明重算
      → committed：发布通过事务校验的候选；整个 Context 仍可能未闭合
      → rejected：丢弃候选，保留修订前基线与具体拒因
      → no_progress：语义和证明状态没有实质进展
      → execution failure：保留真实调用失败，不能冒充语义纠正
~~~

每个 requirement 最多一次无新增证据的 primary revision；候选被拒后，仅在有原生提交、拒因签名未重复、不是执行失败且还有后续既有 completeness pass 和预算时，最多一次定向 correction。两者不增加 pass 或全局预算。新 evidence ID 本身不算进展；相同语义 dependency 的证据刷新也不能制造新的 API 选择。

**拒绝或无进展时，候选 facts、resolutions、requirements 和撤销决定不进入活跃状态；修订前基线继续保留。真实 model/tool calls、tokens、issued evidence、discoveries 和失败历史不回退。** 回滚不能把已经发生的请求当作没发生。

### 8.3 持久化怎样支持这条链

不可变 attempt 保存原生 result、trace、evidence 和 metadata。候选事务另存 pending/committed/rejected marker、原生归档、immutable projections 和 source-support 引用。派生投影与原生提交分别标明。

候选发布前检查全部成员、证据引用和 source witness 的归档载体，最后发布 commit marker。恢复时验证组完整性、摘要和成员；部分写盘不能被加载成有效完整 Context。这里是有 commit marker 的逻辑发布协议，不是对任意文件系统故障都能瞬时还原全部文件的保证。

候选验证 committed 与最终发布 committed 分开：归档 witness 或成员证据载体不足仍会拒绝发布。组完整性通过原事务全部 immutable projections 认证；后续已验证事务可合法替代其中某成员的当前 latest。顶层 Context 中所有 active resolutions（包括保留事实的 unresolved）都必须与对应当前 latest 完全一致。

source-only 重算也会独立发布，模型/工具增量可以为零。统计时不能把这种事务当作 Agent 成功修正错误。

### 8.4 为什么仍会停止

每次 requirement/group 调查的普通 Agent 循环默认最多 4 轮，同次调查至多 1 次额外 terminal-only 修复。首次调查、修订、恢复和修复累计仍受整个 FT 最多 24 次模型调用、64 次工具调用、96,000 source chars、16 个发现函数、依赖深度 2 及 3 个 completeness passes 约束。

可选探索默认最多使用全局额度中的 20 次模型和 56 次工具调用，保留其余 4/8 次给必需调查或修订；小预算按比例限制 reserve，单 pass 禁用后续保留。已知可修订 frontier 优先于继续可选探索。保留额度不会增加总预算，也不保证必需调查不会自行耗尽它。未发出的预算守卫模型操作不计 provider 请求，工具请求与执行由 tool_executed 区分。

自动准备不会独立预留 source chars。Context 的原生调查费用按实际计数登记；前置 bootstrap（含失败读取）写入 framework_prelude，并由组首 cost owner 计一次。循环工具尝试数单独保存；整个 FT 的 metrics 是累计费用。

这些是调用和调查上限，不承诺每个目标都能进入三轮纠正，也不直接限制所有本地证明重算的 CPU 时间。首次递归调查耗尽工具预算后，即使模型调用余额仍在，也可能无法取得修订所需的源码证据。

框架没有任意多轮、跨所有阶段的自动回滚求解器。未知源码、不支持的证明、身份冲突、预算耗尽、损坏输入和执行失败仍会停止或保留缺口。当前反馈也可能未覆盖所有关联字段，或者投影出不够精确的候选；反馈机制本身还需要改进。

## 9. Frozen Context 怎样汇总成 HarnessPlan

load_frozen_inputs 核验索引所对应的 live source、Slice/Minimal FT 身份、发布摘要、最新 resolution 和重算后的完整 Gate。验证失败会保存 blocked.json，generation_allowed=false、model_calls=0。

HarnessPlanBuilder 不调用模型。它先复核义务闭合和输入摘要，然后完成如下投影：

| Context 信息 | Plan 中的执行含义 |
| --- | --- |
| CORE 和 required support | active API 集合及声明 |
| Canonical construction | 每个实参的 construction_recipes |
| Input/length contract | data、size、复制、NUL、capacity、unit 和 bounds |
| Resource Contract | 创建结果变量、消费者引用及 cleanup 的确切对象 |
| Invocation Contract | 初始化/输入准备前置条件和状态转换 |
| Hard ordering | 依赖允许的 create/init/core/cleanup 顺序 |
| Return semantics | 结果捕获、成功条件、nullable guards 和错误路径处理 |
| Callback/internal proof | 源码拥有的 forwarding、调用基数及源码循环 multiplicity 和 storage lifetime |

调用基数证书可能保留 max=null；这表示源码循环的上界未被证明，不能把它解释为已知固定或有限调用次数。

Builder 还检查 active API 定义与可调用性、重复符号、顺序 cycle、参数唯一 recipe、资源身份和 cleanup schedule。不能因为 Context 已 closed 就忽略 Plan 自身无法表示的 ABI 或执行方式。

Plan 的主要字段包括 api_declarations、type_declarations、headers、contracts、resources、construction_recipes、invocation_contract、input_policy、call_sequence 和 cleanup_sequence。input_digests 将它绑定到当前 FT、Context、Closure 和义务图。

这里的“汇总”是把多处契约下沉为同一条明确执行计划。例如 creator 的返回值先绑定 resource R，消费者使用 R，cleanup 使用同一个 R；另一次 creator 得到的同类型对象不能拿来替代 R。

## 10. Plan 怎样变成 C/C++ 代码

ContextStage4Generator 把完整 Plan 渲染为代码生成 prompt。该阶段不提供 repository tools 或源码 body，不让代码模型重新寻找 API 或改写 Context。

代码模型负责确定变量声明、合法 ABI、边界检查、scratch storage、调用和单一清理区等代码写法，输出带 LLVMFuzzerTestOneInput 的一个 translation unit。

典型 recipe 有 fuzz_bytes、fuzz_size、bounded NUL string、stack_zero_init、creator_call、resource_reference、out_parameter_storage、derived_scalar 和 callback_object。模型必须使用 recipe 指定的来源、表达式、bounds、producer、userdata 和生命周期。

源码拥有的 callback/internal 调用不会自动变成 harness 中额外直接调用。绑定已有项目 callback 时要使用指定符号；只有 Plan 许可且有证书的公共 callback object，才能使用相应 deterministic stub。

代码生成后立即调用 validate_code 和 recipe binding validator，检查入口、ABI、允许 API、调用位置/次数、顺序、实参表达式、输入绑定、资源来源和 cleanup。校验器支持有限代码语法和模式，不能把“通过”解释为任意等价实现都能被证明，或所有 runtime 语义都已覆盖。

--plan-only 可以只保存执行计划；--harness 可以将现有 C/C++ 代码与当前冻结 Plan 对照校验，并按配置编译运行。这两种路径都不需要代码模型请求，也不能借已有代码绕过 Context 和 Plan 的身份、闭合检查。

生成代码失败时，文件和诊断可以仍然保留。代码存在不等于通过质量门禁。

## 11. 编译、运行和代码修复

构建器读取 TargetBuildConfig，验证目标源文件、头文件和 project root，分别编译目标库、harness 和固定输入 driver，再链接。当前新链对目标、harness、driver 和链接都加入 AddressSanitizer/UndefinedBehaviorSanitizer 配置。

C++ harness 使用 clang++/C++17，C 目标按其 recipe 编译；C harness 使用 clang/C11。build.json 保存实际命令、状态和 recipe。

--runtime 在构建成功后执行六个固定输入：空串、单 NUL、单 0xff、{}、a\0b、0 到 255 的字节序列。记录各输入的退出码、stdout/stderr 和 timeout，并开启 ASan leak 检查；sanitizer 报告保留在诊断中。runtime.json 明确 fuzz_executed=false：这是固定文件输入 driver 调用，不是长时间覆盖引导 fuzz。

当前单个输入的 passed 依据是 returncode==0。六输入通过仅表明进程正常退出且未触发导致失败的 sanitizer；不证明每个输入都调用了目标、覆盖了解析成功和失败路径，或输出语义正确。

--max-code-repairs 默认 0，可显式设为 1。在 model_translation 路径中，开启后只对 invalid_code 或 compile_failed 追加一次代码请求，传入旧代码、代码校验/编译诊断和同一 FrozenPlan。--harness 路径不调用模型修复。代码修复不重新挖 Context，不改 Plan，不增加 API。

当前 runtime_failed、provider failure 不触发这一代码重试。运行失败可能来自目标或 harness，需要归因；新链尚未自动实现 runtime → Context/Slice 的通用反向修复。

所有代码尝试、响应、校验和 build 被归档，避免修复失败时误用先前的构建成功文件。

## 12. 最终产物在哪里

下面是常见的新链目录结构。部分投影或 build 文件只有实际到达该阶段才存在：

~~~text
artifacts/
  functions.json
  annotations.json / flows.json / sfg.json
  ownership.json / usage_patterns.json           # 完整 SFG 模式可产生
  candidate_discovery/
    candidates.json
    validated_candidates.json
    agent_runs/<candidate_id>/
      result.json / evidence.json / trace.json / metadata.json
  semantic_slices/<candidate_id>/
    slice.json / evidence.json / trace.json / metadata.json
  minimal_fts/<ft_id>/
    minimal_ft.json / metadata.json
  harness_contexts/<ft_id>/
    requirements.json / resolutions.json / facts.json
    harness_context.json / api_closure.json
    argument_graph.json / canonical_construction.json
    resource_contract.json / invocation_contract.json
    parameter_semantic_contract.json / external_input_flow.json
    semantic_obligation_graph.json / completeness.json
    closure_feedback.json / subject_repair_history.json
    context_revision_history.json / context_revision_transactions.json
    evidence.json / metadata.json
    agent_runs/<requirement_id>/
      result.json / trace.json / evidence.json / metadata.json
      attempt_0001/...
    revision_transactions/<transaction_id>/
      metadata.json / source-support.json
      projections/<requirement_id>/...
  context_generations/<ft_id>/
    blocked.json                               # 生成前门禁失败
    <plan_id>/
      harness_plan.json
      <configuration_digest_prefix>/
        harness_plan.json / prompt.json / response.json
        harness.cpp 或 harness.c
        code_validation.json / metadata.json
        code_attempts/attempt_0001/...
        build/build.json / build/runtime.json
        build/smoke_harness / build/input_*.bin
~~~

最终新链 harness 位于 context_generations/<ft_id>/<plan_id>/<configuration_digest_prefix>/harness.cpp 或 harness.c。代码生成配置不同会形成不同目录；旧尝试可进入 history，不能只搜索到一个 harness 文件就认定它是当前通过的结果。

判断结果要读取对应 metadata.status、code_validation、build 和 runtime，并核对 Plan/input digests。plan_only 也可以得到 passed metadata，但没有代码；未请求 --build 或 --runtime 时，也不能把 passed 自动解释为编译和运行已通过。

## 13. 成本和 provider events 怎样汇总

Candidate、Slice、Context 的 trace 保存模型响应、工具操作、终态提交、修复和失败事件。模型返回的 usage 记录 prompt/completion/total tokens；Context 的 aggregate metrics 还包含全局工具、源码字符、发现和 budget_stop。

代码阶段使用 response.json、model_attempts 和 code_attempts 的记录。已经发出的失败请求仍计 model operation；provider 未返回 usage 时，用量标为未知，不能填零后声称完整成本。

汇总时需要遵守数据的原始/派生边界：

1. 同一 grouped 请求按 cost owner 计一次。
2. latest 是当前发布别名；存在 immutable attempt history 时，不能再次计费。
3. revision_transactions/projections 是派生文档，复制的 trace 不产生新请求。
4. 被 rejected 的真实 native attempt 仍计费。
5. budget fallback 的零调用存档不等于 provider 请求。
6. source-only 重算与 semantic revision、schema repair 分开统计。
7. response/request IDs、payload 和 usage 用于交叉核对，必要时区分跨 trial 来源。

因此“有多少 attempt 目录”“有多少事务”“有多少模型调用”“有多少成功响应”“用了多少 tokens”是不同指标。Source chars 也不是 token 数。

目前旧 collect_fresh_stability 对新增事务 projection 的筛选存在重复统计风险；cJSON 本轮已准备独立 artifact collector 处理该边界，旧汇总脚本尚未整体改造。本文描述正确计费边界，不声明所有历史 collector 都已实现相同规则。

## 14. 用 cJSON 追踪一条实际数据流

入口签名是：

~~~c
cJSON *cJSON_ParseWithLengthOpts(
    const char *value,
    size_t buffer_length,
    const char **return_parse_end,
    cJSON_bool require_null_terminated);
~~~

Parser 保存这个真实签名、正文和源身份。Candidate 将其列为高优先级入口，Validation 调查外部字节输入，Slice 决定核心和关联函数，Minimal FT 固定调查目标。

Context 为输入、长度、两个其他实参、返回值和树资源建立要求。已保存的两条解析 Context 中，四个 canonical 参数都已 resolved：

~~~text
value                   ← fuzz_bytes
buffer_length           ← fuzz_size
return_parse_end         ← constant(0)
require_null_terminated  ← constant(0)
~~~

这说明参数层的数据流已明确，尚不能保证整条调用安全。返回 cJSON 树的 ownership/lifecycle 中仍有 release_api/cleanup.api=null；两个 wrapper caller 的不同 runtime return origins 也存在歧义。最终 Gate 保存 mandatory_cleanup_unresolved 和 resource_identity_multiple_origins，阻止冻结和生成。

return_parse_end 在源码上是借用输入的 alias，不是新分配对象，不能按 owned out-parameter 释放。不同 wrapper 的返回树也不能仅凭相同类型、producer API 合并。

如果之后取得清理和调用范围的有效证明，Plan 才能表达“调用解析、捕获同一个返回资源、检查 nullable、按已证明的清理 API 释放”。代码模型再把该计划翻译为变量和调用。本文没有补写一个人工 harness 来绕过尚未闭合的 Gate。

本例还说明两种不同缺口：Delete 函数存在于完整索引，但模型的 callee 查询可能截断、没有取得必要正文证据；CJSON_CDECL hook ABI 则属于框架结构化能力不足。增加源码阅读或改进证明规则分别处理这些原因，不能统一写成“模型信息不全”。

Hook ABI 是独立确认的能力缺口，并非上述两条 Parse 的最终 hard_missing 直接列出的阻塞项。

## 15. 各层停止时会留下什么

| 位置 | 当前处理 | 后续是否生成代码 |
| --- | --- | --- |
| 源码/配置无效 | 保存错误或退出该阶段，不能认证 snapshot | 不允许 |
| Candidate unresolved/rejected | 保留 verdict、问题和证据；Slice 仅处理 accepted | 不允许该候选直接推进 |
| Slice invalid | 保存 terminal/选择校验错误和真实修复记录 | 不允许把 invalid Slice 投影为有效 FT |
| Context 缺证明 | 输出 incomplete、hard gaps 和 frontier；剩余预算内可修订 | 未闭合时不允许 |
| 候选未满足指定局部证明/引入错误或丢失已有证明 | rejected，保留修订前活跃基线和真实成本 | 仍需整个 Context 闭合 |
| Context/Plan 输入身份不一致 | 生成门禁 blocked，代码模型调用为 0 | 不允许 |
| 代码不符合 Plan/编译失败 | 保存代码和诊断；显式额度内最多一次代码修复 | 文件可能存在，但结果未通过 |
| Runtime failure | 保存运行失败，不自动开启新的代码或 Context 修复 | 代码保留，质量状态为失败 |
| 全局调查预算耗尽 | 未完成槽位保留 unresolved/fallback，记录 budget_stop | 不能借预算耗尽放宽 Gate |

该实现已具备局部错误反馈、候选状态验证和有界回滚，但闭合仍取决于证据取得、规则覆盖、准确反馈、调度和剩余预算。当前未实现任意项目、任意错误都能自动退回合适上游并持续修复到成功。

## 16. 对照源码阅读

| 机制 | 主要实现 |
| --- | --- |
| 项目解析与完整 SFG | [parser.py](../sfg_builder/parser.py)、[pipeline.py](../sfg_builder/pipeline.py)、[SFG CLI](../sfg_builder/cli.py) |
| 候选保留/排序与批量语义验证 | [entry_candidates.py](../harness_generation/entry_candidates.py)、[candidate_cli.py](../harness_generation/candidate_cli.py)、[validation CLI](../harness_generation/semantic_discovery/cli.py) |
| 源码查询与证据身份 | [repository tools](../harness_generation/semantic_discovery/tools.py)、[source_snapshot.py](../harness_generation/source_snapshot.py) |
| Slice 与 Minimal FT | [Slice CLI](../harness_generation/semantic_slicing/cli.py)、[FT builder](../harness_generation/minimal_ft/builder.py)、[FT CLI](../harness_generation/minimal_ft/cli.py) |
| Context 任务、Agent 与全局循环 | [requirements.py](../harness_generation/harness_context/requirements.py)、[agent.py](../harness_generation/harness_context/agent.py)、[loop.py](../harness_generation/harness_context/loop.py)、[models.py](../harness_generation/harness_context/models.py) |
| 参数图与规范契约 | [argument_graph.py](../harness_generation/harness_context/argument_graph.py)、[reconciliation.py](../harness_generation/harness_context/reconciliation.py)、[construction.py](../harness_generation/harness_context/construction.py) |
| 义务图与闭合 Gate | [obligations.py](../harness_generation/harness_context/obligations.py)、[completeness.py](../harness_generation/harness_context/completeness.py) |
| 反馈、修订和源证据发布 | [closure_feedback.py](../harness_generation/harness_context/closure_feedback.py)、[repair_transactions.py](../harness_generation/harness_context/repair_transactions.py)、[transaction_support.py](../harness_generation/harness_context/transaction_support.py)、[Context persistence](../harness_generation/harness_context/persistence.py) |
| 冻结读取和执行计划 | [generation persistence](../harness_generation/context_generation/persistence.py)、[builder.py](../harness_generation/context_generation/builder.py)、[recipes.py](../harness_generation/context_generation/recipes.py) |
| 代码翻译、校验、构建和修复 | [stage4.py](../harness_generation/context_generation/stage4.py)、[validation.py](../harness_generation/context_generation/validation.py)、[code_repair.py](../harness_generation/context_generation/code_repair.py)、[build.py](../harness_generation/context_generation/build.py)、[generation CLI](../harness_generation/context_generation/cli.py) |
| 项目构建与汇总 | [target_build.py](../harness_generation/target_build.py)、[collect_fresh_stability.py](../scripts/collect_fresh_stability.py) |

当前候选事务的具体实现边界见 [Context 修订与回滚报告](CONTEXT_REPAIR_TRANSACTION_REPORT.md)。cJSON 的注册、历史产物与暂停状态见 [能力检验记录](CJSON_RECON_FRAMEWORK_CAPABILITY_REPORT.md) 和 [testing_paused.json](../artifacts/cjson_capability_20261006/testing_paused.json)。
