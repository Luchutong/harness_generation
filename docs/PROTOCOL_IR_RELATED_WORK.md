# ProtocolIR 相关工作与方法抽取(2026)

本文回答一个问题:**要把 ProtocolIR 继续做下去,今年的相关工作里有哪些方法论可以借。**

它和 `docs/PROTOCOL_FORMAT_MINING.md` 是互补的:那篇问"怎么把 `protocol.json` 从
手写变成自动抽取",本篇问"抽出来之后,IR 缺的那一块,别人已经怎么做过了"。

## 0. 本文的读法

### 0.1 为什么每条都要标核实等级

本文的素材来自多 agent 文献检索。检索过程中反复出现同一种失效:**论文本体和头条数字
几乎每次都是真的,错的是"机制细节"那一层**——而机制细节恰好是要照抄的东西。

已实测到的三个例子:

| 条目 | agent 声称 | 回原文核实 |
|---|---|---|
| HGFuzzer(arXiv 2505.03425) | "path invariants vs trigger variables"、"10%/90% 变异比"、"length/magic/header 列为 invariant" 等 4 条机制 | **4 条里 3 条不在文中**。论文本身真实(确实生成 AFL++ 兼容的 C/C++ 自定义 mutator),但上述机制是编的。**已剔除,勿再引入** |
| LLM4Fuzz(arXiv 2508.01750) | ① LLM 选 "5–7 个关键状态";② "覆盖率反馈重加权转移" | 核心属实(LLM 生成**代码**产出状态序列、3 协议 12 漏洞)。但 ① **论文无此数字**,原文只说 "a small but essential subset",prompt 里是 `{number}` 占位符;② **机制错**——反馈回路存在,但用的是执行结果,原话 *"We do not report traditional code coverage metrics"*;"DTMC" 亦属过度具体化 |
| `ProtocolIR` 命名检索 | 搜索摘要给出一条 "AgentThread Protocol IR / Responsibility IR" 引用 | agent 自己 fetch 原文证伪并丢弃(arXiv 2606.28690 实为 *Formal Security Analysis of Agent Protocol Composition*,全文用 TLA+,不含 "Protocol IR")。这条 agent 的处理是诚实的 |

因此本文用三级标记,**任何要写进 method 的机制都必须先降到 A 级**:

- **A 级——本会话回原文逐条核过**。可直接引用。
- **B 级——agent 报告属实并自标了证据等级,本文作者未独立复核**。可作线索,引用前自核。
- **C 级——只见于检索摘要,全文未取得**。列出仅为完整,不作为依据。

### 0.2 一条前置结论

`ProtocolIR` 作为系统名**未被占用**:GitHub 仓库名检索 `total_count: 0`;
`protocol-ir` 关键词的 454 个结果是红外(Infrared)遥控协议,无关。唯一真实碰撞是
3GPP/ETSI ASN.1 的 `ProtocolIR-Container` / `protocolIRs`(RANAP/NBAP/F1AP 的
Information Element 容器类型名,非中间表示语言)。沿用该名可以,建议首次出现时加一句
"与 3GPP ASN.1 的 `ProtocolIR-Container` 无关"以免检索混淆。[B 级]

---

## 1. 结论先行

### 1.1 我们的缺口(已测,非推断)

见 `docs/COVERAGE_EQUIVALENCE.md`,数字全部由 `coverage-arms` 从
`measurements.json` 生成:

| | branch(target source) | |
|---|---|---|
| `reference`(手写) | 56/68 = 82.4% | |
| `contracted`(ProtocolIR 驱动) | 53/68 = **77.9%** | ratio 0.946429,gate 判 `below_reference` |

差的 4 个 direction **全部**落在 `MP_STORE` / `MP_RELEASE` / `MP_USE` 三个有状态 case
(`target.c:97`、`105`、`112` 的两个 direction);另在 `target.c:126` 的 `default:` 上
我们**赢**(10599/7940 vs 0/63531),净 −3。三个 seed 上完全一致。

根因一条,可从源码证明:`tests/fixtures/coverage_arms/contracted_published.c` 里
`payload_len = remaining`(再截到 `MP_MAX_PAYLOAD`),于是第一帧吃掉全部剩余输入,
**任何 ≤72 字节的输入循环只跑一次**;而语料种子是 2–9 字节。一个 `mp_context` 因此每条
输入只见到一个 opcode——跨帧的 STORE→USE / STORE→RELEASE **在结构上不可能发生**。
reference 做的是 `Data[pos++] % (MP_MAX_PAYLOAD + 1u)`:从 fuzz 输入抽长度,余量留给
后续帧。

### 1.2 文献共识优先级 vs 我们的实测:两条被证伪

这是本文最重要的过滤结果。**两份独立检索报告的头号建议,恰好落在我们已排除的两类上**:

| 文献主张 | 我们的实测 | 判定 |
|---|---|---|
| "nested length 自底向上重算——这是缺口里最可能的大头" | `target.c:114/115/120/121` 两臂**都覆盖**,含 BUG 5 路径 | **证伪**,不是缺口 |
| 强调 opcode 分布 / dispatch 边界值 | `target.c:126` `default:` 我们赢 | **证伪**,不是缺口 |
| "给 IR 加 variant / path_condition 维度"(两份报告的最高杠杆 #1) | 本 target `MP_HEADER_SIZE` 是常量 8,无可选字段 | **本 target 不适用**(方向对真实协议成立,对我们无收益) |
| payload length 的**边界值**表 | 边界值不是问题,**长度从哪来**才是 | **修正**:不是补边界表,是补"长度的来源" |

原因清楚:协议 fuzzing 文献默认目标是**网络服务**(有响应码、有会话、有嵌套 TLV),
我们的 target 是**单进程 parser + 扁平 8 字节头**。共识优先级迁移不过来是正常的,
**不要因为文献都这么说就去改**。

### 1.3 真正对得上的四条

| 缺口/需求 | 前作 | 落到 ProtocolIR 哪一层 |
|---|---|---|
| 跨帧有序状态序列(唯一实测缺口) | AFLNet 的 prefix replay;NSFuzz 的静态 state variable 定位;LLM4Fuzz 的"LLM 写序列采样**代码**" | `stateful_operations` 从 opcode 集合 → 状态变量 + 转移关系;harness 从 per-frame → 单 buffer 内多帧序列 |
| 长度是抽样还是饱和(根因) | Peach Pit 的 `Relation type="size" of="X"` | `FrameField.width` 现在只能写一个**字段名**,是 Peach 的无类型退化版;换成带类型 relation 后,`payload_len` 必须**由 payload 算出**而非吃掉余量 |
| 状态机与报文格式的抽象层次 | FANDANGO:states/messages/transitions **统一为 nonterminal** | 原则性目标,不是下一步 |
| harness 生成物形态 | Bulbasaur 的 hard-frontier 选分支;LLM4Fuzz 让 LLM 写采样器而非写序列 | Stage 4 prompt:把"生成序列"变成"生成一个受约束的**序列采样函数**" |

### 1.4 缺口在 IR schema 里的精确落点

读 `harness_generation/protocol_ir.py` 与 `protocol_plan_validation.py` 确认:

- `StatefulOperation = {opcode, reason, evidence}`——**一个集合,没有顺序、没有转移、
  没有生产者-消费者关系**。plan 闸门 `_stateful_violations` 比对的是**排序后的 opcode
  名集合**。所以"RELEASE 只在 STORE 之后可达"既表达不了,也检查不了。
- `FrameModel.max_payload` 是**上界,不是分布**。`bounded_multi_frame` +
  `bounded_steps` 的闸门只要求 `bounded_steps` 是**正整数**。于是"声明多帧 + 上限 32"
  能过闸,而生成的 harness 只跑一帧——**声明与机制之间没有任何检查**。

合起来:**harness 是唯一没有契约的产物**。IR 对格式事实管得很严(provenance /
confidence / evidence 齐全),对**策略**只验了一串名字。这份 harness 语法合法、能链接、
能跑满预算、过掉每一条检查;它是契约的一个退化实现,而契约没有条款能说它退化。

**这也解释了这个 bug 为什么发现得这么晚**:在 branch coverage 与手写 reference 对比
之前,流水线里没有任何更早的信号能说"这个 harness 结构上到不了有状态路径"。

---

## 2. 对得上的工作,逐条

### 2.1 状态序列(直接命中唯一缺口)

**NSFuzz**(TOSEM 2023,DOI 10.1145/3580598)[C 级]
静态分析 + 注解 API 在 SUT 源码里定位两类东西:**I/O synchronization point**(网络事件
循环入口)与 **state variable**;运行时对 `shared_state` buffer 求哈希打成 state id,
任一状态变量变化即判定状态转移,从而**避免 StateAFL 的 post-execution 分析开销**。
*对我们*:**"静态分析找到状态变量集合 + 运行时哈希成 state id"这套组合,与我们最契合
——我们的 miner 本来就在做 C 源码静态分析。** 这是把 `stateful_operations` 从"操作清单"
升级为"状态变量 + 转移关系"的最低成本路径。

**AFLNet**(ICST 2020;五年回顾 IEEE TSE 51(4), 2025, DOI 10.1109/TSE.2025.3535925)[C 级]
第一个**代码覆盖 + 状态覆盖双反馈**的协议 fuzzer:用响应码作协议状态代理,在线学习状态
机(IPSM),Target State Selector 选目标状态 → Sequence Selector **重放前缀**到达该状态
→ 只变异该状态下消费的消息。
*对我们*:STORE/USE/RELEASE 本质就是"必须先到达某状态才能执行后续操作"。**前缀重放**
映射到单进程 harness 就是:在同一个 buffer 里构造**帧序列**——这正是 reference 做的事,
也正是我们做不到的事。

**LLM4Fuzz / LLM-Assisted Model-Based Fuzzing of Protocol Implementations**
(arXiv 2508.01750)[A 级——核心已核,两处细节已纠正]
**核实结论**:LLM 产出的是**代码**而不是声明式模型——abstract 原话 *"we prompt the LLM
to generate code that produces sequences of states"*,"This program serves as a
protocol-specific sequences generator";3 个协议实现(MQTT / Modbus / DAAP)、12 个新漏洞。
**已纠正的两处**:① "5–7 个状态"论文里没有(原文 "a small but essential subset",
prompt 用 `{number}` 占位符,示例列了 7 个 MQTT 状态);② 反馈回路存在但**不是覆盖率
反馈**——原话 *"We do not report traditional code coverage metrics"*。
*对我们*:产出物形态与我们同构(都是代码)。可借的是"**让 LLM 写采样器,而不是写序列
本身**"。**但那两条被纠正的细节不要引用。**

**FANDANGO / Language-Based Protocol Testing**(arXiv 2509.20308,
Liggesmeyer / Zamudio Amaya / Zeller)[A 级——4/4 逐句在 abstract]
**interaction grammar** = 上下文无关文法的扩展,**每个 message element 被指派给负责
产生它的通信方**;**把经典状态模型折叠进文法——"embed classical state models by
unifying states, messages, and transitions all into nonterminals"**;文法元素上叠加
constraints 表达语义特征(*"binary message formats, checksums, encodings"*);同一文法
既生成也解析。覆盖 SMTP / DNS / FTP。
*对我们*:**这是本文里最优雅的 IR 设计**,也是我们 stateless-per-frame 问题的正确抽象
层次——"生成一条报文"天然就是"走状态机的某条边"。但它是**重构级**改动,列为原则性
目标,不是下一步。

### 2.2 长度关系与 IR schema

**Peach Pit 的 `DataModel` / `StateModel`**[A 级——已核 `Relation` 与 `Fixup`]
`<Relation>` 有 `type`(Size / Count / Offset)+ `of`,让 Peach 在变异时自动维护长度、
元素计数、偏移;可选 `expressionGet` / `expressionSet`(须互为逆);checksum 走独立的
`<Fixup>`(`Crc32Fixup` / `MD5` / `SHA1` 等)。`<StateModel>` 用 States + Actions 定义
状态机,与 DataModel **分离**。
*对我们*(schema 层面的头号参照):**Peach 早已解决了我们 IR 缺的两件事——(a) 字段间
`size`/`count`/`offset` 关系,(b) 状态机与数据模型的分离。** 我们现在的
`FrameField.width` 能写一个**字段名**——那是 `Relation type="size"` 的无类型退化版。
补上带类型的 relation 是**向后兼容**的扩展,而且它直接命中根因:一旦 `payload_len`
必须**由 payload 导出**,就不可能再出现"吃掉全部余量"。这也是 Peach 被至少四个独立
工作当作逆向的最终 IR 来产出的原因(PRE2Fuzz ICSE 2026 等)[C 级]。

### 2.3 harness 生成物形态

**Bulbasaur: Branch-Guided Online Mutator Generation for Greybox Fuzzing**
(Yiyi Wang, Dongsong Yu, Ruiqi Dong, Yiyang Chen, Xiaogang Zhu, Chao Zhang;
USENIX Security 2026, Baltimore, pp. 4089–)[A 级——本会话直接解 PDF 读到正文]
维护 branch database;先找 **frontier branch**(出边未全覆盖),再从中挑**持续未覆盖
超过阈值(经验值 6 小时)的 hard branch**,只对这些花 LLM 预算;生成物是
**operand-aware mutator template**;LLM 先判断该分支**是否 input-dependent**,不是就返回
`UNABLE_TO_BREAK_THROUGH` 直接跳过。数字:line +23.18%、branch +24.46%,15 个 CVE。
*对我们*:可迁移的是**(a) 先问 LLM"这个分支是否 input-dependent",不是就别修**——
对应 harness 里那些不可达/环境相关分支;**(b) 重生成时把上一版 artifact 一起给它**。
"未覆盖超 N 时间才算 hard"那个触发条件对我们离线评 harness 不适用。

**SeedMind**(arXiv 2411.18143)[B 级]
LLM 产 Python **generator 脚本**;循环是 执行 → 收 branch coverage → 把函数分
fully/partially/未覆盖三类 → **只把 partially covered 放进 prompt** → 关键一步:一个
**"摘要 prompt"把 coverage report 转成 2–3 句自然语言诊断 + 2–3 句改进建议,并明确要求
不要输出新脚本**(刻意制造一次 chain-of-thought)→ 重新生成。
*对我们*:**这是最该照抄的反馈表示法**——不要把未覆盖行列表直接丢给 LLM。

### 2.4 反馈回路:一条看起来反对我们的负结果

**Gentoo / Fuzzing with Agents? Generators Are All You Need**(arXiv 2604.01442)[B 级]
agent 合成 target-specific input generator;ablation 结论:**coverage guidance + mutation
对 agent 生成的 generator 没有统计显著收益,但对所有人工写的 generator 都显著**——
作者解释为 agent 已经把结构/语义逻辑编码进 generator,coverage guidance 变多余。

*对我们*:**它不适用,理由正是我们自己的实测**。它的前提是"generator 已经把结构编码
进去了";我们**证明了我们没有**——`payload_len = remaining` 让循环只跑一次,结构根本
没进去。前提不成立,结论不能外推。所以"加一轮 coverage-driven repair"对我们是有理由
的——**但必须按 §3.2 的规格做**,否则做出来的数字解释不了。

---

## 3. 评测口径

### 3.1 我们已经做对的

**分母不掺 harness。** OSS-Fuzz-Gen 的评测实现
(`experiment/evaluator.py`)[A 级——已回原文核]用
`compute_total_lines_without_fuzz_targets(coverage_summary, generated_target_name)`,
内部 `if fuzz_target_base_name not in f['filename']`,**把 fuzz target 自身排除在分母外**;
另用 `run_result.coverage.subtract_covered_lines(existing_textcov)` 扣掉既有覆盖。
我们的 gate 指标 scope 是 `target_code`(只算 `target.c`),**harness 已在分子分母之外**。
→ **77.9% / 82.4% 没有被 harness 行数稀释,缺口是真的。** 这条排除一个怀疑,不是新增
一个问题。(`subtract_covered_lines` 那个"增量"口径等要跟别的工具横向比时再用。)

### 3.2 待补的两条

标准出处:**SoK: Prudent Evaluation Practices for Fuzzing**(IEEE S&P 2024,
DOI 10.1109/SP54263.2024.00137, arXiv 2405.10220)[A 级——已回原文核]。
审 2018–2023 年 150 篇顶会论文、尝试复现 8 篇。硬性建议:

- **≥10 次重复**(或用 a-priori power analysis 定样本量);
- 统计检验用 **permutation / bootstrap,而非 Mann-Whitney U**;多者比较用 bootstrap 版
  ANOVA + Posthoc(Tukey-Kramer 或 Dunnett);
- 报 **effect size(Vargha–Delaney A12)** 与不确定区间;
- **初始语料自身的覆盖率要单独报**——否则会把语料的功劳算到 harness 头上;
- **每个被比较的 fuzzer 必须用同一套 coverage 度量**。

它同时给了流行病学:55% 的论文某实验重复 <10 次,**63% 完全不做统计检验**。

*我们的现状*:1 个 target 上的**确定性单点**。注意这和"抖动大"不是一回事——
`-runs=20000` 下覆盖率饱和,三个种子给出完全相同的数字(见
`docs/COVERAGE_EQUIVALENCE.md` 的 Seed spread 一节),**所以重复得不出新信息**。
但那不等于有统计证据:它意味着任何**跨 target、跨预算的推广目前没有任何支撑**。

反面教材:**FuzzPilot**(arXiv 2605.26539)[B 级]——N=5 / ablation N=3,作者自陈
"没有任何 pairwise 显著结论";且它有一条 **fairness 臂显示换插桩就能追平**
(AFL++ + cmplog 270 edges vs FuzzPilot 269)。这正是"口径不对,数字白做"。

### 3.3 一处贡献机会:build-configuration comparability

**已核实的文献空白**:SoK **完全没有讨论**编译器 flag、优化级(`-O0/-O1/-O2/-O3`)、
被比较 fuzzer 之间的**构建配置对等性**,也未讨论 **differing translation units** 与
**inlining 对覆盖率的影响**。但它**覆盖了**同类问题的一个特例——sanitizer 插桩偏差
(FishFuzz 案例:插桩落在 ASan 新增代码上,报告优势从 8.44% 掉到 1.69%)。

我们这一路踩的恰好就是那片空白,而且**有实证**(全部记录在
`docs/COVERAGE_EQUIVALENCE.md` 的 "Evaluation infrastructure fixes" 与 Arms 两节):

- `structured.c` / `pass_through.c` 是 `single_tu`(把 `target.c` include 进来、按 C++17
  编译),而发布的 pipeline harness 是 `two_tu`(C11 `target.o` 旁边放 `extern "C"` 原型);
- C++ 编译会 mangle 名字(`_Z8mp_parseP10mp_contextPKhm`、`target.c:le16`),所以跨臂的
  函数级比较**只能读 `totals.functions`,不能读函数名**;
- `shutil.copyfile` 丢执行位;
- `llvm-cov` / `llvm-profdata` 不在 PATH 上(需 `llvm-cov-18` / `llvm-profdata-18`)。

**沿用 SoK 的 checklist 结构补一节 build-configuration comparability,是一个站得住的
贡献点**——它不是猜的,是我们自己被逼着解决的四个问题,而审了 150 篇的 SoK 对它沉默。

---

## 4. 核实记录

| 条目 | 核实等级 | 核实结论 |
|---|---|---|
| HGFuzzer | A | **4 条机制 3 条不在文中,已剔除** |
| LLM4Fuzz(2508.01750) | A | 核心属实;**"5–7 状态"不存在;"覆盖率反馈"错**(实际是执行结果反馈);"DTMC" 过度具体化 |
| FANDANGO(2509.20308) | A | abstract 4/4 逐句命中 |
| Peach Pit `Relation` / `Fixup` | A | `type ∈ {Size, Count, Offset}` + `of`;checksum 走 `Fixup`。属实 |
| Bulbasaur(USENIX Sec 2026) | A | PDF 已解出正文;+23.18% line / +24.46% branch / 15 CVE。属实 |
| OSS-Fuzz-Gen 评测分母 | A | `compute_total_lines_without_fuzz_targets` + `subtract_covered_lines` 属实 |
| SoK 的 flag/TU 空白 | A | 确认无编译器 flag / 优化级 / TU / inlining;有 sanitizer 偏差(FishFuzz) |
| SemFuzz(2603.05989) | A(前序会话) | `R=(p,m,c)` / `SR=(p,m,f,C,P)` 形式化、`add/remove/update(fields,...)` 动作序列、w/oAction ablation 87%→36% 均属实 |
| SynapseFlow(2607.07007, CCS 2026) | A(前序会话) | 论文真实(Structural Flow Graphs / Function Triplets);本仓库的 triplets 抽象确为该线下游 |
| `ProtocolIR` 命名 | B | GitHub `total_count: 0`;唯一碰撞为 3GPP ASN.1 `ProtocolIR-Container` |
| Gentoo(2604.01442) | B | 仅摘要;2×2 ablation 结论如所述 |
| SeedMind(2411.18143) / Bulbasaur 细节外的 B 级条目 | B | agent 报告并自标等级,未独立复核 |
| NSFuzz / AFLNet / StateAFL / SGFuzz / ChatAFL / NetLifter / StateLifter / ParDiff / ProtocolGPT / USENIX Sec 26 对抗式格式推断等 | C | 见 §5;引用前须自取全文 |

## 5. 未核实清单(C 级,列全以免当作已核)

**协议格式/状态推断**:Netzob(工具,非论文)、FieldHunter(2015)、NetPlier(NDSS
2021)、Veritas(**ACNS 2011,不是 USENIX**——检索摘要曾误标)、EMSE 2026 分层格式推断
(DOI 10.1007/s10664-026-10814-6)、FieldWeaver(Computer Networks 2026-08)、
NetLifter/Popeye(**CCS 2023**,arXiv 2305.11781)、StateLifter(USENIX Sec '23,
arXiv 2305.13483)、ParDiff(OOPSLA 2024,DOI 10.1145/3649854)、ProtocolGPT
(arXiv 2405.00393)、USENIX Security 2026 对抗式 LLM 格式规格生成(Nanjing, pp.
4069–4088)、ChatAFL(NDSS 2024)、StateAFL(EMSE, arXiv 2110.06253)、APFuzz
(arXiv 2602.21892)。

**LLM 反馈回路**:SBFT 2026 Java harness 生成(arXiv 2603.08616)、ProteusFuzz
(IEEE 11677698)、PromeFuzz(**CCS 2025**, DOI 10.1145/3719027.3765222)、FuzzAgent
(arXiv 2605.14431)、IncrFuzz(IEEE 11360448)、FuzzPilot(arXiv 2605.26539)、
ReFuzzer(ASE 2025)、"How Many Tries"(arXiv 2604.10508)、Rapid Fixes(ICML 2026)、
SCAM 2026 seed generation、UniFuzz(USENIX Sec 2021)、BDCC 2026 10(4):129、
ISSTA 2024 LLM fuzz driver 实证(arXiv 2307.12469)。

**已知不可信/已撤回的线索**(勿再引入):
- "Pensieve: Code Coverage Based Instruction Set Fuzzing (USENIX Sec 2018)"——两次检索
  均无任何证据,同名系统是三个无关工作。**不存在**。
- "Nautilus 自动更新 length 字段"——无证据。Nautilus 可用的是**深度受限的均匀生成**。
- FormatFuzzer(TOSEM 2024)——检索结果中**完全没有** checksum 处理,且需手写 `.bt` 模板。
- PULSAR 是 **SecureComm 2015**,不是 NDSS 2020。

## 6. 不做

- **不动 evaluation 阈值**。§1.1 的 0.946429 是读数,不是成因;改阈值只会把这个问题抹掉。
- 不加 variant / path_condition 维度(§1.2:本 target 无收益)。
- 不补 payload 边界值表(§1.2:边界值不是问题)。
- 不做 FANDANGO 式文法统一(方向对,但属重构级)。
- 不引用 §0.1 里被纠正的那两处 LLM4Fuzz 细节,也不引入已剔除的 HGFuzzer。
