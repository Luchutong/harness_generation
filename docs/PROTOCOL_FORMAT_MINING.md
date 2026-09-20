# Protocol Format 自动化构建:方法抽取与落地映射

本文从六组工作中抽取**可复用的方法机制**,并逐一映射到本仓库
`benchmarks/mini_parser/protocol.json` 的各个字段与 `harness_generation/`
的现有模块上,给出从手工编写走向自动抽取的可行路径。

四份文档的分工:

| 文档 | 问的问题 |
|---|---|
| **本文** | 怎么把 `protocol.json` 从手写变成自动抽取(六组工作 → 块 A/B/C) |
| `docs/PROTOCOL_IR_RELATED_WORK.md` | 抽出来之后,IR 缺的那一块别人怎么做过了(文献综述) |
| `docs/PROTOCOL_IR_METHOD_TRANSFER.md` | 那些方法落到哪个 schema 字段 / 哪个函数 / 哪个闸门(M1–M11) |
| `docs/FRAMEWORK_PAIN_POINTS.md` | 现有实现的痛在哪、按什么顺序动、与上面三份怎么对应 |

**术语碰撞提醒**:本文的 **A/B/C 块**指契约的三个来源分块(帧格式 / 常量约束 /
惯用法);`PROTOCOL_IR_METHOD_TRANSFER.md` 的 **A/B/C** 指**核实等级**。两者无关。

## 0. 问题定位

### 0.1 现状

`protocol.json` 是声明式协议契约,由人工编写,经
`harness_generation/protocol_spec.py` 的 `discover_protocol_spec()` 在同目录
自动发现,由 `load_protocol_spec()` 只做外壳校验(`schema_version` /
`entry_function` / `contract` 类型),`contract` 内部**原样透传**,再由
`candidate.py:135` 挂到 `summary["protocol_contract"]` 写进
`source_summary.json`。

> 更正(2026-09-17):上面这条路径**不接** Stage 4 的 prompt。Stage 4 的
> `{protocol_contract}` 槽位由 `<artifacts>/protocol_ir.json` 填(§5.2);
> 手写 spec 只出现在 `candidate.py` 这条流水线、以及 miner 测试作为 ground
> truth 的地方。此前本文写作"经 `prompts.py` 注入 LLM prompt"是把设计意图
> 当成了实现。

### 0.2 待自动化的对象

`protocol.json` 内部并不是同质的,按可自动化程度分成三块:

| 块 | 内容 | 信息来源 |
|---|---|---|
| **A. 帧格式** | `frame.fields[]`(offset/width/endianness/value) | 可从 `target.c` 静态恢复 |
| **B. 常量约束** | `header_size`、`max_payload`、opcode 枚举范围 | 可从 `parser.h` 静态恢复 |
| **C. 惯用法** | `command_loop`、`context`、`requirements`、`notes` | **不在 `mp_parse` 里**,只能从参考 harness 或 LLM 归纳 |

C 块与 A/B 块的可自动化程度差距是本文的核心结论:**A/B 是工程问题,C 是归纳问题**。
下面的六组工作按此分工对号入座。

---

## 1. 六篇工作的方法抽取

### 1.1 ChatAFL — LLM 做 grammar / state 推理

> Meng, Mirchev, Böhme, Roychoudhury. *Large Language Model guided Protocol
> Fuzzing.* NDSS 2024. <https://github.com/ChatAFLndss/ChatAFL>

**方法机制**

1. **Grammar 抽取**:few-shot prompt 给出 RTSP/HTTP 示例,要求 LLM 以固定
   JSON 模板输出目标协议的全部消息模板,变量位置替换为 `<<VALUE>>` 占位符,
   例如 `PLAY: ["PLAY <<VALUE>>\r\n", "CSeq: <<VALUE>>\r\n", ...]`。
   `temperature=0.5`。
2. **一致性表(consistency table)** —— 真正值得抄的部分。同一抽取任务**重复
   生成 3–5 轮**,逐字段统计频次,**保留多数轮次都出现的字段**以滤除幻觉。
   这是把 LLM 抽取从"不可复现"变成"可复现"的关键工程手段。
3. 产出的 grammar 转成 PCRE2 正则,供结构化变异使用。
4. **Seed 增补**:让 LLM 把缺失的消息类型插入已有 seed 序列。
5. **覆盖平台期处理**:把近期通信历史喂给 LLM,要求生成能到达新状态的消息。

**结果**:RTSP 十种消息类型中 9 种与 RFC 2326 一致(仅偶尔漏掉可选的 `Range`);
相对 AFLNet / NSFuzz 状态转移多 47.6% / 42.7%,状态数多 29.6% / 25.8%,
代码覆盖多 5.8% / 6.7%;发现 9 个未知漏洞。

**对本框架的可迁移点**

- **一致性表直接适用于 C 块生成**。`command_loop`、`context.lifetime`、
  `requirements`、`notes` 这段散文没有确定答案,但重复采样 + 逐字段投票能压掉
  LLM 的自由发挥,产出稳定的候选。
- ChatAFL 的 `<<VALUE>>` 占位符语义,与本仓库 `fields[].value` 中
  `"fuzzer-controlled bytes"` 这类描述是同一回事 —— 即"此字段由 fuzzer 控制,
  格式由契约固定"。可直接对齐表示法。
- **需要注意的方法错配**:ChatAFL 的输入是**自然语言 RFC**,我们的输入是
  **源码**。所以 ChatAFL 贡献的是 LLM 的**可靠性工程**(投票、重试、占位符
  模板),不是抽取源。抽取源要走 §1.3 / §1.4。

---

### 1.2 REDQUEEN — magic / checksum 的测量原语

> Aschermann, Schumilo, Blazytko, Gawlik, Holz. *REDQUEEN: Fuzzing with
> Input-to-State Correspondence.* **NDSS 2019**(非 USENIX)。

**方法机制**

1. **input-to-state correspondence**:输入中的一部分常以近乎未修改的形式
   出现在程序状态里。REDQUEEN 不实现完整污点分析,而是**挂钩比较指令**
   (以及函数调用参数),近似地恢复这种对应关系。
2. **比较指令 → 变异模式**:当发现两个不同操作数被比较,提取为
   `<pattern → repl>` 模式,配合 ±1 变体与多种编码(零/符号扩展、**字节反转**、
   ASCII 等)应用到输入上。
3. **Colorization**:向输入注入随机字节以提高熵,从而**缩小候选替换位置的范围**
   —— 这是让比较指令定位变精确的关键技巧。
4. **Checksum 的 patch + verify 闭环**:用启发式识别"校验和式比较",**patch 掉**
   (例如把比较改成 `cmp al, al` 恒真),在此状态下 fuzz 找到能到达深层逻辑的
   输入,再**回到未 patch 的程序验证** input-to-state 变异能否在真实校验下
   通过。嵌套校验用依赖图 + 拓扑排序处理。

**结果**:LAVA-M 上首个超过 100% 的工具(2265 个标注 bug 只漏 2 个,另找出
335 个未标注 bug),65 个新 bug / 16 个 CVE,对 VUZZER、KLEE、AFLFast、
LAF-INTEL 最高快三个数量级。

**对本框架的可迁移点** —— 这组原语是把 §0.2 的 A 块从"猜"变成"测"的仪器:

- **Colorization 恢复 magic 与其 offset**。向 payload 注入随机字节,观察哪些
  字节被拿去和常量比较 —— 直接给出 `magic0='M'` @0、`magic1='P'` @1、
  `version=1` @2 及 `mp_parse` 中 `return -2` 的这三个常量。
- **字节反转探针恢复 endianness**。REDQUEEN 的编码变体里包含字节反转;
  若反转形式命中比较,则该字段为小端。这是一个**可执行的 endianness 判定器**,
  可直接用于确认 `payload_length`(@4)与 `checksum`(@6)的 `little_endian`。
- **checksum 的 patch + verify 恢复字段语义类型**。把
  `mp_checksum(data + MP_HEADER_SIZE, len) != le16(data + 6)` 这个比较
  patch 成恒真后,若 opcode 分支覆盖显著上升,即可**证明**该字段是校验和,
  且其覆盖范围是 payload 区(`data + MP_HEADER_SIZE`,长 `len`)。
  这是 `checksum` 字段 `value` 描述从自然语言变成可验证事实的途径。
- **操作数宽度给出字段 width**。比较/加载指令的操作数宽度直接对应字段宽度
  (见 §1.4 Tupni 的 chunk 分段)。

**局限**:REDQUEEN 本身是 fuzzer 而非规范挖掘器,不产出声明式 spec;
它提供的是**测量手段**,需要外面套一层把测量结果写成 JSON 的收口逻辑。

---

### 1.3 Controlled Static Loop Analysis — 从 parser 实现静态抽取 FSM

> Shi, Xu, Zhang(Purdue). *Extracting Protocol Format as State Machine via
> Controlled Static Loop Analysis.* **USENIX Security 2023**, pp. 7019–7036.
> arXiv:2305.13483。

**方法机制**

1. **动机**:主流协议格式逆向依赖动态分析,受**低覆盖率**所限 —— 推断出的格式
   只反映观察到的输入里出现过的特征。本文改为**从 parser 实现静态推断**。
2. **目标类别**:格式可由**约束增强的正则表达式**描述、并由 **FSM** 解析的协议。
   这类 FSM 在代码里通常实现为**复杂的解析循环**,常规静态分析难以处理。
3. **核心建模**:**把循环的每一次迭代视为一个状态,把迭代之间的依赖视为状态
   转移**。由此把"解析循环"提升为"状态机",再由状态机反推消息格式。
4. **Controlled(受控)**:目标是路径敏感的高精度,但逐路径展开会**路径爆炸**,
   因此按精心设计的规则**尽可能合并路径**。论文明确对比了循环展开、循环不变式、
   以及既有 FSM 推断工作(如 Chen 等、Shimizu 等、Proteus)在此处的
   状态/路径爆炸或假设不现实的问题。
5. **输出**:状态机 + 消息格式;推断耗时约 5 分钟,精度与召回均 >90%;
   把状态机回灌给协议 fuzzer 后覆盖率提升 **20%–230%**,额外发现 **10 个零日**。

**对本框架的可迁移点**

- **这是 §0.2 中 C 块"`command_loop`"的对口方法**。但要注意一个位置错配:
  `mp_parse` 内部**没有**解析循环 —— 它的 `switch (data[3])` 是单次分派。
  真正的循环在 harness 里:

  ```c
  for (unsigned step = 0; step < 32 && Size - pos >= 2; ++step)
  ```

  所以"循环迭代 = 状态"要应用在**参考 harness 的循环**上,而不是 `mp_parse`
  上。这正好解释了为什么 `command_loop.max_steps: 32` 与
  `selector` 语义在 `target.c` 里找不到 —— 它们是 harness 的状态机。
- **`MP_NESTED_LENGTH` 分支是真正常规意义下的解析循环**:
  `target.c:116` 的 `size_t inner_len = le16(p);` 处于一个嵌套解析循环中。
  这正是该文针对的"约束增强正则 + FSM 实现为解析循环"形态,是 `notes` 里
  "嵌套 payload 字段"描述的来源。
- **"受控合并"是可行性的关键**:如果直接对 `{M,P,1,op,...}` 这种带长度前缀的
  帧做路径敏感展开,长度域会立刻导致爆炸;必须先用 §1.4 的约束把它固定成一个
  符号区间才能收敛。

---

### 1.4 Polyglot / Tupni — 传统 RE 的字段模型与约束推断

> Caballero, Yin, Liang, Song. *Polyglot: Automatic Extraction of Protocol
> Message Format using Dynamic Binary Analysis.* **CCS 2007**, pp. 317–329.
>
> Cui, Peinado, Chen, Wang, Irún-Briz. *Tupni: Automatic Reverse Engineering of
> Input Formats.* **CCS 2008**, pp. 391–402.

这两篇给出的是**字段模型(元数据词汇表)**和**约束推断**,是六组工作里与
`protocol.json` 的 `frame.fields[]` 结构最直接对应的一组。

#### Polyglot:shadowing 与方向字段

1. **shadowing 范式**:核心洞察是"**协议实现处理收到的数据的方式,揭示了消息
   格式**"。因此在模拟器(QEMU)中运行二进制、对接收数据打**动态污点标记**,
   监视其被如何使用,再从事中提取格式 —— 不依赖网络流量聚类(那样缺少语义)。
   可在**去符号的二进制**上工作,一次处理一条消息。
2. **字段属性模型**:field start / field length(定长或变长)/ field boundary
   (**Fixed / Direction / Separator**)/ field type(Direction / Non-Direction)/
   field keywords。
3. **Direction field(方向字段)**:即存有"另一个字段位置信息"的字段,分三类 ——
   **length 字段**(编码目标字段长度)、**pointer 字段**(编码相对位移)、
   **counter 字段**(编码在列表中的位置)。检测方式:该字段被用于推进指针。
   - 直接法:存在间接访存,(1)访问被污点的内存位置,(2)目的地址由污点数据算出。
   - 间接法:指针推进发生在循环中 —— 识别 trace 中的循环(重复代码段 + 回跳),
     其中**停机条件被污点**者标记为污点。
4. **关键:对 direction field 的编码不做任何假设**(字节数、整数编码等),
   这正优于假设固定长度编码的既有工作。
5. **separator 的发现也不假设其值**(不像既有工作假设空白/制表符)。
6. **定长字段边界**:依据"程序把哪些输入字节作为一个语义单元使用"来分组,
   从而找到**相邻二进制字段之间**的边界。
7. **keyword 提取**:可从**单条消息**中提取协议常量,不需要同一位置的重复
   出现。

**结果**:11 个真实实现、5 种协议(DNS、HTTP、IRC、Samba、ICQ),与 Wireshark
手工编写的格式对比,差异很小。

#### Tupni:字段分段、记录序列与跨字段约束

1. **字段边界**:把输入切成 **chunk** —— CPU 指令操作数中**最长的连续被污点
   字节序列**(忽略 move 指令)。可识别 8/16/32/64 位整数操作数、浮点 chunk、
   以及**大端反转字节**,粒度到字节。
2. **记录序列**:通过分析程序中的**循环**识别任意记录序列(循环处理无界记录
   序列),BNF 形式为 `(R1|R2|…|Rn)*`。
3. **记录类型**:按"处理该记录的指令集合"对记录聚类成少数几类。
4. **约束(constraints)** —— 最重要的一项:由动态数据流分析跟踪符号谓词,推断
   字段值约束与跨字段/跨消息依赖。论文明确列举的形状包括:
   - **length 字段**(某字段指定数组字段的长度)
   - **checksum 字段**(其值依赖其他、可能是全部字段的值)
   - **常量值**(某些字段被强制要求的 magic number)
5. **匹配与合并**:来自不同 trace 的两个基字段若被同一组指令访问则匹配;
   记录序列若由同一循环(唯一入口点)处理则匹配;记录若指令集相同则同类型。
   跨 trace 合并 BNF 规则,**为不匹配的字段/记录生成选择(alternation)规则**,
   从而对多个输入做**泛化**。
6. **局限**:字节级污点在字段边界与字节边界不重合时表现差;压缩图像文件只能
   逆向出容器格式。

**结果**:10 种格式(5 文件格式 + 5 网络协议),最多 5 分钟;原型 14,000 行
C++ + 4,100 行 Perl。

#### 对本框架的可迁移点

- **Tupni 的约束分类与 `mini_parser` 的帧几乎 1:1 对应**:

  | Tupni 约束形状 | `protocol.json` 中的对应 |
  |---|---|
  | length 字段 | `payload_length`(且约束为 `len == size - MP_HEADER_SIZE`) |
  | checksum 字段 | `checksum`(`mp_checksum(payload, payload_length)`) |
  | 常量值 magic number | `magic0='M'`、`magic1='P'`、`version=1` |
  | `(R1|…|Rn)*` 记录序列 | `command_loop` |

  **这是"该任务可自动化"的最强论据**:Tupni 在 2008 年就**自动推断**出了这四类
  形状,而我们的 `protocol.json` 恰好只包含这四类。
- **chunk 分段给出 width**:`le16(data + 4)` 是一次 16 位加载,其操作数宽度
  直接给出 `width: 2`;`data[3]` 是 8 位,给出 `width: 1`。
- **Polyglot 的"不假设编码"正是我们需要的**:`le16` 是**两字节小端**,
  若沿用假设固定编码的旧方法会错。其"方向字段用点推进指针来检测"的思路,
  映射到源码层面就是"**该字段被用于计算另一个字段的访问范围**" —— 在
  `mp_parse` 里即 `len` 被用于 `malloc(len)`、`memcpy(p, data + MP_HEADER_SIZE, len)`
  和 `mp_checksum(data + MP_HEADER_SIZE, len)`,是干净的 length 字段签名。
- **Tupni 跨 trace 匹配/合并 → alternation 规则**,对应本框架应支持
  `fields[].value` 的**多候选**表示(例如 `magic` 若在不同版本间变化)。
  当前 `protocol.json` 的 schema 只有单值,建议扩展。
- **重要限制**:Polyglot / Tupni 都依赖重量级动态二进制插桩(QEMU / iDNA)。
  **对本框架不必照搬** —— 我们有源码,`le16(data+4)` 的操作数宽度可由
  tree-sitter **静态**读出(现有 `_body_facts` 已在收集
  `subscript_expressions` 与 `called_functions`)。**采纳其字段模型与约束分类,
  但用静态分析近似其分析过程**,是成本最低的路线。

---

### 1.5 StateAFL / SGFuzz — stateful context 与状态反馈

> Natella. *StateAFL: Greybox fuzzing for stateful network servers.*
> **Empirical Software Engineering** 27(191), 2022(arXiv:2110.06253)。
>
> Ba, Böhme, Mirzamomen, Roychoudhury. *Stateful Greybox Fuzzing.*
> **USENIX Security 2022**, pp. 3255–3272(arXiv:2204.02545)。

这一组是 §0.2 中 C 块 **`context` 与 stateful 语义**的对口方法。

#### StateAFL

1. **编译期插桩**:在**内存分配**与**网络 I/O** 操作上插桩。
2. **运行期状态推断**:每次请求–应答交换时,**快照长生命周期内存区域**
   (生命周期跨越整个 session 的数据,如认证状态、工作目录),**丢弃短生命周期
   数据**。
3. **模糊哈希**:用局部敏感哈希(TLSH 库 + MVPTree 近邻检索)把内存内容映射为
   **唯一状态标识**。
4. **增量构建协议状态机**并据此指导 fuzzing。无需任何协议定制。
5. **结论性发现**:从内存推断的状态比**仅用响应码**更能反映服务器行为
   (响应码会误导并产生冗余状态)。

结果:ProFuzzBench 13 个服务器,无需定制即达到或超过定制化 fuzzing。

#### SGFuzz(Stateful Greybox Fuzzing)

1. **关键观察**:协议实现中的状态变量通常用**具名常量**表示,最常见是
   **enum 类型**或 `#define` 宏。对 **Top-50 最广泛使用的开源协议实现**的调查
   显示:**每一个**实现都用具名常量表示状态;**44/50** 用枚举,**6/50** 用
   `#define`;跨 16 种协议成立。
2. **自动识别**:用**正则模式匹配**自动识别"被赋予具名常量的变量",无需手工
   标注;评测中 **>99%** 的抽取变量是真实状态变量(假阳性主要是配置变量或
   错误/响应码,它们通常不作为"稀有"状态出现)。
3. **State Transition Tree(STT)**:在**每一个状态变量赋值点**注入调用,运行期
   高效构建 STT —— 记录所有 fuzzer 生成输入序列上状态变量的取值序列,作为
   探索过的状态空间的轻量抽象(与 fuzzer 全局共享),用于引导输入生成。
4. **三条启发式**:
   - 把**触发 STT 新节点**的输入加入种子语料(不只按代码覆盖)。
   - 对遍历**稀有 STT 节点**的种子、或其后代更可能走不同 STT 路径的种子
     **加大能量分配**(核心逻辑状态序列 vs 错误处理序列)。
   - **关联输入字节与状态转移**,对"变异后能触发新 STT 节点"的字节给更多
     变异机会。

结果:状态序列覆盖比 LibFuzzer 多 33×、比 IJON 多 15×、比 AFLNet 多 260×;
相同分支覆盖快 2× 以上;12 个未知 bug、8 个 CVE,其中 10/12 是 stateful bug。

**对本框架的可迁移点** —— 这组直接决定 `contract.context` 与 `notes`:

- **`context.lifetime` 有机械判据**。StateAFL 的"长生命周期区域 vs 短生命周期
  数据"给出的正是这个判据:`mp_init`/`mp_destroy` 包围了命令行循环,说明
  上下文的生命周期**跨越循环但不跨越 iteration**。通过对 `mp_init` /
  `mp_destroy` 插桩可**自动判定**该字段,而不是靠人写散文。这与当前
  `protocol.json` 中
  `"one context per libFuzzer iteration, initialized before the command loop and destroyed after the loop"`
  完全对应。
- **`mp_context` 的 stateful 字段可由 SGFuzz 规则推广得到**。`mp_context` 的
  `saved` / `saved_len` / `owns_saved` 并非直接赋具名常量,但它们的赋值点
  **由 `MP_STORE` / `MP_RELEASE` / `MP_USE` 这些枚举值分支守卫**。把 SGFuzz 的
  规则从"被赋予具名常量的变量"推广为"**赋值点被互异具名常量守卫的变量**",
  即可自动导出 `protocol.json` 中
  `"Stateful opcodes MP_STORE, MP_RELEASE and MP_USE need a context that lives across multiple frames in one fuzz input."`
- **`observation` 字段是天然的状态观测点**。`mp_context` 里有
  `volatile uint32_t observation`,参考 harness 每帧后读一次。这正是
  StateAFL"快照 → 状态 ID"的低成本替身:对 `ctx` 每帧做快照即可得到可观测
  状态集,用来**生成 `notes` 中的 stateful 描述**,也可作为覆盖率之外的第二
  反馈信号。
- **SGFuzz 的第三条启发式可直接实现**:`structured.c` 目前对 opcode 的选择是
  `Data[pos++] % 7`,字节与状态转移之间没有关联。按 SGFuzz 的做法关联
  "哪些字节触发新 STT 节点",即可把 `selector` 描述从
  `"consume one fuzzer byte per step and map it to opcode range 1..7"`
  升级为带能量分配的策略。

---

### 1.6 NAUTILUS / Superion — 结构化输入模型 × coverage feedback

> Aschermann, Frassetto, Holz, Jauernig, Sadeghi, Teuchert. *NAUTILUS: Fishing
> for Deep Bugs with Grammars.* **NDSS 2019**。
>
> Wang, Wu, Xu, Wei, Zhang, et al. *Superion: Grammar-Aware Greybox Fuzzing.*
> **ICSE 2019**(arXiv:1812.01197)。

这一组是流水线的**消费端**:给定 `protocol.json` 之后如何把它用出价值。

#### NAUTILUS

1. 定位:**首个把语法生成与覆盖率反馈结合**的 fuzzer。纯变异 fuzzer 难以通过
   结构化输入的语法与语义检查;语法 fuzzer 能过语法但不看覆盖率。
2. **推导树(derivation tree)**作为内部表示,在树上做结构变异后再 unparse 成
   真实输入。
3. **支持用 Python 脚本扩展 CFG** 以处理非上下文无关结构(如 XML 开闭标签
   配对)。
4. **生成策略**:naive generation(随机选规则,带去重过滤)与
   **uniform generation(对所有可能性均匀采样,避免语法结构性偏好)**。
5. **最小化**:subtree minimization(把节点替换为最小子树,若仍能触发新路径)
   与 recursive minimization(其后进一步降低递归深度)。
6. 四种树变异策略 + 复用 AFL 的字节级变异。

结果:mruby 7、PHP 3、ChakraCore 2、Lua 1;覆盖率相对 AFL 高一个数量级,
相对既有语法 fuzzer 高两倍以上。

#### Superion

1. 动机:AFL 的 **trimming 与变异是语法盲的**,面对 XML/JavaScript 这类结构化
   输入时,绝大多数生成输入在早期语法解析阶段就被拒绝。
2. **语法感知的 trimming**:用解析后 AST 在**树层面**裁剪。
3. **两种语法感知变异**:增强的字典变异;**树变异** —— 用 AST 做**子树替换**,
   子树可来自目标输入自身,也可来自队列中随机选取的另一样本。
4. 解析能力由 **ANTLR4 C++ runtime** 提供。在 AFL 上扩展 3,372 行 C/C++。
5. 对比:jsfunfuzz 一个 bug 都没找到,原因正是**手工编写语法不现实**。

结果:相对 AFL 行覆盖 +16.7%、函数覆盖 +8.8%;30 个新 bug、16 个 CVE。

**对本框架的可迁移点** —— 这是"为什么要自动生成 `protocol.json`"的答案:

- **`protocol.json` 本身就是一份语法**。`frame` = 定长头 + 变长 payload,
  带字段约束;`command_loop` = `(frame)*`,上限 32。NAUTILUS/Superion 告诉
  我们拿到这份语法后该做什么:
  1. 把输入表示成**树**(命令序列 → 帧 → 头字段 + payload),而不是裸字节。
  2. 在树上做**结构变异**(子树替换),而非字节翻转。
  3. **uniform generation** 消除模偏差。
  4. **subtree minimization** 得到保持覆盖的规范种子集。
  5. **AST 级 trimming** —— AFL 默认 trimming 会破坏帧结构。
- **一个可直接验证的缺陷**:`structured.c:16` 的 opcode 选择是

  ```c
  uint8_t op = (uint8_t)(1u + (Data[pos++] % 7u));
  ```

  `256 % 7 = 4`,因此 opcode 1–4 各被命中 37 次、opcode 5–7 各 36 次
  (共 256)。NAUTILUS 的 uniform generation 批评的正是这类结构性偏好。
  虽然偏差很小,但这是"用语法模型替代取模"的一个具体、可测的收益点。
- **`selector` 与 `payload_length_source` 目前都是裸字节消费**。改为树表示后,
  这两个字段可升级为"语法驱动的选择",同时保持与覆盖率反馈的对接 ——
  即本仓库 `target_coverage.py` 已有的反馈通道。

---

## 2. 映射:每个 `protocol.json` 字段由谁负责

| `protocol.json` 元素 | 方法来源 | 具体手段 | 块 |
|---|---|---|---|
| `entry_function` | — | tree-sitter 符号表(已有 `_collect_functions`) | B |
| `frame.header_size` | Polyglot / Tupni | 常量 + 守卫子句 `size < MP_HEADER_SIZE` | B |
| `frame.max_payload` | Tupni | 枚举常量 + 守卫 `len > MP_MAX_PAYLOAD` | B |
| `opcode` 范围 `1..7` | Tupni + REDQUEEN | 枚举成员计数 + `switch(data[3])` 的 case 集合 | B |
| `fields[].offset` | Polyglot / Tupni | 下标表达式 `data[i]` / `le16(data + k)` | A |
| `fields[].width` | Tupni(chunk 分段) | 操作数宽度:`data[3]`→1、`le16`→2 | A |
| `fields[].endianness` | REDQUEEN | 字节反转探针是否命中比较 | A |
| `fields[].value`(magic/version) | REDQUEEN | compare-hook + colorization 定位常量与位置 | A |
| `fields[].value`(fuzzer 控制) | 静态 | 该位置不被任何常量比较触及 | A |
| `payload_length` 的语义类型 | Polyglot(direction field / length) + Tupni(length 约束) | 被用于计算另一字段的访问范围 | A |
| `checksum` 的语义类型 | REDQUEEN(patch+verify) + Tupni(checksum 约束) | patch 掉该校验后深层覆盖是否上升 | A |
| `command_loop` | **§1.3 Controlled Static Loop Analysis** | 循环迭代=状态,迭代依赖=转移;对**参考 harness 的循环**施加 | C |
| `context.init/destroy/lifetime` | StateAFL | 长生命周期区域 + malloc/free 包围分析 | C |
| stateful opcode 描述 | SGFuzz | "赋值点被互异具名常量守卫的变量" | C |
| `requirements` / `notes` 散文 | ChatAFL | 重复生成 + 逐字段多数投票(一致性表) | C |
| 下游如何使用 | NAUTILUS / Superion | 树化表示、uniform generation、AST 级 trimming | — |

表的实现落点(2026-09-17):**A/B 行**由 `protocol_miner.py` 从源码产出(§5.1),
**C 行**由 `protocol_conventions.py` 采样投票产出(§5.2)。一处偏差需要说明:
`command_loop` 这一行在"方法来源"里写的是 §1.3 循环分析,但第 3 步尚未实现,
**当前的 sequence model 来自 C 块(LLM)**,只有 `max_steps` 在 LLM 未给出时回落
到 `SOURCE_ENGINEERING` 的默认值——回落值带 `source` 与 `evidence` 标记,不会被
误读成实测值。等第 3 步落地后,该行的方法来源才真正成立。

---

## 3. 综合流水线

```mermaid
flowchart TD
    A[target.c + parser.h] --> B[Static Miner]
    A --> C[Dynamic Probe]
    D[参考 harness<br/>harnesses/structured.c] --> E[Loop/FSM Miner]

    B -->|常量/枚举/守卫子句/操作数宽度| F[Field Model]
    C -->|compare-hook + colorization<br/>字节反转 + checksum patch| F
    E -->|循环迭代=状态<br/>受控路径合并| G[Command Loop Model]

    F --> H[LLM 合成]
    G --> H
    H -->|ChatAFL 一致性表<br/>重复采样+多数投票| I[protocol.json 候选]

    I --> J{验证闸门}
    J -->|schema 校验<br/>扩展 load_protocol_spec| K[通过]
    J -->|覆盖率等价<br/>spec 驱动 harness vs structured.c| K
    J -->|失败| H

    K --> L["注入 prompt<br/>stage4_harness_plan / _transform<br/>的 protocol_contract 槽位"]
    K --> M["下游:树化生成 / uniform generation<br/>AST trimming / STT 反馈"]
```

上图是**设计**形状,不是当前实现形状:到 2026-09-17 为止,`B`(静态 miner)、
`F`/`G` 中来自静态分析的部分、`H`(LLM 合成,仅 C 块散文)以及持久化都已落地,
`L` 也已在 Stage 4 接通,但 `C`(动态探针)、`E`(循环建模)与 `J`(验证闸门)
尚未实现——**`L` 目前拿到的契约没有经过 `J`**。各步状态以 §5 为准。

各段与方法的对应:

- **Static Miner(§1.4 的静态近似)**:复用 `source_analysis.py` 的
  `_collect_enumerators` / `_collect_types` 取 B 块常量;复用 `_body_facts`
  的 `if_conditions` / `subscript_expressions` / `called_functions` 取 A 块的
  offset、width、守卫常量。**不需要 QEMU/iDNA 级插桩**。
- **Dynamic Probe(§1.2)**:实现 REDQUEEN 的三个原语(compare-hook、
  colorization、checksum patch+verify),复用 `target_coverage.py` 取覆盖变化。
- **Loop/FSM Miner(§1.3)**:对 `structured.c` 的 `for (step < 32)` 施加
  "迭代=状态"建模,产出 `command_loop`;对 `target.c:116` 的嵌套解析循环
  产出嵌套 payload 描述。
- **LLM 合成(§1.1)**:只负责 C 块的散文部分。输入是 A/B 块的结构化事实 +
  §1.5 的状态观测,输出受 JSON Schema 约束,N 次采样后逐字段投票。
- **验证闸门**:当前 `load_protocol_spec` 只做外壳校验(`contract` 是
  `dict(contract)` 浅拷贝透传)。需扩展为真正校验 `contract.frame.fields`,
  并增加"spec 驱动的通用 harness 覆盖率 ≈ `structured.c` 覆盖率"的等价断言。

---

## 4. 关键发现与风险

### 4.1 三个已确认的具体问题

1. **`source_analysis.py:493-496` 是硬编码**,位于通用分析模块中:

   ```python
   if "mp_init" in helper_names and "mp_destroy" in helper_names:
       hints.append("mp_init/mp_destroy are available helpers for mp_context lifetime management")
   if "mp_checksum" in helper_names:
       hints.append("mp_checksum is available as a helper for constructing parser inputs")
   ```

   若本工作的主张是通用流水线,这是可被直接指出的问题。建议按签名/调用图
   泛化(成对出现的 init/destroy;被 entry 守卫子句调用的纯函数)。

2. **`structured.c:16` 的取模偏差**(见 §1.6)。
   > 补记(2026-09-20):这一条记的是缺陷本身,**缺口在同一个循环的下一行**。
   > `structured.c:17` 的 `% (MP_MAX_PAYLOAD + 1u)` 抽的是"一段"而非"全部剩余",
   > 所以 `pos` 只推进 `len`,`:15` 的循环得以跑很多轮。契约路径丢掉的正是这条性质
   > (它把长度写成 `payload_len = remaining`,于是循环恰好跑一次)——2026-09-18 的
   > 覆盖率测量里 4 个分支的差距来自这里。诊断见 `docs/FRAMEWORK_PAIN_POINTS.md`
   > §6.2(1),方法落点见 `docs/PROTOCOL_IR_METHOD_TRANSFER.md` §1.1。

3. **纯 trace 方法会低估字段宽度 —— 这是必须走混合路线的硬证据**。
   `payload_length` 宽 2 字节(`le16`,小端),但参考 harness 里
   `len ≤ MP_MAX_PAYLOAD = 64`,于是 `frame[5] = (uint8_t)(len >> 8)`
   **恒为 0**。一个只观察合法行为的 Polyglot/Tupni 式动态挖掘器会得出
   "该字段宽 1 字节"的结论;只有读 `mp_parse` 的 `le16(data + 4)` 才能得到
   正确的 width。**字段宽度来自 parse 代码,不来自行为轨迹** —— 这条同时
   解释了为什么 §1.3 的静态方法和 §1.2 的动态方法不能互相替代。

### 4.2 循环论证风险

当前体例是:人工编写的 `protocol.json` 作为 ground truth 喂给 LLM,用于
**测量** LLM 生成 harness 的能力。若改为 LLM 自动挖掘 spec 再喂给 LLM,
测量对象就变成 LLM 的自洽性,基准失效。

**建议定位**:保留人工 spec 作为 ground truth,把 miner 作为**被评估对象** ——
即"自动协议契约挖掘准确率"的基准,`protocol.json` 作标注。这比"让流水线更
自动"更站得住,且标注数据与 `discover_protocol_spec` 的发现机制都已具备。

### 4.3 文献的共同限制

| 方法 | 限制 | 对本框架的影响 |
|---|---|---|
| Polyglot / Tupni | 依赖 QEMU / iDNA 级动态二进制插桩;字节粒度,字段边界与字节边界不重合时失效 | 不建议照搬实现,采纳其**字段模型与约束分类**,用静态分析近似 |
| Controlled Static Loop Analysis | 仅适用于"约束增强正则 + FSM 实现为解析循环"这一类协议 | 本目标的 `command_loop` 恰好属于该类,但需先固定长度约束才能收敛 |
| REDQUEEN | 输入不映射到变换后状态时失效(如哈希表索引);本身不产出声明式 spec | 作为**测量原语**使用,需外套收口逻辑 |
| ChatAFL | 输入是自然语言规范,非源码;依赖 LLM API 与速率限制 | 只迁移其**可靠性工程**(投票/重试/占位符模板) |
| StateAFL / SGFuzz | 面向网络服务器与消息序列;状态变量假设为具名常量 | `mp_context` 需把规则推广为"赋值点被互异具名常量守卫" |
| NAUTILUS / Superion | 需要**用户提供语法**;NAUTILUS 对二进制格式需额外扩展 | 语法正是我们要自动生成的产物 —— 二者互补,不冲突 |

---

## 5. 实施顺序与状态

| # | 步骤 | 状态 |
|---|---|---|
| 1 | **A/B 静态 miner**(tree-sitter,复用 `source_analysis`) | **已实现**:`harness_generation/protocol_miner.py` |
| 2 | 动态探针(REDQUEEN 三原语),判定语义类型与 endianness 的交叉验证 | 待办 |
| 3 | §1.3 循环建模,针对 `structured.c` 的循环产出 `command_loop` | 待办 |
| 4 | 验证闸门(扩展 `load_protocol_spec` + 覆盖率等价) | **待办**。原定"须先于第 5 步",实际第 5 步的 C 块合成先行落地而闸门仍未建,见 §5.3 |
| 5 | LLM 合成 + 一致性表,只用于 C 块散文 | **已实现**:`harness_generation/protocol_conventions.py` |
| 5b | A/B + C 合并为 `ProtocolIR`、持久化、CLI、下游消费 | **已实现**:`protocol_ir.py`、`protocol_cli.py`、`artifacts.py`、`stage4.py`,见 §5.2 |

第 5 步先于第 4 步落地,不是顺序被推翻,而是两件事的依赖方向本来就不同:
第 4 步要挡住的是**错误的契约进入下游**,第 5 步要挡的是**样本本身的不可靠**。
后者用投票一致性在采样内自我收口,不依赖前者;前者至今没有实现,缺口见 §5.3。

### 5.1 已实现的 A/B miner

`harness_generation.protocol_miner` 按本文 §0.2 的划分只覆盖 A/B 两块,
并强制每条事实携带源码证据:

- `mine_protocol_facts(source, function)` → `ProtocolFacts`
- `ProtocolFacts.to_contract(strict=True)` → `protocol.json` 形状的契约;
  任一字段缺证据即抛 `ProtocolMinerError`
- `limitations` 显式列出静态分析**无法**决定的内容(含"惯例块不在 parser 体内")
- CLI:`python -m harness_generation.protocol_miner --source ... --function ...`

**对 `mini_parser` 的实测结果**(`tests/test_protocol_miner.py` 的
`MiniParserMiningTests`,8 项 + 13 subtests;差分见同文件
`DifferentialAgainstHandWrittenContractTests`,5 项):

| offset | 人工 `protocol.json` | miner 恢复 | width | endianness | role |
|---|---|---|---|---|---|
| 0 | magic0 | magic0 | 1 | — | magic |
| 1 | magic1 | magic1 | 1 | — | magic |
| 2 | version | version | 1 | — | version |
| 3 | opcode | opcode | 1 | — | opcode |
| 4 | payload_length | payload_length | 2 | little_endian | payload_length |
| 6 | checksum | checksum | 2 | little_endian | checksum |
| 8 | payload | payload | var | — | payload |

`header_size` 8 = 8;`payload_offset` 8 = 8;`max_payload` 人工写的符号
`MP_MAX_PAYLOAD` 被解析为 64;opcode 范围 1..7 且枚举名全部还原。
**7/7 字段、offset、width、endianness、role 全部一致。**

`payload_offset` 是这张表原先没列出的元素,而它恰恰是**不能被上表推出**的:
`mini_parser` 的 `header_size` 与 `payload_offset` 都是 8,所以只列 header
的表分不清"payload 起点被单独测出来"与"payload 起点照抄 header"。这两者的
区别只在 header 之后存在填充或非字段字节时才显形,`PayloadOffsetMiningTests`
用一个 `header_size=8` 而 `payload_offset=12` 的夹具把它钉死
(`test_contract_reports_the_measured_payload_offset` 直接断言两者不等),
并要求证据指向被选中的那个表达式。`ConflictingPayloadRegionTests` 覆盖相邻
的坑:header 内部的 `data + K` 不得被当成 payload 起点——否则会出现两个
同 offset 的字段,而下游消费者是按 offset 索引字段的。

关键测试是
`test_every_field_evidence_points_at_real_source_lines`:它重新读取源文件,
断言每条 evidence 的 `snippet` 真的出现在它声称的那一行上 —— 否则"每字段有
证据"只是注释而不是保证。另有
`DifferentialAgainstHandWrittenContractTests` 以人工 spec 为 ground truth
做差分,即 §4.2 建议的"把 miner 当被评估对象"的落点。

**已知未覆盖**(留给第 2 步):miner 从**源码**推断 endianness 与语义类型,
尚未用 REDQUEEN 的运行期探针交叉验证。§4.1 第 3 条指出的"纯轨迹会低估字段
宽度"正是反向的;两者应当互为校验。

### 5.2 已实现的 C 块合成、合并与下游消费

第 5 步对应 §1.1 ChatAFL 迁移过来**可靠性工程**,落在
`harness_generation/protocol_conventions.py`(与 `protocol_ir.py`、`artifacts.py`、
`protocol_cli.py`):

- **采样与投票**。`infer_protocol_conventions` 顺序请求 N 个样本(CLI 默认
  `--samples 3`),逐字段投票选值。选值和计数在**同一遍**里完成:选择规则读的
  就是产生 `vote_summary` 的那个计数器,所以"某个值赢在几票"与"这个值被选中"
  不可能各算一次而算出两个答案。
- **一致性表就是置信度**。`vote_summary.confidence.value =
  sample_validity × mean_field_agreement`,即 §1.1 第 2 条那个一致性表的可计算
  形式(§2 表中 `requirements`/`notes` 一行,§3 流程图 `H --> I` 那条边)。
  这修掉的是一个具体的失真:全部样本都解析成功但**互相矛盾**时,旧的
  `llm_confidence` 仍是 1.0,与三个样本完全一致时不可区分,下游无法分辨稳定
  推断与掷骰子。`ProtocolIR` 读这个值而不是重算,所以消费方依据的数字与审计
  方能对着 `fields` 复核的数字是同一个。
- **合并**。`ProtocolIR.from_facts_and_conventions(facts, conventions)` 把 A/B
  (miner)与 C(投票)合成 `protocol_ir.json`;`to_protocol_contract()` 把它投影成
  `load_protocol_spec` 接受的 `protocol.json` 形状。
- **持久化**。三个产物写在 `--output` 根目录:`protocol_candidates.json`(A/B
  与证据)、`protocol_conventions.json`(C 块、样本与投票元数据)、
  `protocol_ir.json`(合并结果)。写法与 `write_triplets` 一致(键排序、无
  非有限数),同目标两次运行的 diff 是干净的。
- **CLI**。`protocol-mine --source ... --function ... --output ...`,加
  `--with-llm` 时摘要打印 `samples=N timeout=Ts worst_case=Ws`。`--llm-timeout`
  的默认值是 `None` 而非 `120.0`,这样它永远不成为超时的第二个来源。

**下游消费**:Stage 4 的 plan 与 transform prompt 都带 `protocol_contract`
槽位,`stage4.py` 在读 `<artifacts>/protocol_ir.json` 后填入
`to_protocol_contract()`。三条边界是刻意的:

1. 发现位置**只有**这一处(即 `protocol-mine --output` 写的那个根,也正是
   Stage 4 已经拿到的根),没有第二个位置也没有开关——一个能悄悄看别处的阶段,
   它的输入就无法从命令行读出来;
2. 文件**在但读不出/不合法**时抛 `Stage4Error`,不回落。静默回落会产出一个
   "看起来依据协议、实际什么都没被告知"的 harness,而且它会**通过**校验,
   在帧布局、长度修复与 context 生命周期上悄悄错下去;
3. 文件**不存在**时是真正的 FT-only:prompt 明确要求"用 unique ISF、必需的
   PRF/HPF 调用、函数元数据与验证反馈"并**不得**发明 framed protocol。六个
   协议关注点(帧字段、length/checksum repair、payload 由 fuzz 控制、context
   生命周期、多帧循环、stateful opcode)明确挂在"有契约"这一支下,否则
   `mp_init`/`mp_destroy` 这类 triplet 也会被要求陈述 header 字段的 endianness。

> 表述边界:**Stage 4 不再依赖手写 `protocol.json`**,但全仓不是。
> `candidate.py` 的 `discover_protocol_spec` 路径仍会发现并加载它,那是另一条
> 流水线;手写的 `benchmarks/mini_parser/protocol.json` 同时是 miner 测试的
> ground truth,不应删除。

### 5.3 验证闸门(第 4 步)

第 5 步落地后,§3 流程图里 `I --> J{验证闸门}` 这一段仍是空的。当前契约只是
prompt 输入:LLM 把 `payload_offset` 写错、漏掉 checksum 修复或改了
`max_payload_symbol`,原先 Stage 4 的校验器不会拦。

按依赖顺序的三项,现状:

1. schema 层:真正校验 `contract.frame.fields`,而不是只确认键存在 —— **待办**。
   `load_protocol_spec` 仍是外壳校验(`contract` 是浅拷贝透传)。
2. **plan ↔ contract 一致性** —— **已实现**,见下文。
3. 覆盖率等价:"spec 驱动的通用 harness 覆盖率 ≈ `structured.c` 覆盖率" ——
   **已测量,见 §5.3.2**。它是动态问题,不属于静态闸门,因此作为**基准级验收
   指标**关闭,而不是接进 Stage 4。

> 补记(2026-09-20):上面三项都在问"**产物对不对**",缺一项问
> "**这次失败是产物错,还是工具链错**"。这一项不是锦上添花:当前 gate 把
> "没测到"与"测到但更低"归约成同一个词(不达标),而 harness 以 C++ 编译、
> 却由 C 驱动 `clang` 链接,一个用了 `std::vector` 的合法 harness 会因此链接失败、
> 得到空统计,进而被报成"覆盖率低于参考"。诊断与修法见
> `docs/FRAMEWORK_PAIN_POINTS.md` §3.2 / §3.4 / P0-d。

#### 5.3.1 plan ↔ contract 一致性闸门(已实现)

**Typed Contract Projection + 结构化 binding + 确定性比较**,落在
`harness_generation/protocol_plan_validation.py`,在 `Stage4Generator.run()` 里
插在 `parse_harness_plan(...)` 之后、transform prompt 之前。位置是刻意的:
闸门要挡的是**错误的 plan 继续污染 transform**,放到最终 harness 审计之后
就只能事后追认。

- **投影** `protocol_contract_projection(ir, project_functions=...)` 把 mined IR
  压成一份"必须被 plan 保留的规范摘要":`frame`(header_size / payload_offset /
  max_payload / max_payload_symbol / 每个字段的 role+offset+width+endianness)、
  `input_model`(bounded_multi_frame / bounded_steps / payload 受 fuzz 控制 /
  length+checksum 修复)、`context`(type / init / destroy / lifetime)、
  `stateful_operations`、`helpers`(只含证据支撑**且**项目真有定义的)。
- **plan 必须返回** `protocol_contract_bindings`,形状相同,取值是数字、布尔、
  枚举或从投影抄来的 token。投影直接就渲染在 plan prompt 里(prompt 升到
  `stage4-harness-plan-v7`),所以"照抄"是明确指令而不是猜测。
- **比较** `validate_plan_contract(...)` 是纯确定性的:不重挖协议、不读散文、
  不调用 LLM。硬拒项包括 `payload_offset` 写错、字段增删、magic/version 字面量
  不符、漏声明 length/checksum 修复、有契约却无有界多帧循环、`context` 缺失或
  `lifetime` 是 `per_frame`、stateful opcode 增删、helper 不在证据∩项目集合内。
  契约能"要求"行为却不能"禁止"更谨慎,所以这几项是单向的;而抓**凭空发明**的
  三项(多出的字段 / opcode / helper)是集合比较,双向。

**刻意不查的**(写进 `ProtocolContractProjection.warnings`,只记录不判失败,诚实
划出静态闸门的边界):miner 的**描述性**字段值(`"le16() load"` 之类;只有
magic/version 这类裸 C 常量才是字面量并参与比较)、IR 的 `requirements`/`notes`
散文、`limitations`。覆盖率等价另属第 3 项。

无 `protocol_ir.json` 时投影为 `None`,plan 不得携带 bindings(`plan.json` 因此
不新增任何键),FT-only 路径逐字未变。

#### 5.3.2 覆盖率等价(已测量)

**报告:`docs/COVERAGE_EQUIVALENCE.md`;驱动:`harness_generation/coverage_arms.py`
(CLI 子命令 `coverage-arms`);证据:`tests/fixtures/coverage_arms/measurements.json`。**
报告由证据渲染而成,没有手写数字;`coverage-arms --check` 能在没有编译器、没有
LLM 的情况下重算每一个判定。

> 补记(2026-09-20):可复现性主张**只到"判定"层,不到"输入"层**。实测
> `verify_manifest`(`coverage_arms.py:267`)只遍历 `manifest.arms`,
> `target_source.sha256` 与 `corpus.digests` **从不被读**——改了 `target.c` 或语料后
> 重跑,`--check` 不报任何问题。见 `docs/FRAMEWORK_PAIN_POINTS.md` §4。

在 mini_parser 这一个基准上,`-runs=20000`、3 个 seed、5 个 arm,候选
`contracted`(正式 publish 的 1845 B harness)对 `reference`(`structured.c`):

| 指标 | reference | contracted | ratio | 判定 |
|---|---|---|---|---|
| lines | 95.122% | 95.122% | 1.0 | 达标 |
| regions | 92.1053% | 88.1579% | 0.957 | 容差内(tolerance 0.05) |
| branches | 82.3529% | 77.9412% | 0.946 | **未达标** |

**结论:不宣称等价** —— `below_reference`。branches 这一项候选比参考低 4.4 个
百分点,超出容差。报告把结论写成三层(见 `COVERAGE_EQUIVALENCE.md` 的
`## Conclusion`,每一句都由证据渲染):

1. **contract 路径显著优于 FT-only arm** —— 取 contracted 最差 seed 与 ft_only
   最好 seed 相比,三个指标分别领先 82.9 / 67.1 / 66.2 个百分点;ft_only 只进入
   target 的 5 个函数中的 3 个,且它只是"没给合约时 pipeline 自己的产物"。
2. **但尚未达到手写 reference,因此不宣称等价** —— branch ratio 0.946 低于容差
   下限 0.95;region 0.957 在容差内但不等;line 1.0 达标。
3. **剩下的是 harness quality gap,不是 pipeline 断链** —— contracted 是正式
   publish 产物、能 build、能跑满 20000 次,且每次运行都以 sanitizer finding
   结束并落在 `target.c:73` / `target.c:91`(与 reference 同一批 frame)。缺的是
   结构策略覆盖分支空间的能力,不是链路本身。**缩小它要改策略,不是改阈值。**

三条必须随数字一起读的限定:

- **`cov`/`ft` 是 engine-level,不是目标源码覆盖率。** 它们来自 libFuzzer 对整个
  插桩程序(含 harness 自身)的计数,只作遥测;闸门只读 `llvm-cov` 过滤到
  `target.c` 的那一层。两者在报告里分层分表,不混用。
- **判定是 budget-relative 的。** 同一批 arm 在 `-runs=2000` 时三个指标全部不达标
  (lines ratio 0.833);即 contract 路径要多跑一些执行次数才能达到 reference 一次
  就到的覆盖。报告同时给出两个预算,并明确这属于 harness 的性质、不是测量错误。
- **等量工作要求关掉 sanitizer。** 带 ASan/UBSan 时,reference 跑 10–43 次就崩、
  contracted 跑 801–1348 次才崩,覆盖率变成"崩得多快",跨 arm 不可比。所以覆盖层
  不带 sanitizer 构建,每个 arm 跑满同一个 `-runs`。

另有三项如实记录:

- **FT-only arm(494 B,无 `protocol_ir.json` 时 publish 的产物)**只覆盖 12.2% 的
  行,与 tracked baseline `pass_through` 逐位相同,即 `ft_only − pass_through` 的
  recipe 效应为 0 —— 上面那张表的差距不是编译方式造成的。
- **被审计拒绝的 `attempt_003` 覆盖率与正式发布物相当**,说明**该拒绝不是覆盖率
  过滤器**:它拒的是 harness 私自复刻项目算法,与覆盖无关。它因此在报告里只作
  `diagnostic_rejected`,**不作为候选**,也不能被 gate 读取。
- **seed 只证明确定性,不构成独立样本。** `-seed=1/2/3` 确实传到了命令行
  (`commands.json` 可查),但覆盖层在 `-runs=20000` 已饱和,除 `rejected_attempt_003`
  外每个 arm 三个 seed 数字完全相同。所以那次 sweep 是"同一个数测了三遍",
  报告有专门的 `### Seed spread` 段落把这件事说出来,而不是让读者当成三次独立确认。

测量装置本身修掉两个缺陷(报告 `## Evaluation infrastructure fixes`):two-TU arm
的 `./fuzz_target` 副本丢可执行位(`shutil.copyfile` 不保 mode,导致 Layer A 整列
`error` 空统计),以及 toolchain 版本解析用裸 `shutil.which` 而 collector 用带版本
名的 `llvm-cov-18`(报告曾印出"unavailable"却正是它跑的测量)。两处修完后**重跑了
campaign**,而不是手改证据 —— 这个模块的全部意义就是文档里不能有跑不出来的数字。

**边界**:一个基准、一个目标函数、一份语料、一个预算;且闸门只在存在手写参考
harness 的地方可定义。因此它关闭的是 §5.3 第 3 项作为**基准级验收指标**,不是
生产环境验证器 —— 接进 Stage 4 意味着每次 attempt 都要跑一整轮 fuzz campaign,
而对任意 target 并没有 `structured.c` 可比。完整限定见报告 Caveats (a)–(j)。

---

## 6. 参考

| 工作 | 出处 | 链接 |
|---|---|---|
| ChatAFL | NDSS 2024 | <https://www.ndss-symposium.org/ndss-paper/large-language-model-guided-protocol-Fuzzing/> · <https://github.com/ChatAFLndss/ChatAFL> |
| REDQUEEN | NDSS 2019 | <https://dev.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04A-2_Aschermann_paper.pdf> |
| Extracting Protocol Format as State Machine via Controlled Static Loop Analysis | USENIX Security 2023, pp. 7019–7036 | arXiv:2305.13483 |
| Polyglot | CCS 2007, pp. 317–329 | <https://dl.acm.org/doi/abs/10.1145/1315245.1315286> |
| Tupni | CCS 2008, pp. 391–402 | <https://dl.acm.org/doi/10.1145/1455770.1455820> |
| StateAFL | Empirical Software Engineering 27(191), 2022 | arXiv:2110.06253 |
| Stateful Greybox Fuzzing(SGFuzz) | USENIX Security 2022, pp. 3255–3272 | <https://www.usenix.org/conference/usenixsecurity22/presentation/ba> |
| NAUTILUS | NDSS 2019 | <https://www.ndss-symposium.org/ndss-paper/nautilus-fishing-for-deep-bugs-with-grammars/> |
| Superion | ICSE 2019 | arXiv:1812.01197 |

**venue 更正说明**:REDQUEEN 发表于 NDSS 2019(非 USENIX);StateAFL 发表于
*Empirical Software Engineering* 2022(非 NDSS),NDSS 2022 无此文。
