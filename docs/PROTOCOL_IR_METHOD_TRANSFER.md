# ProtocolIR 方法迁移:从相关工作到本框架的可落地改动

本文回答一个问题:**把外部工作里的方法,变成这个仓库里可以动手改的东西。**

三份文档的分工:

| 文档 | 问的问题 |
|---|---|
| `docs/PROTOCOL_FORMAT_MINING.md` | 怎么把 `protocol.json` 从手写变成自动抽取 |
| `docs/PROTOCOL_IR_RELATED_WORK.md` | 抽出来之后,IR 缺的那一块别人怎么做过了(文献综述) |
| **本文** | **那些方法具体落到哪个 schema 字段 / 哪个函数 / 哪个闸门,代价多少,怎么验证** |

本文与综述的区别是**每一条方法都要回答"改哪里"和"凭什么说改对了"**。凡是没有落点的,
归入 §4「不采纳」并写明理由,不占篇幅。

---

## 1. 缺口的第一手证据

全部来自本仓库,可复核。

### 1.1 两行 C 的对照

**手写 reference**(`benchmarks/mini_parser/harnesses/structured.c:14-33`,省去 checksum 行):

```c
size_t pos = 0;
for (unsigned step = 0; step < 32 && Size - pos >= 2; ++step) {
    uint8_t op = (uint8_t)(1u + (Data[pos++] % 7u));                   // opcode: 抽出来的
    size_t requested = (size_t)(Data[pos++] % (MP_MAX_PAYLOAD + 1u));  // 长度: 抽出来的
    size_t len = hg_min_size(requested, Size - pos);                   // 再钳到剩余

    uint8_t frame[MP_HEADER_SIZE + MP_MAX_PAYLOAD] = {'M', 'P', 1, op};
    ...
    pos += len;
}
```

**opcode 与长度都是从 fuzz 字节抽出来的取值**;因为抽的是 `% 65` 而不是"全部剩余",
抽完通常还剩输入,`pos` 只推进 `len`,`Size - pos >= 2` 得以继续成立。循环因此真的跑很多轮。

**ProtocolIR 驱动的发布物**(`tests/fixtures/coverage_arms/contracted_published.c:40-43`):

```c
size_t remaining = size - (offset + MP_HEADER_SIZE);
size_t payload_len = remaining;
if (payload_len > MP_MAX_PAYLOAD) {
    payload_len = MP_MAX_PAYLOAD;
}
```

长度是**剩余输入本身**。第一次迭代 `offset == 0`,故 `frame_len == size`,走完 `offset += frame_len`
循环即退出——**任何 ≤72 字节的输入循环只跑一次**(`MP_HEADER_SIZE = 8` + `MP_MAX_PAYLOAD = 64`,
`benchmarks/mini_parser/target.c:13`)。语料种子 2–9 字节。

于是 STORE→USE / STORE→RELEASE 跨帧序列**在结构上不可能发生**——而这正是那 4 个丢失
direction 的全部所在(`target.c:97`/`105`/`112`)。

**两处都写了 `payload_len` 进帧、都从 `data` 拷贝了 payload。差别只在这个数从哪来。**

### 1.2 IR 已经知道答案,而且说了三遍

**证据 A——IR 自己点名了这个缺口。**
`tests/fixtures/stage4_recorded_attempts/protocol_ir.json` 的 `limitations[0]`,逐字:

> `field_8 has a variable width; it must be tied to the length field by a later stage`

这条被 **pin 在测试里**(`tests/test_protocol_ir.py:794-796`),即它是真 miner 对真 target
的稳定产物,不是某次运行的偶然输出。IR 明确说了"要由**后续阶段**把它绑到长度字段",而后续阶段没做。

**证据 B——顺序依赖也在 IR 里,以散文形式。**
同一份 IR 的三个 `stateful_operations[*].reason`,逐字:

- `MP_RELEASE`: "MP_RELEASE frees ctx->saved and clears ctx->owns_saved, **changing persistent
  context state for subsequent frames**."
- `MP_STORE`: "MP_STORE transfers ownership of the payload buffer into ctx->saved and sets
  ctx->owns_saved, **mutating persistent context state used by later frames**."
- `MP_USE`: "MP_USE reads ctx->saved and ctx->saved_len, so **its behavior depends on prior
  MP_STORE/MP_RELEASE frames within the same context lifetime**."

挖矿那一层**完全理解**这是个有序状态机。但 `StatefulOperation = {opcode, reason, evidence}`
(`harness_generation/protocol_conventions.py:69-72`)没有地方放这个理解,投影
(`protocol_plan_validation.py:200-202`)把它压成 `sorted(opcode)`,闸门
(`:530-546`)做集合差。

**证据 C——格式关系的方向是反的。**
IR 的 `frame.fields` 里:

```
payload   role=payload   offset=8   width=payload_length   value='fuzzer-controlled bytes'
```

`width = "payload_length"` 说的是"**payload 的宽度由 payload_length 字段给出**"——这是**解析**
方向(从线上读一个数,再决定读多少)。而生成 harness 没有线:它必须**先定 payload,再算长度字段**。

`FrameField.width: int | str`(`harness_generation/protocol_ir.py:186`)的 docstring 就写着
"the name of the field that sizes it"——**一个裸字段名,没有类型**。这是 Peach
`Relation type="size"` 的无类型退化版。

### 1.3 契约在哪儿漏掉它

`protocol_contract_projection`(`protocol_plan_validation.py:152-207`)产出的 `input_model`
一共四条策略条款,加上 frame / context / stateful / helpers 四块。逐条对 contracted harness:

| 契约条款 | 投影从哪来 | 闸门怎么判 | contracted harness |
|---|---|---|---|
| `bounded_multi_frame` | `sequence_model.multi_frame` | 必须是 `true` | ✅ 是 |
| `bounded_steps` | `max_steps.value = 32`,`source = engineering_choice` | 正整数,且与 plan 一致 | ✅ 32 |
| `payload_fuzzer_controlled` | `ROLE_PAYLOAD in roles` | 必须是 `true` | ✅ 有 memcpy from `data` |
| `repair_length` | `ROLE_PAYLOAD_LENGTH in roles` | 必须是 `true` | ✅ 写了 `payload_len` 进帧 |
| `repair_checksum` | `ROLE_CHECKSUM in roles` | 必须是 `true` | ✅ 算了 checksum |
| `stateful_operations` | `sorted(opcode)` | 集合比较 | ✅ 三个都在 |
| **`limitations`** | IR 原文 | **只进 `warnings`,从不判定**(`:382-383`) | ❌ **没被满足——但没人在看** |

(上表逐条**读发布物正文核实**,不是从条款推断:循环在 `:31`、`max_steps = 32` 在 `:29`、
payload 来自 fuzz 字节在 `:53-54`、长度字段写回在 `:50-51`、checksum 写回在 `:57-59`、
`mp_init`/`mp_destroy` 在 `:26`/`:68`。)

**唯一没被检查的那条,恰好是唯一没被满足的那条。**

**附带发现(同一失效类,不在本文方法清单内)**:该 harness 在 `:7` **手抄了 `mp_context`
的字段布局**。IR 的 `context` 只给 `type` / `init` / `destroy` / `lifetime`,**没有字段布局**,
所以 harness 必须自己猜对——猜错的后果不是编译错,是静默的栈溢出或读错偏移。这与 §1.3 是
同一件事(声明与产物之间没有检查),只是换了一个对象。

三条损失全部有据:

1. `payload_fuzzer_controlled` 只能说"payload 来自 fuzz 字节",说不出"**长度是从 payload 抽的**"。
   投影从 `ROLE_PAYLOAD in roles` 推导它——**只看字段存不存在**。
2. `repair_length` 只要求"有个长度字段要填"。harness 填了,填的是 `remaining`——条款无法区分。
3. `bounded_steps = 32` 的 `source` 是 `engineering_choice`(证据只有一句尾注释),投影对它
   只发一条 warning("the contract's loop cap is a harness policy, not source-backed")。
   **声明"跑 32 帧"与"实际只跑一帧"之间没有任何检查。**
4. `limitations` 被设计性地排除在判定之外——`_projection_warnings` 的 docstring 自己说这是
   "the honest boundary of a static gate"。这个设计选择本身没错,问题是**缺的东西恰好只能
   落在这里**,于是它成了缺口自己写下的墓志铭。

> **边界(诚实起见)**:驱动那次 coverage 的 IR 在 `/tmp/hg_recording`,该目录已清空。
> 本节引用的是**同为真 DeepSeek 对同一 target** 挖出来的录制 IR,结构同形且有测试 pin;
> 但我无法逐字引用那一份。

---

## 2. 方法抽取

每条给出:来源与核实等级 / 机制(逐字证据)/ **落到本框架哪里** / 代价 / **怎么验证** / 边界。

**编号是加入顺序,不是阅读顺序**(M9–M11 是后加入的,排在 M6–M8 之前)。索引:

| | 方法 | 来源 | 定位 |
|---|---|---|---|
| M1 | 带类型的字段关系 | Peach Pit `Relation` | **已实现**(§5 第 1 步) |
| M2 | 状态变量 + 转移 | NSFuzz | **已实现**(§5 第 2 步) |
| M3 | 单 buffer 内多帧 + 前缀重放 | AFLNet | 概念前置(无独立改动) |
| M4 | 让 LLM 写采样器,而不是写序列 | LLM4Fuzz | **下一步**(§5 第 4 步) |
| M5 | 反馈的表示法:注释视图 | SeedMind + SBFT 2026 | 记录;§3 之后那一步的输入 |
| M6 | 先问 LLM"这个分支是否 input-dependent" | Bulbasaur | 生成侧 prompt 级;与 M4 同批 |
| M7 | states/messages/transitions 统一成 nonterminal | FANDANGO | **不采纳为下一步**(§4) |
| M8 | 评测口径 | SoK + SBFT 2026 | 记录;一处可发表的空白 |
| M9 | **生成方差是主方差** | FuzzAgent | **约束验收方式**(§5 第 5 步) |
| M10 | 分层校验 + 回滚,而不是修最终产物 | SynapseFlow | ⚠️ **归属待裁定**,见本节 |
| M11 | 让两个产物互为 oracle | SPAR(USENIX Sec 2026) | 记录;§1.3 的**终局形态**,非本轮 |

### M1 · 带类型的字段关系(Peach Pit `Relation`)

**来源**:Peach Pit `DataModel` 的 `<Relation>` 元素。[A 级——已回原文核 `Relation` 与 `Fixup`]

**机制**(逐字):`<Relation>` 带 `type`(取值 `Size` / `Count` / `Offset`)+ `of`,让 Peach 在变异时
自动维护长度、元素计数、偏移;可选 `expressionGet` / `expressionSet`,**两者必须互为逆**;
checksum 走独立的 `<Fixup>`。

**落到本框架**:`harness_generation/protocol_ir.py` 新增

```python
@dataclass(frozen=True)
class FieldRelation:
    kind: str        # "size_of" | "count_of" | "offset_of"
    target: str      # 被度量的字段名
    direction: str   # "parse" | "construct"
```

`FrameField` 增 `relation: FieldRelation | None = None`;`width` **保留不动**(向后兼容,
现有 IR 与全部 fixture 继续可读)。

`direction` 这一维不是 Peach 的字段名,而是它的 `expressionGet`/`expressionSet` 逆对在**我们
语境下的命名**:IR 现在写的 `payload.width = "payload_length"` 是 `parse` 方向,而生成 harness
需要的是 `construct` 方向("先定 payload 长度,再算长度字段")。**两者都要在 IR 里,缺的正是后者。**

**代价**:小。新增 dataclass + 两个可选字段,`to_json`/`from_json`/`to_contract_block` 各加一处;
`to_contract_block` 的投影要**保留 relation**(它是 LLM 必须照抄的语义,不是 provenance)。
miner 侧需要一层从现有 `_length_field_name` 事实推导 `parse` 方向的桥——这是唯一有技术含量的部分。

**怎么验证**:①现有 IR/fixture 全部仍能 round-trip(零修改);②新增单测:给定录制 IR,
`payload.relation == FieldRelation("size_of", "payload", "parse")` 可被推导出来;
③`to_contract_block()` 的投影含 relation,且 plan 闸门新增一条"构造方向缺失即拒"。

**边界**:Peach 的 relation 由**人**写进 `.pits` 模板;我们从源码自动推 `parse` 方向是可靠的
(长度字段就在头里),但**推不出** `construct` 方向——那是**策略选择**,不是源码事实。所以
`construct` 方向只能来自 LLM 推断,必须带 `source` / `confidence` / `evidence`,与 IR 其余部分
同等对待。

**2026 年文献核查:先说结论,再说一个会推翻它的反例。**

**(a) 协议挖矿这一支(从流量/源码反推格式)确实都没有 typed relation:**

- **APFuzz**(arXiv 2602.21892,2026,自动灰盒协议 fuzzing)的报文模型是最弱的:
  字段只有 `(name, bit_start, bit_length)` 三元组,**零字段间关系**。全文检索
  "length field" / "size field" / "offset field" / "count field" **全部 0 命中**。
  它**自己把这件事写成了局限**,逐字:
  > "it primarily focuses on message format extraction and **does not fully address the
  > dependency problem inherent in binary protocols**"

  并在未来工作里点名:
  > "Future work could focus on addressing **protocol field dependencies** in binary protocols"

- **SemFuzz**(arXiv 2603.05989,2026)有更丰富的声明式模型(`R` / `SR` / `M` / `A` 四层),
  但它的**字段表示被刻意压成只有名字**。逐字:
  > "the module extracts the message structure F_i, **retaining only field paths (i.e., field
  > names k)** to provide contextual information"

  长度依赖**不是声明在模型里,而是在引擎里用命令式规则重算**。逐字:
  > "if an extension is inserted, the engine **computes and updates the associated
  > extension_len field accordingly**"
  > "When an action contains incomplete parameters (e.g., missing length fields), the module
  > automatically infers and fills them"

  **这两句正是 §1.1 那个缺口的另一种写法**:声明层不表达"长度从哪来",于是执行层替它决定。
  差别只在于 SemFuzz 把这件事**显式地**交给引擎(它的设计),而我们把它**隐式地**交给了模型
  (我们的缺口)。**SemFuzz 因此是我们的对照组,不是我们的先例。**

- **APFuzz 与 SemFuzz 都没有**把"A 的长度等于 B"表达为表示层的一部分。(第三篇 SynapseFlow
  **根本不是协议工作**——它自己在 Limitations 里把协议实现排除在外;且其归属待裁定,见 M10。
  所以它既不算同类系统,也不算这条结论的证据。)

**(b) 但反例存在,而且很强——SPAR(USENIX Security 2026, pp. 4069–4088)。**
南京大学,arXiv 无全文但 **USENIX 开放获取 PDF 已逐字读到**(A 级)。它**有** typed relation:
用微软的 **3D / EverParse** 描述语言,数组长度写成对字段的算术函数
`ArrayType ::= Type[const] | Type[h(field_identifier +)]`,字段约束写成对多字段的谓词
`{f(field_identifier+)}`。它自己的 IR 叫 **PFG(Packet Format Graph)**,顶点是
`(τ, ω, φ)`(类型、字段名、约束),边长是**包内**字段顺序。BABEL 那个例子逐字:

```
UINT8 Plen { Plen <=248};
UINT8 Omitted { (AE==3 && Omitted==0) || (AE!=3 && Omitted<=((Plen+7)/8)) };
UINT8[(Plen+7)/8-Omitted] Prefix;
```

> "The length of this field is constrained by the values of Plen and Omitted."

**所以必须纠正一个容易犯的过度断言**:`M1` **不是**"没人做过的东西"。typed relation 在
2026 年已经有 A 级的先例,而且是拿成熟的形式化语言做的。本文里 M1 的正确定位是:

| 维度 | SPAR(已有) | 我们(缺的) |
|---|---|---|
| typed relation 本身 | ✅ 3D 语法,类型完整 | — |
| 关系方向 | **两个方向都用了**:校验时按它判、生成时按它解 | **只有 parse 方向**(`width="payload_length"`) |
| 关系从哪来 | **RFC 文档 + LLM**,再加对抗式精化 | **从源码自动推** |
| 变量长度怎么定值 | **调 SMT(Z3)解出**合法常数 | **没有这一步**——模型直接写 `remaining` |

SPAR 定长度那步逐字:

> "we invoke an **SMT solver** over the accumulated constraints upon reaching this field to
> compute possible values of Plen and Omitted. As a result, we can compute a possible
> constant length c = (Plen+7)/8-Omitted."

**注意这一步仍然不是我们的答案。** SPAR 解出的是**一个满足约束的常数**——它服务于"造出
合法包去测 parser",长度**不是从 fuzz 字节抽的**。所以 SPAR 与 SemFuzz 落在同一边:
**执行层把长度算出来**。§1.1 要的是**另一边**:长度**本身是 fuzz 的输入**。这个位置在
2026 年的文献里**依然是空的**——但空的是"构造方向 + fuzz 可控",**不是**"typed relation"。

SPAR 的 Limitations 还顺手证实了另外两件事(逐字):

> "it **does not enforce global semantic constraints** or dependencies between fields located
> across different structures. Enhancing the expressiveness of the underlying formal
> specifications to accommodate these sophisticated, **state-dependent protocol
> architectures** remains a valuable direction for future work."

即:**它也不建模协议状态**——与 M2 要补的位置恰好一致。

---

### M2 · 状态变量 + 转移(NSFuzz)

**来源**:NSFuzz,TOSEM 2023,DOI 10.1145/3580598。[C 级——只见摘要,引用前须自取全文]

**机制**:静态分析 + 注解 API 在 SUT 源码里定位 **I/O synchronization point** 与
**state variable**;运行时对 `shared_state` buffer 求哈希打成 state id,任一状态变量变化即判定
状态转移——从而避免 StateAFL 的 post-execution 分析开销。

**落到本框架**:`stateful_operations` 从 opcode 列表升级为**状态变量 + 转移**:

```python
@dataclass(frozen=True)
class StateVariable:
    name: str        # "ctx->owns_saved", "ctx->saved", "ctx->saved_len"
    owner: str       # "mp_context"
    evidence: tuple[ProtocolEvidence, ...]

@dataclass(frozen=True)
class StatefulOperation:
    opcode: str
    reason: str = ""
    evidence: tuple[ProtocolEvidence, ...] = ()
    writes: tuple[str, ...] = ()   # 状态变量名
    reads:  tuple[str, ...] = ()   # 状态变量名
```

**为什么这是最低成本路径**:见 §1.2 证据 B——**这些状态变量名已经在 IR 的 `evidence` 里了**,
逐字:`"ctx->owns_saved = 1;"`、`"ctx->saved = p;"`、`"if (ctx->owns_saved) free(ctx->saved);"`。
缺的只是把它们**结构化地写出来**,而不是留在证据字符串里。

有了 `writes`/`reads`,顺序约束**可以自动推导**:`MP_USE.reads ∩ MP_STORE.writes ≠ ∅`
⇒ USE 必须在 STORE 之后。闸门因此可以检查 `stateful_operations` 的**顺序**而不只是集合。

**已在录制 IR 上实测**(正则 `\b([A-Za-z_]\w*)->(\w+)\b` 扫 `evidence`,读/写按是否后跟 `=` 区分):

```
MP_RELEASE:  writes {ctx->owns_saved}; reads {ctx->owns_saved}
MP_STORE:    writes {ctx->saved, ctx->saved_len, ctx->owns_saved}
MP_USE:      reads  {ctx->saved, ctx->saved_len}; writes {ctx->observation}
```

于是顺序约束**直接可推**:

```
MP_USE.reads ∩ MP_STORE.writes = {ctx->saved, ctx->saved_len} ≠ ∅
  ⇒ USE 必须在 STORE 之后
```

**这一条今天算不出来,只是因为没有把这两个集合写下来**——数据早就在 IR 里,连证据字符串都带着。
这里把 `free(ctx->saved)` 视为释放行为，不视为对 `ctx->saved` 成员的直接赋值；
`ctx->observation = ...` 则是写入。原表将这两处分类错了，实现按源码语句纠正。

**代价**:中。改 `protocol_conventions.py` 的 dataclass(现有 `evidence` 语义不变)、
miner 加一步从证据字符串抽取状态变量与读/写、投影与闸门各加一条。抽取本身是一行正则。

**怎么验证**:①录制 IR 的 `stateful_operations[*].writes/reads` 非空且与证据一致(上面这张表
可直接写成断言);②新增闸门测试:plan 声明 `[MP_STORE, MP_USE]` 通过、`[MP_USE, MP_STORE]`
(顺序颠倒)被拒——**这条今天做不到,正是要修的东西**;③现有 `_stateful_violations` 的集合
语义仍保留(顺序是**追加**约束,不是替换),FT-only 路径逐字不变。

**两条实测出来的注意点**:

- 判据必须是**交集**(`reads ∩ writes`)而不是并集。`ctx->observation` 只出现在 `MP_USE` 里,
  它是**输出**,不是被共享的状态;用并集会凭空造出"USE 之间互有顺序"这种假约束。
- 读/写分类是**启发式**。"后跟 `=` 即写" 覆盖不了 `ctx->saved_len++`、复合赋值、以及
  "传进一个会改它的函数"。这条与仓库里已有的 `_unique_local_aliases` 同一性质:**保守,
  **宁可漏判不可误判**——漏判只是少一条顺序约束(退回今天的行为),误判会拒掉正确的 harness。

**边界**:NSFuzz 的运行时哈希成 state id 对**离线评 harness** 不适用(我们没有运行时状态反馈)。
只借它的**静态 state variable 定位**这一半。

---

### M3 · 单 buffer 内多帧 + 前缀重放(AFLNet)

**来源**:AFLNet,ICST 2020;五年回顾 IEEE TSE 51(4), 2025, DOI 10.1109/TSE.2025.3535925。
[C 级]

**机制**:代码覆盖 + 状态覆盖双反馈;用响应码作协议状态代理,在线学习状态机(IPSM);
Target State Selector 选目标状态 → Sequence Selector **重放前缀**到达该状态 → 只变异该状态下
消费的消息。

**落到本框架**:STORE/USE/RELEASE 本质就是"必须先到达某状态才能执行后续操作"。映射到单进程
harness 即:**在同一个 buffer 里构造帧序列**——这正是 reference 做的事(§1.1 左),也是
contracted 做不到的事(§1.1 右)。

**这是 M4 的前置**:没有"单 buffer 多帧"这个执行模型,序列采样器无处安放。

**代价**:小(概念上已具备)。`sequence_model.multi_frame` 已经是 `true`,`bounded_steps` 已经
是 32。**真正缺的不是"声明多帧",是"让多帧真的发生"**——即 §1.3 第 1、2、3 条。

**怎么验证**:这一条的验证就是本任务的总验收(见 §3)。

**边界**:AFLNet 的前缀重放是**在线**的(靠响应码知道到没到目标状态);我们的 target 单进程、
无响应码,没有等价的在线信号。所以借的是**执行模型**,不是它的选择算法。

---

### M4 · 让 LLM 写采样器,而不是写序列(LLM4Fuzz)

**来源**:arXiv 2508.01750。[A 级——核心已核,两处细节已纠正]

**机制**(逐字):abstract 原话 *"we prompt the LLM to generate code that produces sequences of
states"*;**"This program serves as a protocol-specific sequences generator"**。3 个协议实现
(MQTT / Modbus / DAAP)、12 个新漏洞。

**已纠正的两处(勿再引用)**:① "5–7 个状态"论文里没有(原文 "a small but essential subset",
prompt 用 `{number}` 占位符);② 反馈回路存在但**不是覆盖率反馈**——原话 *"We do not report
traditional code coverage metrics"*。

**落到本框架**:Stage 4 的产物形态。现在的 prompt 让模型产出一个**循环**(隐式序列);
M4 建议改成让模型产出一个**受约束的序列采样函数**——显式回答"这一帧的 opcode 从哪来、
长度从哪来、循环什么时候继续"。§1.1 的两行 C 正是"循环"与"采样器"的差别。

**代价**:小到中。`stage4` 的 prompt 模板加一段;产物仍是 C,不新增文件类型。

**怎么验证**:prompt 升版后真机重跑,看生成的 harness 里长度表达式**是否来自输入**
(可直接 grep 生成物:`% (MP_MAX_PAYLOAD + 1u)` 形态)。

**边界**:M4 是**生成侧**的改动;**它不构成闸门**。没有 M1 的 relation 与 §3 的判定条款,
prompt 改了也可能继续生成饱和式长度——而且我们没有任何东西能发现。**M4 必须与 M1 配套,单独做
等于把缺口从"结构不可能"降级为"概率上不常发生"。**

---

### M5 · 反馈的表示法:注释视图,而不是未覆盖行列表

**两份独立来源,B 级 + A 级,结论一致。**

**来源一**:SeedMind,arXiv 2411.18143。[B 级]
LLM 产 Python generator 脚本;循环是 执行 → 收 branch coverage → 把函数分
fully / partially / 未覆盖三类 → **只把 partially covered 放进 prompt** → 关键一步:一个
**"摘要 prompt"把 coverage report 转成 2–3 句自然语言诊断 + 2–3 句改进建议,并明确要求不要
输出新脚本**(刻意制造一次 chain-of-thought)→ 重新生成。

**来源二**:Coverage-Guided Multi-Agent Harness Generation for Java Library Fuzzing,
SBFT 2026(ICSE Workshop),arXiv 2603.08616。[A 级——**本会话取到 arXiv e-print 全文 .tex 逐字核**]
Java 库 fuzzing 的五 agent 流水线。反馈表示法逐字:

> "To seed the coverage analysis, we merge method-level coverage data with the static callgraph
> to produce an **annotated view showing coverage status for each reachable method, grouped by
> call depth from the target**."

给 refinement agent 的载荷逐字:

> "the refinement agent receives the current harness code, **the coverage analysis strategy
> (priority methods and improvement rationale)**, and annotated coverage data."

即:**动态覆盖率 ∪ 静态调用图 → 按到目标的调用深度分组 → 外加一个"策略对象"(优先方法 +
改进理由)**。不是未覆盖行列表,也不是裸覆盖率百分比。

另两条可直接借的机制,逐字:

> "**Convergence detection through code hashing** prevents oscillation between semantically
> equivalent harness variants."

> "requiring on average only **3.1 iterations** until the first harness is synthesized";
> "all evaluated harnesses compiling successfully after **at most 6 iterations**."

**落到本框架**:将来做 coverage-driven repair 时的**反馈表示法**,以及"何时停"的判据。

**(a) 表示法**:我们已经有调用图(`sfg_builder`,Structural Flow Graph)与 target-scope 覆盖率。
把两者**合并成一张按调用深度分组的注释视图**,比今天把未覆盖列表直接回灌更接近两份文献的做法。
**(b) 停止判据**:code hashing 防震荡 —— 直接对应我们 retry 循环里"模型反复交同一个 harness 的
等价变体"这一类浪费。
**(c) 迭代预算**:3.1 次到首个 harness、≤6 次全部编译成功,可作为我们 `max_attempts` 的参照。

**代价**:小,但**现在不做**——它是 §3 之后那一步的输入,不是本次改动的一部分。记在这里是为了
别到时候临时发明一个更差的表示法。

**边界**:两份都**没有**给出字面序列化格式(字段名 / JSON / 表格形状),SBFT 那份 agent 明确
检索后回报 NOT FOUND IN TEXT。所以借的是**结构**(分组维度 + 策略对象),不是可照抄的 schema。

---

### M9 · 生成方差是主方差——我们的单点测量因此不完全成立(FuzzAgent)

**来源**:FuzzAgent: Multi-Agent System for Evolutionary Library Fuzzing,arXiv 2605.14431
(Yunlong Lyu 等)。[A 级——**本会话取到 arXiv e-print 全文 .tex 逐字核**]

**机制**:把 LLM 库 fuzzing 从"开环代码生成"变成"闭环推理 agent":Harness Generator 产
harness,跑 campaign,Coverage Analyzer 分析分层覆盖率找瓶颈,再产新 harness。覆盖率反馈的
消融是明确正向的——逐字:

> "removing the Coverage Analyzer reduces branch coverage to 146508, descrease 18.5% compared
> with the standard setting."(标准设置 179619 branches)

**但对我们最重要的不是这个,是它的方差分析**——逐字:

> "Library fuzzing is inherently stochastic, and **LLM-based harness generation introduces a
> second, often dominant source of randomness** on top of the fuzzer itself."

> "Across available libraries, **the CV caused by harness generation is consistently larger than
> the CV caused by repeated fuzzing with a fixed generated harness**. This result indicates that
> LLM harness generation is the dominant source of statistical variation in LLM-based library
> fuzzing. Consequently, **evaluating such systems with only one generation trial can produce
> unstable and potentially misleading results**."

**落到本框架 —— 这条直接约束我们自己的结论。**

`docs/COVERAGE_EQUIVALENCE.md` 已经如实记录了"`-runs=20000` 下覆盖率饱和,三个种子给出完全
相同的数字"。当时的读法是:种子饱和 ⇒ 重复得不出新信息,但**跨 target / 跨预算的推广没有支撑**。

FuzzAgent 把这件事说得更狠:**我们采样错了那个方差源。** 种子铺开测的是 **fuzzer 的**方差;
而"LLM 生成 harness"引入的方差**更大**。我们的 `contracted` 臂是**一次生成**的**一个** artifact
(`contracted_published.c`,1845 B,sha256 pin 在 manifest 里)。

**所以 §1.1 的 0.946429 是"某一次生成的 harness"的读数,不能读成"ProtocolIR 方法的读数"。**
这不削弱缺口的存在——§1.1 的根因是从**源码证明**的(`payload_len = remaining` 让循环只跑一次),
与方差无关。但它**约束了修复后的验收方式**:

> **M1–M4 做完之后,重跑**一次**生成、测一次**覆盖率,不足以宣称改善。
> 需要**多次独立生成**,并把"生成间方差"与"运行间方差"分开报。

**代价**:这是**评测成本**的增加,不是代码改动。每次生成要真机跑 DeepSeek(参考:我们上一轮
19 次生成 / 90,832 tokens / 66.7s),需要 N 次独立生成以获得生成方差。

**怎么验证**:固定 target 与预算,做 N 次独立生成,每次各自 `-runs=20000` 测覆盖率,报
**生成间**离散度;并与"固定一个 harness 重复跑若干 seed"的**运行间**离散度对比。若生成间显著
更大(文献预期如此),则今后所有结论都必须按生成间方差来报。

**边界**:
- 这是**别人家的**方差分析(20 个 C 库、上游是 OSS-Fuzz 生态),**我们的 target 更小、更
  确定**,生成间方差未必同样主导。**所以我们应当去测,而不是直接套用结论。** 但**测之前不能
  假设它不成立**——那正好是被文献点名的那个错误。
- FuzzAgent 的量化数字(179619 / 146508 branches、$63.44/20 库、12.6M completion tokens)与
  我们的规模不可比,只作存在性证据。
- 该论文**自述不开源**("the dual-use potential of FuzzAgent precludes an open-source
  release"),所以只能读方法,不能跑对照。
- 该文**没有** Limitations / Threats to Validity 章节,agent 已核实并如实回报;上面那两段出自
  Discussion 与 Ethical Considerations。

---

### M10 · 中间产物分层校验 + 回滚,而不是修最终产物

> ⚠️ **本节来源的归属待确认,先读这段再读内容。**
>
> 本篇论文(SynapseFlow,arXiv 2607.07007,CCS 2026)与本仓库的 `sfg_builder` 在**标识符层面
> 逐一对上**,不可能是命名巧合:
>
> | SynapseFlow 论文 | 本仓库 |
> |---|---|
> | Structural Flow Graph (SFG) | `sfg_builder/`, `SFGNode`/`SFGEdge` |
> | 特殊 `"(null)"` 节点表示无输入/输出结构 | `sfg_builder/graph.py:15` `NULL_NODE = "(null)"` |
> | Input Stream Function / Process Function / Helper Function | `sfg_builder/roles.py` `LABEL_ORDER = ("ISF", "PRF", "HPF")` |
> | Function Triplet (FT) = (I, P, H) | `harness_generation/triplet.py` `FunctionTriplet` |
> | "three prompt variants … majority vote" | `sfg_builder/voting.py`"Majority voting for independent … prompt variants" |
>
> 本仓库的历史被 filter-branch 重写后压缩到 `a00c192`(2026-09-17,"Bring the working tree into
> git: protocol mining, SFG builder, pipeline"),**查不出这套设计的引入时间**,所以**无法从仓库
> 内部判定谁先谁后**。
>
> **两种可能,后果相反**:
> - 若 `sfg_builder` 与 SynapseFlow **同源**(同一课题组 / 同一作者),则 SynapseFlow **不是外部
>   相关工作**,本节应降级为"我们自己的设计在别处的书面表述",**不能当作独立佐证引用**。
> - 若 `sfg_builder` 是**独立实现**且晚于 2026-07,那么这是一个必须在文档里显式说明的
>   **相似性问题**,而不是可借用来源。
>
> **本文其余部分不受影响**(M1–M9 与 SPAR 均不依赖 `sfg_builder` 的归属)。**请裁定后再决定
> 本节去留。**

**若确认为外部来源**,可借的机制有两条(A 级,USENIX 式开放获取全文逐字核):

**(a) 分层校验 + 回滚到最后一个好的阶段,而不是修最终产物。**

> "**Validation of Intermediate Outputs.** Each stage's output undergoes lightweight
> syntactic validation before proceeding. We check for undefined functions or macros (e.g.,
> calls to non-existent APIs), references to external libraries not in the project, and
> duplicate definitions. The final harness from Stage 4 must additionally pass compilation
> and a 30-second test (executing with empty input to ensure no immediate crash)."

> "if the final harness (Stage 4 output) fails compilation or a basic runtime test, instead
> of discarding all previous work, we **roll back to the output of Stage 3 and regenerate
> Stage 4**. If repeated failures occur, we **roll back further** (to Stage 2, then Stage 1)."

**并且明确否掉了 LLM 自修复**——逐字:

> "Our experiments show that **LLM-based repair is often non-deterministic and can introduce
> new, unrelated errors** while attempting to fix the original one."

这一条**与本仓库行为一致**(pipeline 已有回滚,plan 的"实施结果"一节记录了 attempt_001
`HarnessPlan duplicates FT functions: mp_destroy` 被回滚、整轮 `run_result.success` 仍为 True)。
**所以它对我们不是新机制,而是一条外部依据**:说明"回滚而非修复"是有人独立做过并写下来的
选择,而不是我们的将就。

**(b) 三次投票消歧。** 逐字:

> "We therefore employ a **three-prompt voting scheme**: we craft three prompt variants
> (direct extraction, yes/no question, multiple-choice) for the same query and take the
> majority vote of the LLM's responses."

**这一条我们若已有(`sfg_builder/voting.py`),则同样属"已有";若只覆盖了 stream 分类一处,
则可推广到 miner 的字段/角色识别。** 归属未定,不写成待办。

**该文的负面结果(即便不作为来源,也值得知道)**:

> "Across all 25 projects, SynapseFlow extracts 11,326 FTs, of which **1,098 are false
> positives**, giving a precision of **90.3%**."

即 **FT 抽取本身有约 10% 的假阳性**。我们的 `triplet_extractor` 若与之同源,这个数字直接
适用;若不是,也提供一个量级参照。

**边界(无论归属如何都成立)**:该文在 Limitations 里**明确把协议实现排除在适用范围外**,
逐字:

> "Targets that require strict, multi-stage stateful interaction (**e.g., protocol
> implementations**) or complex input validation … **exceed the capabilities of libFuzzer's
> stateless, input-space exploration model**. Consequently, SynapseFlow is **not designed for
> such targets** and achieves low coverage on them like all other libFuzzer-based tools."

**即:它自认做不了我们正在做的事。** 所以即便它可用,借的也只能是 (a)(b) 两条**工程机制**,
**不能**借它对协议/有状态 target 的任何结论。

---

### M11 · 让两个产物互为 oracle,而不是让闸门单向检查(SPAR)

**来源**:Generating Precise Format Specification for Network Protocols Through Adversarial
LLM Interactions,USENIX Security 2026, pp. 4069–4088(南京大学,Ye / Shui / Wu / Zhou / Xu / Shi)。
[A 级——**开放获取 PDF 全文逐字核**,21 页,页码经 PDF 页脚确认]

**这是全部素材里,唯一同时具备 (i) typed relation、(ii) 模型↔产物一致性检查 的 A 级先例。**

**机制**:LLM 从 RFC 同时产**两份**产物——声明式格式规范 + 参考 parser;两者**互为 oracle**
互相精化,直到不动点。

> "we generate both packet formats and reference packet parsers that **iteratively refine one
> another to reduce hallucinations**: the packet formats allow us to create a variety of
> network packets for parser testing, while **runtime checks in the parsers help identify
> format errors**."

> "In adversarial LLM interactions, we respectively use the format and the parser **as
> oracles** to generate **positive and negative** protocol packets."

> "When a **positive packet fails a parser** or a **negative packet passes the test**, we
> report an issue in the parser implementations."

> "This adversarial refinement process continues until reaching a **fixed point**, where the
> format specification and the reference parser are **mutually consistent** and compatible."

**落到本框架 —— 这条正对 §1.3 的病根。**

§1.3 的结论是"**唯一没被检查的那条,恰好是唯一没被满足的那条**":契约检查了 frame、context、
checksum、opcode 集合,**没有检查声明与产物是否一致**。SPAR 的全部贡献就是**补上这个检查**,
而且它给出的形状比"再加一条静态条款"更强:

| | 我们今天的闸门 | SPAR 的做法 |
|---|---|---|
| 检查方向 | 声明 → 产物(单向) | 声明 ↔ 产物(**互为 oracle**) |
| 检查者 | 静态审计 | **运行**产物,拿**反向**证据(negative packet 通过 = 规范有问题) |
| 终止条件 | 通过 / 不通过 | **不动点**(再精化也改不动) |

**注意一个重要的负面事实**:SPAR **不是**用 LLM 生成报文的,采样交给求解器——逐字:

> "SPAR directly applies the constraint φ to an **SMT solver**, e.g., Z3, which will generate
> valid values for each field."

**所以 SPAR 与 SemFuzz 又落在同一边:长度是解出来的,不是 fuzz 输入。** 与 M1 那节的结论一致。

**代价**:高。要跑产物、要构造正/负样本、要一个"互为 oracle"的循环。**不是本次改动的一部分**,
记在这里是因为 §1.3 的缺口最终需要这个形状才能闭合——**加条款只能让闸门更严,不能让声明与
产物互相对质**。

**怎么验证(将来真做时)**:对 `contracted_published.c` 构造 positive/negative 包,断言
positive 包失败或 negative 包通过 —— 若今天就能测出,说明这个 oracle 早该有。

**边界**:
- SPAR 的规范来自 **RFC 文档**;我们的来自**源码反推**。RFC 是权威且完备的,源码反推不保证
  完备——**同一个 oracle 形状搬到我们这里,强度会打折**,因为"声明"这一侧本身就可能是错的。
  这是 §1.2 证据 A(`limitations[0]`)已经暗示过的:我们的 IR 会自己承认不确定。
- SPAR 自述其精化是**有代价、不保证收敛**的,逐字:"this approach does not, in theory,
  guarantee thorough coverage; it is an intentional trade-off to allow computational
  feasibility."**不要把它写成万灵药。**
- SPAR 同样**不建模协议状态**(逐字见 M1 那节末),所以它不解决我们的多帧问题。

---

### M6 · 先问 LLM"这个分支是否 input-dependent"(Bulbasaur)

**来源**:Branch-Guided Online Mutator Generation for Greybox Fuzzing,USENIX Security 2026,
pp. 4089–。[A 级——本会话直接解 PDF 读到正文]

**机制**:维护 branch database;先找 **frontier branch**(出边未全覆盖),再从中挑**持续未覆盖
超过阈值(经验值 6 小时)的 hard branch**,只对这些花 LLM 预算;生成物是 **operand-aware
mutator template**;LLM 先判断该分支**是否 input-dependent**,不是就返回
`UNABLE_TO_BREAK_THROUGH` 直接跳过。数字:line +23.18%、branch +24.46%,15 个 CVE。

**落到本框架**:**(a)** 先问 LLM"这个分支是否 input-dependent",不是就别修——对应 harness 里
那些不可达 / 环境相关分支;**(b)** 重生成时把上一版 artifact 一起给它。

**"未覆盖超 N 时间才算 hard"那个触发条件对我们离线评 harness 不适用**——我们不是在跑长期
fuzzing campaign。

**代价**:小(仅 prompt)。**边界**:同 M4,是生成侧而非闸门。

---

### M7 · 把 states / messages / transitions 统一成 nonterminal(FANDANGO)

**来源**:arXiv 2509.20308(Liggesmeyer / Zamudio Amaya / Zeller)。[A 级——4/4 逐句在 abstract]

**机制**(逐字):**interaction grammar** = 上下文无关文法的扩展,**每个 message element 被指派
给负责产生它的通信方**;**"embed classical state models by unifying states, messages, and
transitions all into nonterminals"**;文法元素上叠加 constraints 表达语义特征(*"binary message
formats, checksums, encodings"*);同一文法既生成也解析。覆盖 SMTP / DNS / FTP。

**落到本框架**:**不采纳为下一步**(见 §4)。记在这里是因为它是**我们问题的正确抽象层次**——
"生成一条报文"天然就是"走状态机的某条边",而我们现在是 `FrameModel` + `SequenceModel` 两个
互不相干的块。属重构级。

---

### M8 · 评测口径(SoK + 一处贡献机会)

**来源**:SoK: Prudent Evaluation Practices for Fuzzing,IEEE S&P 2024,
DOI 10.1109/SP54263.2024.00137。[A 级——已回原文核]

**硬性建议**:≥10 次重复(或 a-priori power analysis);统计检验用 permutation / bootstrap
而非 Mann-Whitney U;报 effect size(Vargha–Delaney A12)与不确定区间;**初始语料自身的覆盖率
要单独报**;每个被比较的 fuzzer 必须用同一套 coverage 度量。流行病学:55% 的论文某实验重复
<10 次,**63% 完全不做统计检验**。

**已核实的文献空白**:SoK **完全没有讨论**编译器 flag、优化级、被比较 fuzzer 之间的**构建配置
对等性**,也未讨论 **differing translation units** 与 **inlining 对覆盖率的影响**。但它**覆盖了**
同类问题的一个特例——sanitizer 插桩偏差(FishFuzz:报告优势从 8.44% 掉到 1.69%)。

**落到本框架**:我们这一路踩的恰好是那片空白,而且有实证(`docs/COVERAGE_EQUIVALENCE.md` 的
"Evaluation infrastructure fixes" 与 Arms 两节):`single_tu` vs `two_tu` 的 recipe 差异、C++
name mangling 让跨臂函数名比较失效、`shutil.copyfile` 丢执行位、`llvm-cov` 不在 PATH。
**沿用 SoK 的 checklist 结构补一节 build-configuration comparability,是一个站得住的贡献点**——
不是猜的,是我们自己被逼着解决的四个问题。

**一处独立佐证(A 级)**:SBFT 2026(arXiv 2603.08616)为我们 gate 的 scope 选择给出了**同一个
理由**,逐字:

> "**we introduce method-targeted coverage that tracks coverage only during target method
> execution to isolate target behavior**"
> "Standard coverage instrumentation measures all executed code, **creating a misaligned
> incentive for agents to invoke unrelated utility methods**."

我们的 gate 只读过滤到 `target.c` 的那层(scope `target_code`),**与它是同一个设计决定**。
这条把我们从"自己觉得应该这么量"升级为"有一个独立的 2026 年工作、为同一个理由、做了同一个
选择"。值得写进 `docs/COVERAGE_EQUIVALENCE.md` 的论证里。

**边界**:§1.1 的 0.946429 是**读数,不是成因**。本文全部改动都不碰 evaluation 阈值。

---

## 3. 总验收:让新条款拒掉那个已知退化的产物

M1 + M3 + M4 合起来只服务一件事:**在 plan 闸门里加一条能说出"你把它退化了"的条款。**

具体形状:当契约声明 `multi_frame` 且存在 `size_of` relation 时,plan 的
`input_model.payload_length_strategy` 必须声明为**从 fuzz 输入抽取**(而非饱和剩余),
且必须给出抽取表达式;Stage 4 的 C 审计要能在生成的 harness 里**找到**该表达式。

**验收标准(这是本次改动唯一有意义的判据)**:

> 新增的闸门/审计必须**拒绝** `tests/fixtures/coverage_arms/contracted_published.c`。

那份 1845 字节的发布物**就在仓库里**、被 manifest 以 sha256 pin 住、是我们**已知会丢失 4 个
branch direction** 的那个 artifact。**如果新条款不能拒它,新条款就是没用的。** 这是一个
现成的、非构造的、有 ground truth 的回归样本——不需要为了测而造一个。

两个样本已在 manifest 里 pin 死,本次核对 sha256 全部相符:

| arm | 文件 | size | sha256 | recipe |
|---|---|---|---|---|
| `contracted` | `tests/fixtures/coverage_arms/contracted_published.c` | 1845 | `49a5a01c87cf341a0f6a594873d867cb2e9a3fac9fd060f49943f72b2c44a218` | `two_tu` |
| `reference` | `benchmarks/mini_parser/harnesses/structured.c` | 1160 | `6039764f6fd3b5c4f2ec1a0c4a47e2ee763372fb8bbc635d0df79b8c2e51ea08` | `single_tu` |

**两者在语法上确实可分**:contracted 的长度表达式不含任何对 `data` / `size` 以外的抽取
(`payload_len = remaining`,而 `remaining = size - (offset + MP_HEADER_SIZE)`);
reference 的长度表达式是 `Data[pos++] % (MP_MAX_PAYLOAD + 1u)`。
**"长度是否由输入字节经取模/截断导出"是一个纯语法判别式**,不需要数据流分析即可区分这两者。
(这不代表新审计是 sound 的——见 §4 边界。)

配套的三条守卫(防止放松而非收紧):

| 守卫 | 断言 |
|---|---|
| 无 IR 时新条款不生效 | 同一份 harness 不给 `protocol_ir.json` → 行为逐字不变(FT-only 红线) |
| 手写 reference 不被误伤 | `structured.c` 的 `% (MP_MAX_PAYLOAD + 1u)` 形态必须**通过**新审计 |
| 现有 fixture 零修改 | 全量 636 passed / 368 subtests 保持,既有测试一行不改 |

**一条必须写进 docstring 的边界**:这是**语法近似,不是数据流分析**。"从 `data` 抽一个数、
再用常量整帧覆盖"依旧能通过;长度从**局部变量**经函数返回值传递也识别不了。不要把它写成
sound,也不要把"拒掉了 contracted_published.c"当成"以后不会再退化"。

---

## 4. 不采纳

| 项 | 理由 |
|---|---|
| **nested length 自底向上重算** | 实测证伪:`target.c:114/115/120/121` 两臂**都覆盖**,含 BUG 5 路径 |
| **opcode 分布 / dispatch 边界值** | 实测证伪:`target.c:126` 的 `default:` 我们**赢**(10599/7940 vs 0/63531) |
| **给 IR 加 variant / path_condition 维度** | 本 target `MP_HEADER_SIZE` 是常量 8,无可选字段,无收益 |
| **补 payload 边界值表** | 边界值不是问题,**长度从哪来**才是(§1.1) |
| **FANDANGO 式文法统一(M7)** | 方向对,但属重构级,不是下一步 |
| **NSFuzz 的运行时 state-id 哈希** | 我们没有运行时状态反馈,离线评 harness 用不上 |
| **AFLNet 的状态选择算法** | 单进程 target 无响应码,没有等价的在线信号 |
| **Bulbasaur 的"未覆盖超 N 小时算 hard"** | 不跑长期 campaign |
| **Gentoo 的负结论**("coverage guidance 对 agent 写的 generator 无显著收益") | **前提不成立**:它的前提是 generator 已把结构编码进去;我们证明了我们**没有**(§1.1)。前提不成立,结论不能外推 |
| **改 evaluation 阈值** | §1.1 的 0.946429 是读数不是成因,改阈值只会把问题抹掉 |
| **SynapseFlow 的 SFG / Function Triplet 作为外部先例** | **归属未定**(见 M10 的 ⚠️ 块):它与本仓库 `sfg_builder` 标识符级一致,在裁定之前**不得当作独立相关工作引用** |
| **SemFuzz 的 `R`/`SR`/`M`/`A` 四层模型** | 单报文模型,无序列;且其长度由**引擎推断**——正是 §1.1 要避免的方向(详见 M1 那节) |
| **APFuzz 的字段模型** | 只有 `(name, bit_start, bit_length)`,**无字段间关系**,比我们现有 IR 还弱;无借鉴价值 |
| **PRE2Fuzz(ICSE 2026 Demo)** | 全文取不到:Demo track ~200 词摘要,**无 arXiv、无 DOI、无仓库**。唯一可得事实是产物为 Peach Pit——不构成方法 |
| **FieldWeaver(Computer Networks 2026)** | 全文取不到(全路由 403,无预印本);仅有的中文二手机器翻译摘要,**Q2/Q4/Q6 全部 NOT FOUND**。**不得据它做任何机制论断** |
| **EMSE 2026 MDIplier\***(DOI 10.1007/s10664-026-10814-6)** | 全文付费墙;**纯格式推断(inference-only)**,摘要零生成/零 fuzzing/零 LLM 成分,**不是同类系统** |

**已剔除、勿再引入**:HGFuzzer(arXiv 2505.03425)的 4 条机制中 3 条不在文中;"Pensieve:
Code Coverage Based Instruction Set Fuzzing (USENIX Sec 2018)"经两次检索确认**不存在**;
"Nautilus 自动更新 length 字段"无证据;FormatFuzzer(TOSEM 2024)检索结果中完全没有 checksum
处理。**LLM4Fuzz 的两处被纠正细节不得引用**(见 M4)。

**第 4 例机制层编造(本会话新增)**:二手引用称 SemFuzz *"formalize field mutation as
`R=(p,m,c)`"*。**全文核对:错在实质,不只是细节。** `R=(p,m,c)` 确有逐字原文,但它是
**从 RFC 解析出的规范条目**(p = 协议名、m = 报文类型、c = 内容),
**与"字段"无关**;字段要到下一层 `SR=(p,m,f,C,P)` 才出现。逐字:

> "we formalize the RFC specification as a set of requirements: D = {R_1, …, R_n} where each
> R_i = (p,m,c) represents the **protocol name, message type, and specific content**."

同一份报告里还有**两处该纠正的**:(i) 它的 87%→36% 削蚀是**测试用例生成准确率**,不是检出率
或覆盖率,且必须与"语义规则抽取"恰好也是 87% 的另一个数字**分开引用**;(ii) `add` 的动作
签名是 `add(fields, position, value)`,比 `remove`/`update` 多一个参数,
"`add/remove/update(fields,…)`"这个笼统写法不准确。**这三点都属"论文与头条数字为真、机制细节
失真"的老毛病**——与 §6 末尾的方法学警告同源。

---

## 5. 实施顺序

| 步 | 内容 | 依赖 | 可独立验证 |
|---|---|---|---|
| 1 | **M1** `FieldRelation` + `FrameField.relation`,`parse` 方向从现有事实推导 | — | round-trip 零修改 + 单测 |
| 2 | **M2** `StateVariable`、`StatefulOperation.writes/reads`,顺序约束可推导 | — | plan 顺序颠倒被拒 |
| 3 | **§3 判定条款** + 三条守卫 | 1 | **拒掉 `contracted_published.c`** |
| 4 | **M4** Stage 4 prompt 改成产"序列采样函数" | 3 | 真机重跑,grep 生成物的长度表达式 |
| 5 | 真机重跑 **N 次独立生成**(见 M9)+ coverage 复测 | 4 | 生成**间**方差 vs 生成**内**方差 |

**进度（2026-09-20）**：第 1–3 步已落地。新 IR 的 size relation 带来源和证据，
状态读写与顺序进入 plan 闸门；Stage 4 还检查声明的字节采样表达式是否进入
payload 拷贝长度。已用仓库中的 `contracted_published.c` 验证拒绝、用手写
`structured.c` 验证采样识别。第 4 步只补了生成提示，尚未用真实模型重跑；
第 5 步的独立生成与覆盖率复测也未进行。因此目前只证明退化样本会被拒，
不声称覆盖率已改善。旧 IR 仍按原文加载，不自动补推断关系。

第 1、2 步互不依赖,可并行。**第 3 步是分水岭**:它之前所有改动都不可证伪,它之后才有
"改对了没有"的判据。**第 5 步之前不要宣称任何覆盖率改善。**

第 5 步的"N 次"不是保守起见,是 M9 的直接后果:**一次生成的一个 harness 不足以支撑关于方法的
结论**。今天 `contracted` 臂就是**一次生成的一个** artifact。修复后的复测如果仍然只跑一次生成,
那我们只是又得到一个读数,没有资格说方法变好了。

**两条已记录但不进序列的方法,理由各不相同:**

- **M11(互为 oracle)不进序列,但它是 §1.3 的终局形态。** 第 3 步的条款只能让闸门**更严**,
  不能让声明与产物**互相对质**。§1.3 的结论("唯一没被检查的那条,恰好是唯一没被满足的那条")
  在只加静态条款的情况下**仍然成立**——只是多检查了一条。要真正闭合,需要 M11 那个形状,
  而它的代价是"要跑产物 + 要造正负样本",不是本轮的活。**写在这里是为了别把第 3 步误当成
  终局。**
- **M10 的归属澄清之前不进序列。** 它到底是我们自己的设计在别处的书面表述,还是外部先例,
  决定了它是"依据"还是"相似性问题",**两种情况下都不是待办事项**。

---

## 6. 核实等级

沿用 `docs/PROTOCOL_IR_RELATED_WORK.md` §0.1 的三级标记:**任何要写进 method 的机制都必须先
降到 A 级。**

| 条目 | 等级 | 说明 |
|---|---|---|
| Peach Pit `Relation` / `Fixup` | A | `type ∈ {Size, Count, Offset}` + `of`;`expressionGet`/`expressionSet` 互为逆;checksum 走 `Fixup` |
| Bulbasaur(USENIX Sec 2026) | A | PDF 已解出正文;+23.18% line / +24.46% branch / 15 CVE |
| FANDANGO(2509.20308) | A | abstract 4/4 逐句命中 |
| SoK(IEEE S&P 2024) | A | checklist 与 FishFuzz 案例属实;flag/TU 空白确认 |
| LLM4Fuzz(2508.01750) | A | 核心属实;**两处细节已纠正,勿引用** |
| §1 全部证据 | A | 本仓库文件,逐字引用,关键项有测试 pin |
| **SPAR**(USENIX Sec 2026, pp. 4069–4088) | **A** | 开放获取 PDF 全文;页码经页脚确认;M1 反例 + M11 的唯一先例 |
| **APFuzz**(2602.21892) | **A** | HTML + PDF 全文;`(name, bit_start, bit_length)` 无关系,自述为 future work |
| **SemFuzz**(2603.05989) | **A** | HTML + PDF 全文;**三处二手引用失真已纠正**(见 §4 末) |
| **SynapseFlow**(2607.07007, CCS 2026) | **A(出处待裁定)** | 全文已核,**但与本仓库 `sfg_builder` 标识符级一致**——见 M10 的 ⚠️ 块 |
| FuzzAgent(2605.14431) | A | arXiv e-print 全文 .tex 逐字核 |
| SBFT 2026(2603.08616) | A | arXiv e-print 全文 .tex 逐字核 |
| SeedMind(2411.18143) | B | agent 报告,未独立复核 |
| FieldWeaver(Computer Networks 2026) | C | **仅中文二手机器翻译摘要**;Q2/Q4/Q6 全部 NOT FOUND |
| PRE2Fuzz(ICSE 2026 Demo) | C | 仅 ~200 词摘要;无 arXiv / DOI / 仓库 |
| EMSE 2026 MDIplier\*(s10664-026-10814-6) | C | 付费墙,仅摘要;且为 inference-only,非同类系统 |
| NSFuzz / AFLNet / StateAFL / SGFuzz / ChatAFL / NetLifter / StateLifter / ParDiff / ProtocolGPT | C | 引用前须自取全文 |

**已核实"不属于本域"、不得引用**:

| 条目 | 核实结论 |
|---|---|
| **"How Many Tries"(2604.10508)** | 曾在 §5 的 C 级线索里被列为 fuzzing / 反馈类。**已核实为误**:全文检索 "coverage" **零命中**,内容是 HumanEval / MBPP 上的 Python 自修复。**与 fuzzing、harness 生成、覆盖率反馈均无关,不得引用。** |
| **SynapseFlow 的协议结论** | 该文自述**把协议实现排除在适用范围外**(逐字见 M10 末)。**即便 M10 归属澄清后可用,也只能借其工程机制,不得借其对协议/有状态 target 的任何论断。** |
| **EMSE 2026 / FieldWeaver** | 均为**格式推断**,摘要层面零生成、零 fuzzing 成分,**不能作为"IR + 生成器"的同类系统引用**。 |

**检索方法学警告(重复强调)**:本文档的文献素材来自多 agent 检索,已实测到同一种失效反复出现
——**论文本体与头条数字几乎每次都是真的,错的是"机制细节"那一层**,而机制细节恰好是要照抄的
东西。三个实例(HGFuzzer 3/4 条编造、LLM4Fuzz 2 处、一条完全不存在的工作)记录在
`docs/PROTOCOL_IR_RELATED_WORK.md` §0.1。**任何 C 级条目在进入 method 之前必须自取全文。**
