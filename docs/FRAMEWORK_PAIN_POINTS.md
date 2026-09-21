# 框架痛点与优化:诊断、方法来源、落地映射

本文回答一个问题:**这套流水线现在最大的问题在哪,该动哪里,凭什么说动对了。**

它是一份**诊断**,不是一份改进记录——文中每一条都还没动手改。

四份文档的分工:

| 文档 | 问的问题 |
|---|---|
| `docs/PROTOCOL_FORMAT_MINING.md` | 怎么把 `protocol.json` 从手写变成自动抽取(六组工作 → 块 A/B/C) |
| `docs/PROTOCOL_IR_RELATED_WORK.md` | IR 缺的那一块,别人怎么做过了(文献综述) |
| `docs/PROTOCOL_IR_METHOD_TRANSFER.md` | 那些方法落到哪个 schema 字段 / 哪个函数 / 哪个闸门(M1–M11) |
| **本文** | **现有实现的痛在哪、按什么顺序动、与上面三份怎么对应** |

**术语碰撞提醒**:`PROTOCOL_FORMAT_MINING.md` 的 **A/B/C 块**指契约的三个来源分块
(帧格式 / 常量约束 / 惯用法);`PROTOCOL_IR_METHOD_TRANSFER.md` 的 **A/B/C** 指核实等级。
本文两种都用,一律写明"块 A/B/C"或"核实等级 A/B/C"。同一对字母在两份姊妹文档里指两件
不相干的事,本身就是第 2 节所述病症的一个小样本。

---

## 0. 一句话诊断

**框架的痛点不是"某个校验器不够强",而是没有**一个概念**有唯一权威。**

同一件事被多处各持一份副本。副本会漂移,而**漂移的方向决定后果**:

- 副本**更宽**(审计放行、别处不认)→ 失败被推到很晚,报错指向无关的地方;
- 副本**更严**(审计拒绝、别处接受)→ 合法产物被误杀,而失败原因被写成一句与真实原因
  无关的散文。

两类后果在这套实现里都出现过,都有第一手证据(下表)。

### 与 `PROTOCOL_FORMAT_MINING.md` §4 的关系

那份文档的 `§4.1 三个已确认的具体问题`、`§4.2 循环论证风险`、`§4.3 文献的共同限制`
记的是**方法层**的风险。本文记的是**实现层**的风险。两者不是同一批问题,但有交集:
§4.1 第 1 条(`source_analysis.py:493-496` 硬编码 `mp_init`/`mp_destroy`/`mp_checksum`)
就是"一个概念没有唯一权威"的最小个例——**哪些 helper 可用**这件事由一段硬编码名单决定,
而不是由推导决定。见 §6.1 第 6 行。

---

## 1. 证据坐标与核实等级

沿用 `PROTOCOL_IR_METHOD_TRANSFER.md` §6 的分级:**A = 亲手执行/逐字读码验证**,
**B = 代理报告的源码阅读(未执行)**,**C = 仅有摘录**。进本文的结论只允许 A 或 B。

| # | 结论 | 坐标 | 等级 |
|---|---|---|---|
| 1 | 日志策略集合已漂移(7 项 vs 2 项) | `validation.py:29` vs `stage4.py:30` | **A** |
| 2 | harness 语言三处权威不一致 | `prompts.py:164` / `fuzzer_build.py:23-30` / `stage4.py:843-848` | **A** |
| 3 | B 层用 C 驱动链接 C++ 对象 | `target_coverage.py:241` + 录制 `commands.json` | **A** |
| 4 | `parsed.json` 由 Stage 4 写,phase 只在 Stage 4 内 | `stage4.py:309/351/380/411` | **A** |
| 5 | 缺测量被 `all()` 归约成假 | `coverage_arms.py:1083` + `:1103` | **A** |
| 6 | `target_source.sha256`/`corpus.digests` 从不校验 | `coverage_arms.py:267` 只遍历 `manifest.arms` | **A** |
| 7 | `_failure_reason` 会取到已回滚 attempt 的原因 | `pipeline_result.py:209` | **A** |
| 8 | `prompts.py:164` 的 C++ 承诺与 `stage4.py` 的 C 解析相冲 | 同上 | **A** |
| 9 | opcode 范围以散文写、以正则读回 | `protocol_miner.py:1573` / `tests/test_protocol_ir_e2e.py:82` | **A** |
| 10 | IR 的 `requirements`/`notes`/`limitations` 都是 `tuple[str, ...]` | `protocol_ir.py:346-348` | **A** |
| 11 | `stage4.py:1134` 声称"两份允许集不会漂移"是假的 | `stage4.py:1132-1134` | **A** |
| 12 | "FT 不来自 call closure"同一句话写在两处、两处都没修 | `protocol_ir_helpers.py:9` / `pipeline_validation.py:245` | **A** |
| 13 | 同一个漂移在第三层还有一个副本(`IntermediateValidator`) | Fix B 收尾时发现,见 plan | **A** |
| 14 | static-helper 分歧与 `ctx->destroy` 不可见 | 审计 A | **B** |
| 15 | `evaluate_gate` 无生产调用者 | 审计 C | **B** |

**未能复核的**:曾用于演示 #4 的那次真机 run 落在 `/tmp/hg_recording/phase2`,**现已不在
磁盘上**。#4 现在改由**代码结构**支撑(见 §3.1),这比那次一次性 run 的证据更耐久,但它
证明的是"该类失败不可能被记录",不是"某次 run 里出现了 N 次"。

---

## 2. 类一:概念多重权威

### 2.1 副本清单

| 概念 | 副本数 | 载体 |
|---|---|---|
| 策略集合(禁用调用 / 白名单) | **8 组** | `validation.py:29`、`stage4.py:30`、`protocol_ir_helpers`、`declared_contract_helpers`、`protocol_contract_projection.helpers`、`IntermediateValidator.allowed_functions`、`normalize_cpp_harness`×2 |
| **harness 是什么语言** | **3 处** | prompt 说 C++、构建说 C++、审计按 C 解析 |
| `functions.json` 的读取 | **5 处** | 其中**一处没有 schema 校验**,而它的输出喂给 `contract_helpers()` 与 Stage 2 的 `invented`(等级 B) |
| AST 静态分析 | **3 套独立实现** | 其中 `signals.py` 自带另一套 taint 近似(等级 B) |
| "函数在 FT 之外" | **6 处** | — |
| "这是不是 target finding" | **5 处** | 当日一致 |
| `normalize_cpp_harness` | **2 个同名函数** | 实际生效的是 `core.py` 那份(等级 B) |

### 2.2 已经漂移的四处(全部实测)

**(a) 日志集合。** 实测:

```
harness_generation/validation.py:29  → fprintf, perror, printf, putchar, puts, vfprintf, vprintf   (7)
harness_generation/stage4.py:30      → printf, fprintf                                              (2)
```

同一个概念在两处相差 5 项。哪一处生效取决于**走的是哪条路径**,而两条路径的语义差异从
代码上看不出来。这正是 `PROTOCOL_FORMAT_MINING.md` §4.1 第 1 条的同构体:
**该由推导决定的事,由名单决定;名单有两份,就会分叉。**

**(b) harness 语言。** 三处权威,两个答案:

| 位置 | 说的是 |
|---|---|
| `prompts.py:164` | "Implement the supplied HarnessPlan as a **C++** libFuzzer harness. The final harness is a **C++ translation unit**" |
| `prompts.py:185` | "You may use straightforward C++ helpers such as **std::array, std::vector, std::min/std::max, lambdas**" |
| `fuzzer_build.py:23-30` | `-x c++ -std=c++17` |
| `stage4.py:843-848` | `import tree_sitter_c` → **C 语法树** |

后果不是抽象的:4 次 `LLM returned invalid C syntax` 里,`std::`×3、`constexpr`+匿名
namespace×1,**逐个 pin 在测试里**。审计拒绝的正是 prompt 明确邀请的写法。

**(c) 链接驱动。** 实测 `artifacts/coverage_arms/arms/pass_through/seed_1/.../commands.json`
的两条相邻命令:

```
compile harness : /usr/bin/clang++ -x c++ -std=c++17 -g -O1 … -c harness.c
link            : clang  …/harness.o -g -O1 -fsanitize=fuzzer … -o coverage_fuzzer
```

对象来自 `clang++`,链接用的是裸 `clang`。源码侧的成因在
`target_coverage.py:241`:`compiler=target.compiler`——**`harness_compiler` 根本不参与
链接**。这条与 (b) 合起来是一条完整的伤害链,见 §3.4。

**(d) 同一概念的第三层副本。** Fix B 收尾时才撞见:
`pipeline_validation.py:240` 的 `validate_stage4` 会**再用**
`IntermediateValidator().validate_triplet(...)` 复检发布于 `harnesses/` 的 C,而它没有
`extra_allowed`,于是把合约 helper 当越界调用:

```
stage4/attempt_002/validation/intermediate.json -> failed
  ['unexpected target function calls: mp_checksum, mp_init']
```

即"哪些 helper 可调用"这个概念,在**已经统一了两处之后**,外面还有第三处。
`stage4.py:1132-1134` 的 docstring 写着:

> The plan validator and the C audit both widen their allowance by exactly
> this set, so **the two cannot drift apart**.

这句话**只对它所列举的那两处成立**,对第三处不成立。**一份声称"不会漂移"的注释,其
本身就是一个未经检查的副本。**

### 2.3 为什么这是根因而不是症状

单独看每一处副本,都可以论证"它就该这么写"。问题出在**它们之间没有相等性约束**。

这解释了一个反直觉的现象:**继续加校验条款的边际收益在下降**。
`PROTOCOL_IR_METHOD_TRANSFER.md` §1.3 已经证明:契约的每一条条款
(`bounded_multi_frame`、`payload_fuzzer_controlled`、`repair_length`、`repair_checksum`)
**都能被一个覆盖率退化的产物满足**。原因不是条款写得不好,而是**条款的读法不唯一**:
投影从"角色存在"推出布尔值,审计从"调用存在"推出布尔值——两者都"满足条款",两者都
不保证语义。

---

## 3. 类二:失败信号被污染

**这一类比类一更贵**,因为类一让改动变慢,类二让**结论不可信**。

### 3.1 失败记录的宇宙边界(实测)

`parsed.json` 由 Stage 4 写(`stage4.py:309/351/380/411`),它的 `phase` 取值只有
Stage 4 内部的阶段 —— `"harness_code"` 等。构建发生在 **Stage 4 之后**,结果落在
**另一个文件、另一个层级**:`layout.write_validation("compiler", ...)`
(`compiler_validation.py:341`),即 pipeline 级的 `validation/compiler.json`。

两者**从不 join**。后果:

`tests/fixtures/stage4_recorded_attempts/manifest.json` 的 `note` 逐字写着:

> `recorded_error` is the verbatim `parsed.json` error of that attempt.

而 `parsed.json` **在构建阶段可能运行之前就已经写完**。所以那份 17 次 attempt 的分桶表
——Fix B 全部决策的依据 —— **在结构上不可能包含任何 build-time 失败**。

这不是"读错了字段",是**问错了文件**。走查本仓库 tracked 的
`artifacts/deepseek_real/generation/ft_parser_from_memory_a5265df23ba0/stage4/attempt_*`
也印证同一形态:`parsed` 全为 `passed`,而该层级**不存在** `compiler.json`。

**与外部工作的对应**:`PROTOCOL_FORMAT_MINING.md` §4.2 主张"把 miner 作为被评估对象"
——这条主张有一个前置条件,**被评估对象的失败样本必须先无偏**。当前的分桶表不满足它。

### 3.2 缺测量 = 低于参考(实测)

```python
# coverage_arms.py:1083
if reference_percent is None or candidate_percent is None:
    entry.update(ratio=None, passes_strict=None, passes_tolerance=None)
# coverage_arms.py:1103
"passes_strict": all(item["passes_strict"] for item in per_seed) and bool(per_seed),
```

`None` 是假值,所以**"没测到"与"测到了但更低"在报告里是同一个词**:不达标。
判据本身没有第三态。

`PROTOCOL_FORMAT_MINING.md` §5.3.2 把闸门的三项写得很清楚,但**没有写"测不出来时算
什么"**。那一段的三条限定(budget-relative、必须关 sanitizer、seed 不是独立样本)都在
处理测量的**解释**,没有处理测量的**缺失**。

### 3.3 名字与行为不符的两处(等级 B)

- `_nonblocking_result` 名字写 nonblocking,却返回 `"unavailable"`,于是**被判 stage
  失败**;且说明文字进的是 `warnings` 而不是 `errors`,失败原因退化成
  `"Stage validation completed with status unavailable"` —— **连工具链信息都不带**。
- `_failure_reason`(`pipeline_result.py:209`)反向扫描 history 取最后一条
  `pipeline_failed`/`stage_failed` 的 `reason`。一个 run 只要从回滚里恢复过,最后一条
  `stage_failed` 必然属于**那个已被回滚的 attempt**。已在 plan 里记录过一个真实例子:
  整轮的失败原因被写成 `Stage4Error: HarnessPlan duplicates FT functions: mp_destroy`
  (attempt_001,已回滚),而不是 milestone 文案。

### 3.4 复合链:合法产物被报告成"覆盖率退化"(全部实测)

这是本文最重的一条,四个环节每一环都已单独验证:

1. `prompts.py:185` 邀请模型使用 `std::array, std::vector, std::min/std::max`。
2. `fuzzer_build.py:23-30` 与录制命令确认 harness 以 **C++** 编译。
3. `target_coverage.py:241` 用 **C 驱动** `clang` 链接该 C++ 对象。
4. 需要 libstdc++ 符号 → 链接失败 → B 层 totals 为空 →
   `passes_strict=None`(§3.2)→ **报告为 `below_reference`**。

**一个完全按提示词写的合法 harness,会被报告成"覆盖率低于参考"**——与"候选真的退化"
同词。当前没炸,只是因为所有 arm 恰好都没用 stdlib。这把 `PROTOCOL_FORMAT_MINING.md`
§5.3.2 那张表的核心结论 3("剩下的是 harness quality gap,不是 pipeline 断链")
**悬在一个未被检查的前提上**:那个 `0.946` 之所以可信,靠的是报告另给了 `cov`/`ft`
遥测与 `commands.json` 作旁证;换成一份没有旁证的单点报告,`below_reference` 就分不清
两件事。

---

## 4. 类三:可复现性

1. **输入哈希不校验(实测)。** `verify_manifest`(`coverage_arms.py:267`)只遍历
   `manifest.arms`。`target_source.sha256` 与 `corpus.digests` **从不被读**。改了
   `target.c` 或语料后重跑,`--check` 不报任何问题。
   → `PROTOCOL_FORMAT_MINING.md` §5.3.2 声称"`--check` 能在没有编译器、没有 LLM 的
   情况下重算每一个判定"。这句话**在"判定"层成立,在"输入"层不成立**。
2. **两层语料策略不同。** A 层按**内容哈希**复制,B 层按**文件名**,且 B 层额外注入 3 个
   默认种子(`empty`/`zero`/`small`)。"两层同一 corpus"不成立(等级 B)。
3. **确定性检查只覆盖 A 层。** gate 所读的 B 层**没有任何同 seed 重复**(等级 B)。
4. **证据里含绝对路径(实测)。** 录制的 `commands.json` 里是
   `/home/luchitong/work/harness_generation/.claude/worktrees/protocol-mining/…`。
   `artifacts/coverage_arms/` 本身被 gitignore(`.gitignore:18` 只豁免
   `artifacts/simple/` 与 `artifacts/deepseek_real/`),而 committed 的
   `measurements.json` 里存着指向该目录的 `artifact` 键 —— **指针指向未入库的路径**。

---

## 5. 优化点与方法论

排序依据:**不修前一条,后面那条的收益测不出来。**

| 优先 | 优化点 | 类型 | 方法论来源 |
|---|---|---|---|
| **P0-a** | 策略集合单一权威 + 漂移守卫测试 | 工程债 | 无外部文献 |
| **P0-b** | harness 语言单一权威(顺带解掉 C 驱动链接) | 工程债 | 循 `PFM §5.3.2` 体例 |
| **P0-c** | 失败记录覆盖构建期 | 工程债 | `PFM §4.2` 的前置条件 |
| **P0-d** | **缺测量 ≠ 低于参考** | 工程债 | `PFM §5.3.2` 的缺口 |
| **P1** | 散文 → 类型化事实 | 表示层 | `MT M1` + `M2`;`PFM §1.4 Tupni` |
| **P2** | IR ↔ FT 对账 | 表示层 | `PFM §5.3.1`;`MT M2` |
| **P3** | 入口语义统一 + 失败归因取未回滚的那条 | 工程债 | — |
| **P4** | N 次独立生成,生成间/运行间方差分开报 | 评测口径 | `MT M9 + M8`;`PFM §5.3.2` |
| **P5** | 模型 ↔ 产物互为 oracle | 终局形态 | `MT M11`(SPAR) |

(`PFM` = `PROTOCOL_FORMAT_MINING.md`,`MT` = `PROTOCOL_IR_METHOD_TRANSFER.md`。)

### P0-a · 策略集合单一权威

- **落点**:新增 `harness_generation/policy.py`,导出唯一集合;§2.1 的 8 处全部改为导入。
- **代价**:中(机械替换),风险是替换时**顺手改变行为**。
- **凭什么说改对了**:顺序刻意——**先**为每一对副本加相等性断言测试,**再**替换。
  断言失败处就是需要人工裁定的真实漂移点(已知至少 1 处:日志集合)。
- **不要一次性拉平**:`stage4.py:1134` 那句假 docstring 的教训是,把两处合并成一处
  等价于**对第三处的存在视而不见**。先枚举消费者,再合并。

### P0-b · harness 语言单一权威

必须先**做一个决定**,两个方向代价不同:

| 选 | 要改 | 立刻消掉 | 风险 |
|---|---|---|---|
| **C**(与 target 同语言,审计已按 C 解析) | `prompts.py:164/185`、`fuzzer_build.py:23-30` 去掉 `-x c++ -std=c++17` | `LLM returned invalid C syntax` 整族 | 丢掉 C++ 的表达便利 |
| **C++**(prompt/build 现状) | 审计换 C++ 语法树;**且 `target_coverage.py:241` 必须改用 `harness_compiler`** | 同左 | 改动面大,且必须与链接一起改 |

**只选 C++ 而不改链接 = §3.4 那条复合链。** 这两件事必须同一次做完。
**验证**:一条端到端测试,harness 里用 `std::vector` 仍能 build + link + run。

### P0-c · 失败记录覆盖构建期

- **落点**:attempt 级记录在 build 后回写,或建立 attempt ↔ build 的 join;然后
  `manifest.json` 的 `recorded_error` 改用 join 后的字段。
- **凭什么说改对了**:重建的 fixture 分桶表里**必须至少出现一个 build-time 失败族**。
  若重建后仍全是 pre-build 失败,说明 join 没生效,而不是说明"恰好没有构建失败"。
- **注意**:这**不等于**"去追那 4 次 invalid C syntax"。§3.1 指出的是
  **看错了文件**,不是"漏了一类样本"。

**实施记录（2026-09-20）**：新 attempt 的 `outcome.json` 已将解析结果与验证结果关联。
原 17 次 ProtocolIR 录制在构建前全部失败，不能凭空补出构建期分桶，因此保留其
`parsed.json` 原始分桶。另从仓库跟踪的 `artifacts/deepseek_real` 录制建立
`tests/fixtures/stage4_build_attempts/manifest.json`：15 次解析均通过，其中 13 次
在 `harness_compile` 失败；测试逐项从原始 `parsed.json`、`validation/compiler.json`
及 `validation/runtime.json` 复算，证明构建期失败进入分桶。这组历史录制没有
ProtocolIR，不应与原 17 次样本合并统计。

### P0-d · 缺测量 ≠ 低于参考

最小、最独立、且是其余各条的前提。

- **落点**:gate 裁决新增第三态 `unmeasured`;`passes_strict` 只在两侧都有数时才算;
  `all()`(`coverage_arms.py:1103`)换成显式三态归约。
- **凭什么说改对了**:构造一个 totals 为空的 arm,**断言报告是 `unmeasured` 而不是
  `below_reference`**。
- **方法论**:无外部文献可引。它是 `PFM §5.3.2` 那张表**结论 3 的可信度前提**。

### P1 · 散文 → 类型化事实

- **第一手证据**见 `MT §1`(`protocol_miner.py:1573` 写散文 /
  `tests/test_protocol_ir_e2e.py:82` 正则读回 / `protocol_ir.py:346-348` 三个字段都是
  `tuple[str, ...]`)。
- **落点**:`FrameField` 增 `size: SizeRelation | None`;`StatefulOperation.reason` 拆出
  `guard_symbols: tuple[str, ...]`;strict 模式下新字段必须有证据,否则 `ProtocolMinerError`。
- **代价**:高(牵动被 pin 的 `CONTRACT_BINDINGS` 字面量)。
- **凭什么说改对了**:`MT §3` 的总验收——新条款必须能拒掉那个**已知会退化**的
  contracted harness。
- **方法论**:`MT M1`(Peach Pit `Relation`,带类型的字段关系)+ `MT M2`(NSFuzz 状态变量);
  源头是 `PFM §1.4 Tupni` 的 length 约束。

**实施记录（2026-09-20）**：新挖掘的 IR 在 payload 上写入带来源和证据的
`FieldRelation(kind="size_of", target="payload", direction="parse")`，原有 `width`
继续保留；`FrameField.size` 是该关系的只读视图。状态操作另存 `writes`、`reads`、
`guard_symbols`，并从有证据的成员访问推导状态变量与 plan 的顺序约束。严格挖掘拒绝
缺乏证据的关系或状态符号。多帧且有 size relation 时，plan 必须声明有界字节采样表达式，
Stage 4 检查该表达式是否写入 harness，并以语法近似追到 payload 拷贝长度。
`contracted_published.c` 的 `remaining` 长度被拒；手写 reference 的取模采样通过。
旧 IR 不自动补写推断字段，以保持历史录制逐字可读与 round-trip。该审计不是数据流证明：
它只识别直接赋值和一步局部传递，也不跟踪后续覆盖。

### P2 · IR ↔ FT 对账

- **同一句话写在两处、两处都没修**:`protocol_ir_helpers.py:9` 与
  `pipeline_validation.py:245` 都写着 FT 来自共享结构边、**不来自 call closure**。
- **落点**:让 helper 的 membership 走 `§5.3.1` 已经发明的"**证据 ∩ 项目定义**"算子,
  把同一算子用在 lifecycle 上(`MT §5.3.1` 的 `helpers` 是唯一正确权威)。
- **方法论**:`PFM §5.3.1` 的算子,加上一个把"项目定义"读成**链接性**而不是**名字**的
  索引(`harness_generation/project_functions.py`)。无外部文献可引。

**实施记录（2026-09-20）**：新增 `project_functions.py`（把 `functions.json` 一次性读成
`linkable` / `internal_linkage` / `declared_only` / `ambiguous` / `absent` 五态索引）与
`protocol_reconciliation.py`（`reconcile_protocol_ir`），Stage 4、plan 投影、
`parse_harness_plan`、C 审计与 `PipelineStageValidator.contract_helpers()` 全部改读同一份
对账结果，`_load_function_metadata` 与 `_target_function_names` 两处"按名字集合判断"
消失。实测 `mini_parser` 的三类函数各归其位：`mp_init`/`mp_checksum` 在 FT 之外但可链接、
`le16` 是 `static` 因而是**证据而非许可**（`helpers` binding 从 4 个名字减为 3 个），
`mp_parse` 的 IR 与 triplet 入口一致。lifecycle 与 helper 的口径刻意不同：helper 是**可选许可**，缺失
（libc 的 `free`/`memset`）只是"不是本项目函数"，沿用旧行为；lifecycle 是契约**要求**的
调用，不可执行就整轮失败。对账失败发生在任何 LLM 调用之前，写入 `outcome.json` 的
`phase: "protocol_ir"`，`failure_type: "protocol_ir_error"`。

**审查修正（第二轮，2026-09-20）**：上面那版把三处判据留得太松，均由最小反例暴露，
已收窄并各自补了反例测试。

1. **表达式不能自证其名。** `context.init`/`destroy` 从 provenance 里彻底移除
   （`_strong_sources` 只读 `context.evidence`），槽位文本另由一个读者
   `read_lifecycle_expression` 读成四种形状之一：单个调用、单个裸名、类型化声明、
   无效。只有前两种带出函数名，而名字还要 `context.evidence` 佐证——原先
   `_CALL_PATTERN.findall` 扫整个表达式，`"mp_init(&ctx); invented(&ctx)"` 会让一个
   槽位同时授权两个名字。契约的断言不再是自己调用的许可。
2. **两种许可分开核验。** 项目调用按 `ProjectFunctionIndex` 的**唯一可链接定义**
   核验；标准库调用（`malloc`/`free`，即 `policy.py` 的 `DEFAULT_ALLOWED_FUNCTIONS`）
   按其自身许可核验——项目索引无权裁决 libc 名字（同 TU 内的 `static` 定义在此不可见，
   外部同名则是项目自己的冲突），记入对账结果的 `standard_library_names` 而**不进**
   `callable_helpers`；类型化声明由 harness 自己的 C 完成，无需授权；无效表达式
   （散文）**拒绝**而非原样透传成 `context.init` binding。这样"生命周期必须可执行"
   才与 plan 投影一致：gate 与许可读同一个读者，不会再就一个槽位说的是什么产生分歧。
3. **二次校验失败即拒绝。** `declared_contract_helpers()` 原先重读 `protocol_ir.json`
   后不看 `ok` 就交出 `callable_helpers`；`protocol_ir.json` 是发布后可被替换的文件，
   "Stage 4 曾拒绝过"不是该文档的性质，所以现在对账不成立即 `Stage4Error`（已测入口被
   换过的 IR）。缺失的 helper 仍只损失一条授权，这个不对称没有改变。
4. **索引对 `storage` 的形状严格。** `from_records()` 遇到 `storage="static"` 这类
   非"字符串列表"的形状原先读成空存储类，从而误判 `LINKABLE`；`storage` 是索引里唯一
   **误读即 fail-open** 的字段（空 ≡ 外部链接），故形状不对直接 `ValueError`。
   `defined` 仍按 `is True` 读，本来就是 fail-closed。

**收尾守卫（2026-09-20）**：类型化声明必须是完整的单条声明，只能用于 `context.init`，
且声明的基础类型须与 `context.type` 相符；未完成的赋值和后接第二条调用均被拒绝。
标准库名称也不能遮盖项目中两个同名外部定义造成的歧义——`DEFAULT_ALLOWED_FUNCTIONS`
允许 harness **写出**这个调用，并不证明链接时它会绑到 libc；两个同名可链接定义并存时调用目标
不可判定，这一歧义不能读作"只丢了一条可选授权"，因此该角落保持 `standard_library=False`
并发出诊断，与非 libc 名字的 `AMBIGUOUS` 处理一致。

**关于 call closure 的一处更正（本次改动同时修正）**：本节原先把"不改 IR、改为让 FT 抽取
补上 call closure"这条替代路线挂在 `PFM §1.3 Controlled Static Loop Analysis` 名下，并
据此说该步在 `PFM §5` 里仍是待办步骤 3。**该引用是错的**：`PFM §1.3`（及其 §5 步骤 3、
§4.1 第 3 行的 `command_loop`）讲的是**把解析循环的每次迭代建模成状态、迭代依赖建模成
转移**，从而反推消息格式，与"函数调用闭包"没有关系。因此：

- 这条替代路线**不再是 P2 的备选**，也**不得**作为改动 FT 抽取器的理由。P2 选的是
  在 IR 与 FT 之上加一层对账，FT 的"共享结构边、非 call closure"定义原样保留。
- `§6.1` 映射表里 P2 那一行的"§1.3 / §5 步骤 3（路线）"随之删除（见该表）。

### P3 · 入口语义统一 + 失败归因

- **落点**:`_failure_reason`(`pipeline_result.py:209`)取"未被回滚的最后一条",或让
  milestone 文案优先于 stage 文案。
- **凭什么说改对了**:plan 里那个已知例子——整轮原因被写成已回滚 attempt 的
  `HarnessPlan duplicates FT functions`——必须变成 milestone 文案。

**实施记录（2026-09-21）**：Stage 4 的必需验证若为 `unavailable` / `skipped`，仍按
未通过处理；原 `_nonblocking_result` 改名为 `_required_validation_incomplete`，并把
对应组件的警告和编译器启动错误写入 Stage 4 结果及 attempt `outcome.json`。最终
`_failure_reason` 只在最后一次 `rollback` 之后寻找失败事件；若恢复后的运行仅缺少
能力里程碑，报告里程碑原因。回归用例同时固定了“已回滚的 `mp_destroy` 错误不再冒充
整轮原因”和“回滚后当前 attempt 的终局错误仍保留具体原因”。

### P4 · N 次独立生成

- **凭什么说这是必要的**:`PFM §5.3.2` 已经就 **seed 轴**做过一次同类纠正,逐字写着
  "seed 只证明确定性,不构成独立样本"、"那是同一个数测了三遍"。
  **同一个错误在 generation 轴上还没有被检查过。**
- **落点**:至少 N=3 次独立 `generate`,生成间方差与运行间方差分开报。
- **方法论**:`MT M9`(生成方差是主方差)+ `MT M8`(评测口径)。

**实施记录（2026-09-21）**：新增 `generation-variance` 入口。至少 3 轮，每轮从同一套
`functions.json`、`triplets.json`、`protocol_ir.json` 等目录文件复制到全新的 artifact 根，
调用一次完整 `run --validate` 并只测正式发布的 harness；轮内的 Stage 4 回滚不计作独立生成。
目标源码、语料、参考 harness、执行预算和 seed 集固定，覆盖率复用 `coverage_arms` 的
无 sanitizer、仅目标源码的测量路径。`measurements.json` 保留每轮成功/失败及 harness
哈希，`report.md` 把各轮 seed 均值的样本方差与各轮内部 seed 样本方差分别列出；缺失测量
保留在请求总数里，不补零。默认 `N=3` 只作描述统计，不作显著性或总体结论。

运行例（需配置 `LLM_BASE_URL`、`LLM_API_KEY`、`LLM_MODEL`；仓库已存本次固定输入）：

```bash
python -m harness_generation generation-variance \
  --template tests/fixtures/generation_variance/template \
  --ft ft_mp_parse_787468773c9f \
  --project-root tests/fixtures/generation_variance/project \
  --output artifacts/mp-generation-variance-new \
  --trials 3 --runs 20000 --seeds 1,2,3
```

**实测（2026-09-21）**：从用户提供的 `.env` 读取配置，请求模型为 `deepseek-v4-flash`、
`temperature=0.2` 发起 3 次独立生成。三轮均正式发布、哈希不同，各完成 3 个 seed 的
2 万次目标源码覆盖率测量；第二轮的 Stage 4 曾回滚一次，只计作**一轮生成**。
`branches` 的三轮均值为 83.4967%，轮间样本方差 0.320373 平方百分点，轮内 seed
样本方差均值 0.961119 平方百分点；`lines` 两种方差均为 0。
完整证据在 `tests/fixtures/generation_variance/measurements.json`，三份正式发布物及固定
catalog/IR 同目录保存，`docs/GENERATION_VARIANCE.md` 由证据渲染；本地 20 MB 原始运行
文件留在被 git 忽略的 `artifacts/p4_mini_parser_20260921/campaign`。这组 3 轮描述统计
**没有**复现文献的“生成方差更大”现象，也不足以对其他 target 或预算作显著性判断。

### P5 · 互为 oracle

- **方法论**:`MT M11`(SPAR,`MT` 里唯一 A 级先例)。注意 SPAR 的生成用 Z3 不用 LLM,
  且不建模状态——只能借其**工程机制**,不能借它对协议 target 的论断。

---

## 6. 与 `PROTOCOL_FORMAT_MINING.md` 的映射

### 6.1 一对一映射

| 本文 §  | 痛点 / 优化点 | `PFM` 的哪一节 | 映射的性质 |
|---|---|---|---|
| §2.1 (a) | 策略集合漂移 | **§4.1 第 1 条** | **同构**:那条记的是 `source_analysis.py:493-496` 硬编码 helper 名单,P0-a 是它的一般化 |
| §2.1 (b) | harness 语言三处权威 | — | `PFM` 不覆盖 harness 生成语言,是本文新增 |
| §2.2 (d) | 第三层副本 | **§5.3.1** | §5.3.1 把"plan ↔ contract 一致性"当成**一项**来实现;它实际有**三个**消费者 |
| §3.1 | 失败记录只看 Stage 4 内 | **§4.2** | **前提关系**:§4.2 主张"把 miner 当被评估对象",而该主张要求失败样本先无偏 |
| §3.2 / **P0-d** | 缺测量 = 低于参考 | **§5.3.2** | **缺口**:那张表的三条限定处理"测量的解释",没处理"测量的缺失" |
| §3.4 | C 驱动链接 C++ 对象 | **§5.3.2** | **体例先例**:该报告已有 `## Evaluation infrastructure fixes`(修装置 → 重跑,不手改证据) |
| §4.1 | 输入哈希不校验 | **§5.3.2** | **只部分成立**:"重算每一个判定"成立,"输入被固定"不成立 |
| §4.4 | 证据含绝对路径 / 指针指向 gitignore | **§5.3.2** | 同上 |
| **P1** | 散文 → 类型化 | **§2 映射表** + **§5.3.1** | **因果关系**:§5.3.1 的"刻意不查"清单(描述性字段值 / `requirements`/`notes` 散文 / `limitations`)**不是设计选择,是表示层的直接后果** |
| **P2** | IR ↔ FT 对账 | **§5.3.1**(算子) | §5.3.1 已发明"证据 ∩ 项目定义",只是**只用在 `helpers` 一行**;算子里的"项目定义"要读成**链接性**而不只是名字,是本文新增。原写作"§1.3 / §5 步骤 3（路线）"是**误引**,§1.3 讲的是解析循环的状态机建模,与 call closure 无关,已在 §5 P2 更正 |
| **P4** | 生成方差 | **§5.3.2** | **同一错误的另一个轴**:该段已纠正 seed 轴,未检查 generation 轴 |
| — | §1.1 覆盖率缺口的来源 | **§1.6 + §4.1 第 2 条** | 见 §6.2(本文要求回写该文的地方) |

### 6.2 三处必须回写 `PROTOCOL_FORMAT_MINING.md` 的地方

**(1) §1.6 / §4.1 第 2 条只读到了循环的一半。**

该文把 `structured.c:16` 的 `% 7u` 记为"一个可直接验证的缺陷"(opcode 模偏差),并引入
NAUTILUS 的 uniform generation 作为对照。这没错,但**同一个循环的下一行才是契约缺口的
所在**:

```c
16:  uint8_t op = (uint8_t)(1u + (Data[pos++] % 7u));                 // 该文记的是这一行
17:  size_t requested = (size_t)(Data[pos++] % (MP_MAX_PAYLOAD + 1u)); // 缺口在这一行
18:  size_t len = hg_min_size(requested, Size - pos);
33:  pos += len;
```

`:17` 抽的是 `% 65` 而非"全部剩余",所以 `pos` 只推进 `len`,**循环因此真的跑很多轮**。
`contracted` 把长度写成了 `payload_len = remaining`(再钳到 `MP_MAX_PAYLOAD`),于是循环
对任何 ≤72 字节的输入**恰好跑一次**——这正是 `MT §1.1` 那 4 个丢失分支的成因。

**该文当时把这一段读作"reference 的一个性质",没有读作"契约必须保留的一条条款"。**
`MT` 补上了这一条(`size` 关系 + "每帧长度必须是 fuzz 可控的抽取、且留下剩余")。
所以该文 §4.1 第 2 条宜改为指向**缺陷的成因**,而不只是缺陷本身。

**(2) §5.3 的闸门缺第四项。**

该文把第 4 步拆成三项(schema / plan↔contract / 覆盖率等价)。三项都在问"产物对不对",
**没有一项在问"这次失败是产物错还是工具链错"**。P0-c/P0-d 就是这第四项。

**(3) §5.3.2 的"边界"段宜补一句输入层的限定。**

该段逐条列出了报告的限定(a)–(j),但 §5.3.2 开头那句
"`--check` 能在没有编译器、没有 LLM 的情况下重算每一个判定"**读起来像是全部可复现**,
而实测 `target_source.sha256` / `corpus.digests` 从不被读。建议改为
"重算每一个**判定**;输入哈希目前不参与校验"。

### 6.3 映射的边界

- `PFM` 覆盖的是**协议格式挖掘**(块 A/B/C),不覆盖 harness 生成语言、失败记录结构、
  链接驱动——本文 §2.1(b)、§3、§3.4 在那份文档里**没有对应节**。硬要对应会变成编造。
- `PFM §4.3` 的"文献的共同限制"表是**方法层**的,本文不重复;本文引它只作为
  "哪条路不该走"的旁证(例:Polyglot/Tupni 依赖 QEMU 级插桩 → P2 不走动态路线)。
- 本文与 `PFM §4.2 循环论证风险`**不冲突**:§4.2 说的是"别让被测者当出题人",本文说的是
  "别让同一件事有两个出题人"。两者都是**测量装置的完整性问题**,但机制不同,不能合并。

---

## 7. 与 `PROTOCOL_IR_METHOD_TRANSFER.md` 的映射

| 本文 | `MT` 的方法 | 关系 |
|---|---|---|
| P1 | **M1**(带类型字段关系)+ **M2**(状态变量) | 直接来源 |
| P2 | **M2** | FT 侧的对应物 |
| P4 | **M9**(生成方差)+ **M8**(评测口径) | 直接来源 |
| P5 | **M11**(互为 oracle,SPAR) | 直接来源 |
| P0-d | — | `MT` 无对应;它是 `MT §3 总验收` 能成立的前提 |
| P0-b | — | `MT §4 不采纳` 未列;属新发现 |

**两条需要一起读的约束**:

- `MT §5 实施顺序` 第 5 步要求"真机重跑 **N 次独立生成**(见 M9)+ coverage 复测"。
  这一条**在 P4 落地之前无法执行**,因为"N 次独立生成"目前没有可用的方差口径。
- `MT` 已记录 M10/M11 存在但**不排期**,理由写在该文 §5。本文的 P5 与之保持一致。

---

## 8. 诚实的边界

- 本文是**诊断,不是改进记录**。§5 的九条一条都没做。
- 三条审计各自独立完成,本文的 A 级结论由我逐条重跑过(§1 表);B 级结论**未执行**,
  已在表中标出。审计 A 未能执行 AST 相关代码是它用错了 python —— 本 worktree 的
  venv(`/home/luchitong/work/harness_generation/.venv/bin/python`)里 `tree_sitter`
  是可导入的,全量测试就在那个解释器上跑。所以第 14 行两条**可以复核**,只是本文尚未做。
- §3.1 的那次真机 run 已不在磁盘上(见 §1 末)。结构性论断成立,但"上一次 run 里有 N 次
  这类失败"这个具体数字,本文**不予主张**。
- §5 的代价估计是**改动面**的估计,不是工时估计;P1 的"高"指的是它牵动被 pin 的契约
  字面量,不是指它难写。
- 本文**不提**任何评测阈值。`MT` 的红线("缩小差距要改策略,不是改阈值")继续有效:
  P0-d 改的是**把"没测到"与"测到更低"分开**,不是放宽判定。
