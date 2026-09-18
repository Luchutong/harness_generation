# ProtocolIR 合约路径阻塞:真实模型的 Stage4 交互失败

本文记录一次真实（非 mock、非录制回放）DeepSeek 运行的结果。结论是负面的,
因此写成阻塞项而不是特性说明:

> 给定一份真实挖出的 `protocol_ir.json`,当前 Stage4 在 `benchmarks/mini_parser`
> 上**发布不出任何通过自身闸门的 structured harness**。四次 attempt 分别被两个
> 不同的校验器挡下,`harnesses/` 目录为空。

`attempt_003` 产出的 harness 可以编译、运行并命中目标 bug,但它**不是被 pipeline
接受的产物**。本文不把它当作可用 arm。

## 0. 复现路径与 provenance

三段来源必须分开记录,因为它们的可信度不同:

| 阶段 | 来源 | 说明 |
|---|---|---|
| `functions.json` / `triplets.json` | **真实离线静态链** | `python -m sfg_builder` → `python -m harness_generation triplets`,无 LLM、无 key |
| `protocol_ir.json` | 真实 source mining + **录制回放**的 conventions | 静态 A/B 块来自 `target.c` 挖掘;惯用法块来自 3 次真实 DeepSeek 采样(vote confidence 1.0),回放 provider 标为 `recorded-response` |
| Stage1-4 生成 | **真实 DeepSeek** | `deepseek-v4-flash`,config 名与响应体自报的 `deepseek-flash` 不同 |

命令序列:

```bash
cp benchmarks/mini_parser/target.c <project>/          # 只放 target.c,避免解析到参考 harness
python -m sfg_builder --project <project> --output <phase1>
python -m harness_generation triplets --artifacts <phase1>
# protocol-mine 产出 protocol_ir.json,写入 <phase2>/
python -c 'from harness_generation import cli; cli.main([
  "generate", "--artifacts", "<phase2>", "--ft", "ft_mp_parse_787468773c9f"], llm=recorder)'
```

`<phase2>` 与 `<phase1>` 的唯一差别是多了 `protocol_ir.json`——Stage 4 的
`{protocol_contract}` 槽位由 `<artifacts>/protocol_ir.json` 填
(见 `PROTOCOL_FORMAT_MINING.md` §5.2),不是手写 spec。

## 1. 观测结果

运行规模:**24 次生成 / 68,586 tokens / 66.3s**,rollback 6 次
(`STAGE_2 ×3 → STAGE_1 ×3`),最终:

```
Failure reason: Stage4Error: HarnessPlan references functions outside the FT: mp_init
```

四次 attempt 的失败原因(`<phase2>/generation/<ft>/stage4/attempt_00N/parsed.json`):

| attempt | phase | error |
|---|---|---|
| 001 | `harness_plan` | `HarnessPlan references functions outside the FT: mp_init` |
| 002 | `harness_plan` | 同上 |
| 003 | `harness_code` | `Stage 4 redefines project APIs: mp_checksum` |
| 004 | `harness_plan` | `HarnessPlan references functions outside the FT: mp_init` |

### 1.1 attempt 1/2/4:`mp_init` 永远过不了 plan 校验

挖出的合约含 `context: {type: mp_context, init: mp_init, destroy: mp_destroy}`,
模型照办,把 `mp_init` 写进 plan。但 `stage4.py:611` 的集合校验是:

```python
expected = {function.function for function in triplet.functions}
unknown = sorted(set(all_planned) - expected)
```

`ft_mp_parse_787468773c9f` 的 `functions` 只有 `{mp_destroy, mp_parse}`
(isf=`mp_parse`, prfs=`[mp_parse]`, hpfs=`[mp_destroy]`)。`mp_init` 确实是项目函数
(`functions.json` 里有 `target.c:41:mp_init`,body 是 `memset(ctx, 0, sizeof(*ctx))`),
但不在这个 triplet 里。

这不是模型幻觉:是**合约自己声明的 `context.init` 与 FT 抽取结果的结构性错配**。
只要合约提到任何 context 初始化函数,plan 校验就必然拒绝——除非该函数恰好在
`triplet.functions` 内。

### 1.2 attempt 3:harness 生成了,但被重定义检查拒绝

`attempt_003/plan.json` 的 `protocol_contract_bindings` 结构完整:7 个 frame 字段
带 `role`、`header_size: 8`、`payload_offset: 8`、`bounded_steps: 32`、
`repair_length`/`repair_checksum`、`stateful_operations` 三项齐全。产出的
`attempt_003/harness.c`(2165 字节)有界多帧循环、按 role 组装 envelope、payload 保持
fuzzer 可控——形状是对的。

但它自己实现了 `static uint16_t mp_checksum(...)`,触发 `stage4.py:857`:

```python
redefined = sorted((set(definitions) - {FUZZ_ENTRY}) & all_project_functions)
```

该检查**没有 helper 豁免**。

## 2. Fix A:plan 校验把 FT 调用与合约 helper 混在一个集合里

`mp_init` 这类 context 生命周期函数不应该被当作 ISF/PRF/HPF 的 FT 调用去要求属于
`triplet.functions`。它应当能出现在 `state_objects` 的初始化、或 `cleanup_sequence`
的生命周期区域,而不进入"每个 FT function 恰好一次"的集合校验。

`context.init` 是合约自己的声明,不是模型的自由发挥;把它算作越界,等于合约一提到
生命周期函数就自我否决。

## 3. Fix B:helper 的 callable / evidence-only 维度缺失

原假设是"`mp_checksum` 是 static、跨 TU 调不到,所以模型只能重定义"。**核实后不成立**:

- `mp_checksum` 在 `target.c:50` 是**非 static** 定义,第 27 行有原型,外部可调用。
- 挖出的 IR 已经把它声明为 allowed helper(`collect_protocol_helpers(ir).allowed`
  = `{free, le16, memset, mp_checksum, mp_destroy, mp_init, mp_parse}`)。
- `stage4.py:888` 的越界检查是 `expected | declared_helpers`,**调用 `mp_checksum`
  本来是被允许的**。

所以模型有合法选项却选择了本地重定义。真正的问题是**同一条规则的不对称**:

| 检查 | 位置 | 是否豁免合约 helper |
|---|---|---|
| 调用 FT 之外的项目函数 | `stage4.py:888` | **是**(`declared_helpers`) |
| 重定义项目函数 | `stage4.py:857` | **否** |

同一个 helper 因此"可调用但不可定义"。模型看不到可用声明时倾向自己实现,而审计不给
第二次机会。

**真正的 static 死结是 `le16`,不是 `mp_checksum`。** `target.c:37` 是
`static uint16_t le16(...)`,而它在 `allowed` 里。分离编译下调用它是链接错误,已验证:

```
/usr/bin/ld: harness.o: in function `LLVMFuzzerTestOneInput':
harness.c:6: undefined reference to `le16'
```

本次未爆雷,只是因为模型恰好把小端编码内联了(`frame_buf[4] = len & 0xFF`),没有调
`le16`。合约里 `payload_length` 的 value 写的正是 `"le16() load"`——即合约在按名字
指一个 static helper。

因此 helper provenance 需要"可调用 vs 仅供参考"这一维,而不是只给一个名字集合:

- **B1**:`redefined` 检查补上与 `outside_ft` 对称的 helper 豁免,或者在拒绝时明确告知
  该 helper 可调用(模型无法从错误信息里得知自己本可以调用)。
- **B2**:`allowed` 必须区分 linkage。`.allowed` 目前把 static 项目函数与外部可见函数
  混在一起,给出一个构建无法兑现的调用许可。static helper 要么标为 evidence-only,
  要么由 build recipe 保证与 target 同一 TU。

## 4. 三臂覆盖实验(实验性,不作为结论)

配置:同一 seed corpus、`-runs=20000` 固定执行预算、`-seed=1`、3 次重复。

| arm | 来源 | status | cov | ft | execs | 命中 |
|---|---|---|---|---|---|---|
| reference | `harnesses/structured.c` | finding | 36 | 64 | **43** | `mp_parse target.c:91`(UBSan,有符号乘法溢出) |
| contracted | `attempt_003/harness.c` | finding | 67 | 70 | **1348** | `mp_parse target.c:73`(ASan heap-buffer-overflow) |
| uncontracted | `<phase1>/harnesses/*.c` | completed | 11 | 12 | 20000 | 无 |

三个 arm 的 verdict 必须分开写:

- reference:**accepted baseline**
- contracted:**rejected attempt**,executable diagnostic artifact
- uncontracted:**accepted FT-only artifact**

因此它只能支持这个结论:

> ProtocolIR-shaped attempt 的可达性潜力明显更高,但当前闸门使它无法成为 pipeline
> 接受产物。

**不能**写成"contracted pipeline 优于 uncontracted pipeline"——contracted 这一臂从未
通过闸门,统计的是被拒绝产物的行为。

### 4.1 公平性限制

- cov/ft 含 harness 与插桩,不是 target 源码覆盖(沿用 `assessment.collect_metrics`
  的 limitations 原文:*Engine cov/ft includes harness and instrumentation; it is not
  target source coverage.*)
- reference 是单 TU(`#include "target.c"`,靠 `normalize_cpp_harness` 补
  `extern "C"`);两个生成 arm 是 target/harness 分离编译再链接。recipe 不同会影响
  内联与 cov 计数,三条数值不可直接并列比较。
- `-seed=1` + 固定 `runs` 使 3 次重复完全一致。这一栏测的是**确定性**,不是
  稳健性;它不是 3 个独立样本。
- uncontracted 臂来自一次**缺少 `protocol_ir.json`** 的运行:Stage4 走 FT-only 路径,
  模型从未被要求绑定 frame,所以发布物是 `mp_parse`+`mp_destroy` 的直通空壳。
  它不代表"合约无用",只代表"没给合约时的基线"。
- 合约里 `opcode` 的 value 是散文 `"dispatch selector over 7 cases, values 1..7"`。
  spec-driven harness 渲染侧的 opcode 区间靠 `tests/test_protocol_ir_e2e.py` 的
  `_OPCODE_RANGE = re.compile(r"values\s+(\d+)\.\.(\d+)")` 从这段散文里正则抽取——
  这条正则命中纯属巧合。Task 4.5 的"只认字面常量"决定(`magic`/`version` 是字面量,
  `opcode` 不是)与此一致,修它属于 mining/IR 层面,不是本实验能绕的。
- 本文未提交任何录制 artifact 作为 fixture;上表可复现但依赖 `/tmp` 下的中间产物。

## 5. 与本次无关但已澄清的一处

管线摘要里的 `Linker: unavailable` / `Runtime: skipped` / `Fuzz smoke: not_run`
**不是工具链缺失**。`generate` 调用未提供 build/link 配置,Stage4 因此只做了
`-fsyntax-only`:

```
validation/linker.json  -> "link validation unavailable: no build or link configuration"
validation/runtime.json -> "executable was not provided"
```

要让 Stage4 真正构建,需要走 build capability 那条路径
(`FuzzerBuildValidator`:target 与 harness 分别编译成 object,再链接)。
