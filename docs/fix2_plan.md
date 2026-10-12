# HG v0.5 重构方案：从语义证明优先转向 Harness 生成优先

我建议下一阶段对 HG 做一次研究目标和流水线职责的调整，而不是继续扩展 SVF、Effect Verifier 或复杂 C 语义证明规则。

新的核心目标应当是：

> 面向真实 C/C++ 项目，利用 LLM 和静态分析自动生成能够成功编译、正确调用目标 API、在受控环境下运行的 Fuzz Harness。通过实际编译和运行观察验证候选的可执行性，而不是要求先证明目标库内部完整的内存管理实现。

后续再以 coverage、有效输入消费、运行稳定性、Sanitizer 报告等信息构建 Feedback，驱动 Strategy 和 Harness 迭代。

但本轮只调整生成流程和验证目标，不实现测试反馈驱动的再次生成。

## 一、最关键的架构变化

目前 HG 的问题集中在这条依赖链：

```
LLM 生成 Strategy
        ↓
Effect Verifier 尝试证明所有语义效果
        ↓
Semantic Obligation Graph
        ↓
所有 Mandatory Roots 必须闭合
        ↓
Verified FrozenPlan
        ↓
Harness Generation
        ↓
Build / Runtime
```

真实 parser 中的循环、递归、allocator hooks 和复杂 ownership 会导致 Context 长期不闭合，使生成阶段无法得到执行机会。

虽然 v0.4 已经增加了 Experimental DraftPlan 路径，但它仍然是正式证明失败后的次要分支。因此，框架的控制流本质上仍是证明优先，而不是生成优先。

我建议改成：

源码 + Build-aware Index

Tree-sitter / Clang，提取 API、签名、类型和真实构建配置

Candidate Discovery + Lightweight API Context

确定目标入口、可能的初始化/清理 API、可用调用证据

LLM Strategy Planning

生成类型化 API 调用顺序、输入绑定、guard 和 cleanup

Execution Preflight Gate

检查 ABI、调用存在性、参数结构、已知禁止条件和资源绑定

ExecutablePlan → 确定性 Harness 翻译

无需等待复杂所有权证明

真实编译 + Sanitizer Runtime Smoke

记录编译、链接、运行、崩溃及有效性观察

Harness Candidate + Execution Report

保存产物、失败原因、证据及成本

未来阶段：Feedback → Strategy Revision → 新 Harness

仅保留接口和可复用数据，当前不执行闭环

与此同时保留原有：

`Semantic Effect Verifier → Obligation Graph → Verified Gate`

但将其作为可选的独立语义认证流程，不再阻止默认路径生成和运行 Harness。

这一区分非常重要：

- 生成成功：Harness 已生成，并通过相应的编译或运行检查。
- 语义认证成功：满足一套明确定义且经过可信证据证明的语义义务。
- Fuzzing 有效：观察到输入确实触达目标的有效处理路径。

三者应分别统计，不能互相冒充。

## 二、重新定义 HG 的核心成功标准

原来的目标接近：

\\[ \text{Success}=\text{All Semantic Obligations Proven} \\]

这会将 Harness Generation 的成败绑定到复杂 C 程序验证能力。

我建议改为以分阶段、可观察的生成结果为主：

| 等级 | 新状态                 | 判定方式                              |
| -- | ------------------- | --------------------------------- |
| L0 | `plan_valid`        | Strategy 和类型化计划通过基础验证             |
| L1 | `code_generated`    | 生成完整 Harness，代码行为符合计划             |
| L2 | `build_success`     | 真实目标源码与 Harness 编译、链接成功           |
| L3 | `runtime_passed`    | 指定输入下运行成功，未发现导致失败的基础 Harness 执行问题 |
| L4 | `fuzz_effective`    | 有额外证据表明 fuzz 输入进入有效目标处理路径         |
| 独立 | `semantic_verified` | 可选严格语义 Gate 通过                    |

其中 L4 不应由 L3 自动推出；`semantic_verified` 也不作为 L0–L3 的前置条件。

例如，过去的 `json_parse_r02`：

```
json_value *tree = json_parse(data, size);

if (tree != NULL)
    json_value_free(tree);
```

如果 Strategy 结构、实际函数签名与调用契约没有已知冲突，那么它应该可以进入默认生成路径，完成编译和运行。

不需要先证明 `json_value_free()` 内部每个循环和分配释放分支。

但如果明确知道某个 API 需要非空有效句柄，Strategy 却传入 `NULL`，就应该拒绝或标记无效，不能以“暂时不做完整语义证明”为理由忽略已知的调用契约。

新方向是降低生成前的证明负担，而不是取消正确性检查。

## 三、核心修改一：重构 Gate，区分“已知错误”和“尚未证明”

这是整个方向调整中优先级最高的修改。

### 3.1 当前 Gate 的问题

现在有些语义状态实际上被混合处理了：

```
API 调用明显错误
        → 不允许正式生成

API 调用看起来合理，但未证明完整 ownership
        → 不允许正式生成

复杂 cleanup 含有未支持的 while
        → 不允许正式生成
```

对于严格形式化证明，这种处理是合理的。

但对于 Harness Generation，后两种情况不应该自动阻止生成可执行候选。

### 3.2 建议引入 Execution Preflight Gate

将现有严格 Gate 与新 Gate 分离：

| 检查事项                         | Execution Preflight | Formal Semantic Gate |
| ---------------------------- | ------------------- | -------------------- |
| API 是否存在                     | 必须检查                | 必须检查                 |
| ABI、参数数量和类型                  | 必须检查                | 必须检查                 |
| Strategy IR 是否结构合法           | 必须检查                | 必须检查                 |
| 调用资源是否具有合法来源                 | 必须检查已知关系            | 要求认证对应义务             |
| 是否违反已知 API 前置条件              | 拒绝明确违反的调用           | 还需认证相关前置条件           |
| API 调用顺序                     | 拒绝可确定的非法顺序          | 认证顺序与生命周期要求          |
| Ownership 来源                 | 可以保留 unknown        | 要求完整证明对应义务           |
| Cleanup 内部循环                 | 不作为生成硬阻塞            | 无法证明时保留 unknown      |
| 递归释放                         | 不作为生成硬阻塞            | 需要有效摘要或证明            |
| SVF may-alias                | 辅助调查                | 不能直接认证 must-alias    |
| 完整 Semantic Obligation Graph | 不要求全部闭合             | 必须满足正式证明策略           |

### 3.3 使用三值判断，而不是简单布尔值

建议将调用契约判断表示为：

`SATISFIED`、`VIOLATED`、`UNKNOWN`。

例如：

```
class ContractStatus(Enum):    SATISFIED = "satisfied"    VIOLATED = "violated"    UNKNOWN = "unknown"
```

新 Gate 的核心逻辑可以设计为：

```
def evaluate_preflight(strategy, build_index, contracts):    structural = validate_strategy_structure(strategy)    abi = validate_abi(strategy, build_index)    bindings = validate_resource_bindings(strategy)    contract_checks = check_known_contracts(strategy, contracts)    if not structural.valid:        return Reject("invalid_strategy")    if not abi.valid:        return Reject("invalid_abi")    if not bindings.valid:        return Reject("invalid_resource_binding")    if any(c.status == VIOLATED for c in contract_checks):        return Reject("known_contract_violation")    unresolved = [        c for c in contract_checks        if c.status == UNKNOWN    ]    return AllowExecution(        unresolved_contracts=unresolved,        semantic_verified=False,    )
```

这是推荐的逻辑示意，不是现有代码。

其中有一个重要细节：`VIOLATED` 必须建立在已经认证的契约及其适用条件上。

不能因为模型认为某种调用方式不推荐，就把它当作确定的契约冲突。

同样，`UNKNOWN` 不是正确性的证明，只表示尚未排除该候选，允许在受控条件下进行实验验证。

### 3.4 Execution Gate 必须继续阻止的错误

例如：

```
XML_Parse(NULL, data, size, 0);
```

如果已经有足够证据表明第一个参数必须是有效的 parser 对象，那么这种 Strategy 应被拒绝。

另外，对于：

```
Object *a = create();
Object *b = create();

destroy(b);
use(b);
```

如果资源绑定和 API 契约能够明确判定 `b` 已进入 released 状态，就不应该因为关闭严格所有权证明而放行。

新方向不是放弃生命周期建模，而是只要求生成前验证当前系统有能力明确检查的安全约束，不再把所有未证明命题当作生成失败。

## 四、核心修改二：将完整 Context 证明从生成前置条件中移除

我不建议删除现有的 `Effect Verifier`、`Semantic Obligation Graph` 和 `SVF Backend`。

这些是已经投入大量工作的基础设施，仍然可以为 Harness 质量提供支持。

但它们的职责需要改变。

### 4.1 旧职责

```
Effect Verifier
       ↓
证明所有必需语义
       ↓
允许进入 HarnessPlan
```

### 4.2 新职责

```
Strategy
    ↓
轻量契约提取与验证
    ↓
Preflight Gate
    ↓
生成 Harness
```

另一条可选路径：

```
Strategy
    ↓
完整 Effect Verifier
    ↓
Semantic Obligation Graph
    ↓
正式语义认证报告
```

建议把 Semantic Context 分成两种用途：

| 类型                 | 目的                           | 对生成的影响          |
| ------------------ | ---------------------------- | --------------- |
| `ExecutionContext` | 保存所需 API、参数来源、资源关系、已知契约和未知条件 | 决定能否尝试编译运行      |
| `ProofContext`     | 保存完整效果证书、证明依赖和未闭合义务          | 可选的严格认证，不阻塞普通生成 |

两者可以共享底层证据，但不应该要求 `ExecutionContext` 先通过 `ProofContext` 的全部证明。

### 4.3 不要用修改旧 Gate 标签的方式实现

尤其不应该这样：

```
# 错误方案context["generation_allowed"] = Truecontext["frozen"] = True
```

这会破坏你此前努力建立的 Verified / Experimental 隔离。

应当新增独立的生成许可：

```
{
  "execution_preflight": {
    "allowed": true,
    "known_violations": [],
    "unknown_contracts": [
      "returned_object_ownership_unverified",
      "cleanup_internal_effect_unverified"
    ]
  },
  "formal_semantics": {
    "verified": false,
    "unresolved_obligations": 6
  }
}
```

`execution_preflight.allowed=true` 不代表 `formal_semantics.verified=true`。

建议继续保留严格 `FrozenPlan` 作为原正式认证产物，而为默认执行路径使用 `ExecutablePlan`，或者复用现有 `DraftPlan` 的底层机制并赋予清晰的生成候选身份。

此处的 `ExecutablePlan` 可以具有冻结的文件内容和 digest，但计划内容不可变不等于已完成形式化语义证明。

## 五、核心修改三：让生成链路不再被 Candidate、Slice 和 FT 的不稳定性完全阻断

这是实际提高 fresh Harness 产出的关键。

从历史 17 次 fresh run 来看，失败不只有 Context Gate。

还有 Candidate timeout、Slice 输出失败，以及对 callback、stream、opaque context 等结构支持不足。

如果仅修改 Context Gate，而保留完全相同的前期强制依赖，仍然会有相当多的运行到不了生成阶段。

因此我建议引入两级上游分析路径。

### 5.1 默认路径：轻量 API Context

对于简单的 C 接口，比如：

```
json_value *json_parse(
    const json_char *data,
    size_t size);

void json_value_free(json_value *value);
```

理论上并不需要先完成一个较复杂的 Semantic Slice，再生成 Minimal FT，然后进入 Strategy Planning。

可以通过如下方式建立候选上下文：

```
Clang 确认函数签名
        ↓
发现输入参数和返回类型
        ↓
查找类型相关的构造/清理 API
        ↓
读取附近调用示例和源码证据
        ↓
建立最小 Allowed API Scope
        ↓
LLM 生成 Strategy
```

这个上下文可以由确定性分析和少量 LLM 调查形成。

`Allowed API Scope` 应包含具体的已验证符号及其来源，不允许 LLM 凭空添加不存在或未经授权的函数。

### 5.2 复杂路径：保留 Semantic Slice / FT

对于存在：

- 共享状态；
- 多阶段生命周期；
- 注册回调；
- 复杂初始化；
- 跨多个 API 的协议；

这类目标仍然可以使用已有：

`Candidate → Semantic Slice → Minimal FT`

但 Slice 的角色应该从“所有 Harness 必须先通过的独立语义阶段”，调整为“复杂 API 发现和上下文扩展工具”。

建议分两步迁移，避免一次性破坏旧链：

第一步：保留 Candidate/Slice/FT，先解除 Context 证明对代码生成的阻塞。

这样可以立即验证新生成路径是否有效。

第二步：增加 Lightweight API Context，允许已经由 Clang 确认的明确入口直接形成受限的生成上下文。

新路径不能伪造 `Slice completed` 或 FT 认证，也不能通过取消 API Scope 校验来实现所谓的快速生成。

它应拥有独立的授权依据和产物类型。

## 六、核心修改四：让 API 使用契约代替内部实现的完整证明

这应该成为新的静态分析研究重点。

### 6.1 从复杂效果证明转向 Harness 所需的最小契约

例如，一个 parser API 的基本契约可以是：

```
parse(data, size)
    Input:
        data: readable bytes
        size: input length

    Return:
        success: parser-owned or caller-owned resource
        failure: NULL or error status

cleanup(resource)
    Preconditions:
        resource valid under documented API rules

    Effects:
        resource must not be reused afterward
```

这里还必须进一步明确到底是 `parser-owned` 还是 `caller-owned`，不能在实际执行时保留模糊选择而假装两者等价。

但重点在于：

你需要确定调用方应该如何使用资源，不一定需要把 cleanup 内部的每次 free 和循环全部自动证明出来。

### 6.2 允许多种来源的契约证据

建议新建 `APIContract`：

| 证据来源              | 用途          | 注意事项                |
| ----------------- | ----------- | ------------------- |
| Clang 类型信息        | 参数和 ABI 约束  | 类型正确不代表语义正确         |
| 项目公开 API 文档       | 创建、使用、清理协议  | 需绑定版本及适用条件          |
| 项目示例/测试代码         | 发现真实使用模式    | 示例不是完整正确性证明         |
| 静态 Effect Summary | 可以证明的局部函数效果 | 保留分析前提              |
| SVF 值流与别名         | 资源/参数传播关系   | may-flow 不自动变成 must |
| LLM 提案            | 候选调用契约      | 不能自行取得可信证书          |
| 人工审核契约            | 受控研究基线      | 必须记录审核范围和版本         |

这样，LLM 的职责就可以从：

“尝试解释函数内部全部内存管理逻辑”

转为：

“调查目标 API 的合法使用方式，寻找可追溯证据，并生成符合契约的调用策略”。

在默认生成路径中，合理但未认证的契约假设可以保留为风险信息；只有已验证的明确违反才作为确定性拒绝依据。

对于正式 Semantic Verification，仍然只能消费满足相应信任策略的证据。

## 七、核心修改五：把编译和运行变成默认主链的一部分

现在的开发方向应该保证：

只要 Strategy 通过 Execution Preflight，就进入 Harness 生成与真实构建，而不是反复调查无法闭合的复杂效果。

### 7.1 优先复用确定性翻译器

根据最新报告，HG 已经能够通过 Strategy IR 生成 canonical C/C++ 翻译，代码模型只能做不改变行为的有限修改。

因此，新主链建议默认：

```
Typed Strategy
       ↓
ExecutablePlan
       ↓
Deterministic Translator
       ↓
harness.c / harness.cpp
       ↓
Clang Build
       ↓
Sanitizer Runtime
```

对于现有 Strategy IR 已经支持的调用行为，不再额外请求一次 LLM 来生成几乎相同的代码。

LLM 主要投入 API 调查和 Strategy Planning。

如果生成器缺少某种表达能力，应返回清晰的 `unsupported_translation`，而不是临时允许代码模型自行改变调用策略。

### 7.2 生成后验证分三个层次

第一层：代码与编译验证

是否生成完整 harness？是否符合 Strategy？是否能与真实目标库编译和链接？

保存构建命令、编译日志、代码 hash、目标源码和编译配置身份。

第二层：Sanitizer Runtime Smoke

使用固定语料在受控环境下运行，记录异常退出、超时、ASan/UBSan 结果。

如果遇到崩溃，需要区分明确的 Harness 使用错误、可能的目标漏洞和暂时无法归因的失败，不能一概认定目标或 Harness 有缺陷。

第三层：基础有效性观察

判断是否有证据表明 fuzz input 进入了目标功能处理路径。

例如，Expat 的 NULL parser 虽然可以运行，但不能登记为有效解析。没有足够动态证据时，记录 `unknown`，而不是强行判定成功或失败。

建议沿用现有 `quality.py` 的三轴记录思路，不要再创造一套互相冲突的质量标签。

### 7.3 本阶段不根据运行结果自动再生成

这一点按你的要求严格执行。

当前流程应该是：

```
生成一次 Strategy
       ↓
生成一次 Harness
       ↓
编译与运行
       ↓
保存成功或失败
       ↓
结束
```

即使编译失败，也只保存诊断和产物，不自动调用 LLM 修改代码。

即使 Sanitizer 报错，也不自动回到 Planner。

未来才加入：

```
Build/Runtime/Coverage
         ↓
Feedback Analyzer
         ↓
Strategy Revision
         ↓
新 Harness
```

目前可以提前设计结果字段，但不要实现 Feedback Controller、自动修复队列或基于评分的新一轮生成。

## 八、具体需要修改哪些模块？

根据你最新报告中的实现结构，我建议尽量复用现有模块，而不是另起一套 Harness Generator。

| 现有模块                                        | 调整方向                                     | 是否保留    |
| ------------------------------------------- | ---------------------------------------- | ------- |
| `sfg_builder/`                              | 保留结构索引与快速候选发现                            | 保留      |
| `source_analysis/`                          | 继续提供 Clang ABI、函数签名及构建身份                 | 保留      |
| `semantic_slicing/`                         | 从强制上游阶段调整为可选的复杂 API 分析路径                 | 保留      |
| `harness_strategy/`                         | 成为主要的 LLM 生成阶段                           | 重点使用    |
| `semantic_effects/`                         | 提供有限 API 契约事实，不要求证明库内部全部内存效果             | 保留      |
| `svf_backend/`                              | 用于按需解决关系不确定性，不作为默认生成前置依赖                 | 保留、默认可选 |
| `strategy_context/gate.py`                  | 拆分 Execution Preflight 与严格 Semantic Gate | 核心修改    |
| `context_generation/draft_builder.py`       | 复用并扩展为默认可执行候选计划构建机制                      | 核心修改    |
| `context_generation/strategy_generation.py` | 默认使用确定性代码翻译                              | 核心修改    |
| `orchestration/controller.py`               | 新增单次生成模式，不再优先执行语义补证与重规划                  | 核心修改    |
| `orchestration/quality.py`                  | 独立记录编译、运行和有效性                            | 保留、完善   |
| `orchestration/checkpoint.py`               | 保存计划、代码、构建、运行及诊断                         | 保留      |

### 建议新增的三个小模块

```
harness_generation/
├── api_contracts/
│   ├── models.py
│   ├── extraction.py
│   └── validation.py
│
├── execution_preflight/
│   ├── gate.py
│   └── diagnostics.py
│
└── context_generation/
    └── executable_plan.py
```

分别负责：

- `api_contracts`：归一化 API 使用约束及证据来源。
- `execution_preflight`：判断候选是否存在已知非法行为。
- `executable_plan`：将允许尝试运行的 Strategy 固定成不可变计划。

这三个模块都应尽可能薄，避免再次出现大规模职责重叠。

## 九、建议采用的实施顺序

这次我建议只做五个 PR，完成一轮小规模真实验收后就停止新增功能。

### 01

PR-01：拆分双 Gate，解除证明依赖

新增 Execution Preflight，不再要求完整 Context 闭合才能进入生成；保留原 Verified Gate 的全部严格性。

验收： 固定 `json_parse_r02` 在原 Context 仍为 17/23 的情况下，可以获得可执行候选计划；已知错误 ABI、非法资源绑定、明确违反的 API 契约仍被拒绝。

### 02

PR-02：ExecutablePlan 与确定性生成

基于现有 Strategy IR 和 canonical translator 实现生成，不依赖代码 LLM、不调用完整语义证明器。

验收： 固定 Strategy 可以生成真实 C Harness，并通过实际 Clang 编译与基本 runtime。

### 03

PR-03：单次生成 Controller

实现独立 `generate` 模式。一次 Strategy Planning、一次代码生成、一次 build/runtime 验证，保存结果后结束。完整 semantic recovery 保留给其他模式。

验收： 不因复杂 cleanup 证明失败而反复请求模型；没有任何 build/runtime 触发的新一轮生成。

### 04

PR-04：Lightweight API Context

增加不依赖完整 Semantic Slice 的简单 API 上下文生成路径，同时保留现有 Slice/FT 模式作为复杂协议分析选项。

验收： 对已经确认的 parser anchor，可以直接建立受限 API Scope 并生成 Harness；不伪造 Slice/FT 的完成状态。

### 05

PR-05：生成质量与固定实验

规范 `build_success`、`runtime_passed`、`fuzz_effective` 和 `semantic_verified` 的独立统计，完成真实项目的小规模测试。

验收： `XML_Parse(NULL, ...)` 不被记为有效解析 Harness；固定 json_parse 可以完成新默认链路；严格认证结果不被覆盖。

### 对本轮工作的明确限制

先不扩展：

- 通用循环和递归语义证明；
- SVF points-to 精度及复杂对象图算法；
- 任意 callback / stream / out-parameter 的新语言能力；
- 基于 coverage 的 Strategy 打分；
- 自动代码修复和多轮 Harness 生成；
- Feedback Controller。

这些能力可以保留为以后独立的研究工作，但当前阶段不再把它们列为新主链完成的前提。

## 十、重构完成后，框架应该如何运行？

建议在 CLI 中明确区分两种模式。

```
# 默认研究主线：优先生成、编译和运行
harness-generation harness-run \
    --mode generate \
    --artifacts ./artifacts/target \
    --build \
    --runtime
```

```
# 保留原严格语义认证模式
harness-generation harness-run \
    --mode verify \
    --artifacts ./artifacts/target \
    --build \
    --runtime
```

以上是建议的新 CLI 设计，不是当前已支持的参数。

两种模式的差别：

| 行为                           | `generate` | `verify` |
| ---------------------------- | ---------- | -------- |
| 需要完整 Semantic Slice          | 不强制        | 按原正式链要求  |
| 需要全部 Semantic Obligations 闭合 | 否          | 是        |
| 需要合法 Strategy 和 ABI          | 是          | 是        |
| 检查已知调用契约冲突                   | 是          | 是        |
| 生成可执行 Harness                | 是          | 通过证明后生成  |
| 编译与运行                        | 默认执行       | 按配置执行    |
| SVF                          | 可选按需       | 可供证明使用   |
| 语义认证身份                       | 保留未证明状态    | 严格区分是否认证 |
| 自动 Feedback 迭代               | 暂不支持       | 暂不支持     |

建议新默认模式采用 `generate`，而不是让用户每次显式开启旧的 `allow_experimental` 绕过正式 Gate。

但迁移时必须明确记录新的执行许可；不能悄悄改变现有 `FrozenPlan`、`generation_allowed` 的正式语义。

### 我希望新版本首先得到的结果

例如：

```
{
  "mode": "generate",
  "target": "json_parse",
  "strategy_status": "valid",
  "execution_preflight": "allowed",
  "semantic_verified": false,
  "code_generated": true,
  "build_success": true,
  "runtime_passed": true,
  "fuzz_effective": "unknown",
  "unresolved_contracts": [
    "cleanup_internal_effect_unverified"
  ],
  "feedback_iteration": 0
}
```

这代表一个已经生成和运行的 Harness 候选，而不是正式证明了它的全部语义正确性。

`feedback_iteration=0` 只是未来可扩展的元数据，不应触发任何新的生成任务。

## 十一、可以直接提供给 Codex 的重构提示词

下面这份任务适合先交给 Codex 完成 PR-01 至 PR-03。PR-04 的 Lightweight API Context 可以在基本生成链路验收后再做，避免一次性修改过多模块。

```

项目：Luchutong/harness_generation
基线：当前本地 v0.4-orchestration 工作区

任务：
将 HG 从 Semantic-Proof-First 调整为
Harness-Generation-First。

本轮主要目标：
优先生成可编译、可运行的 C/C++ libFuzzer Harness。
不再要求提前证明目标库内部全部复杂内存管理实现。

严格保留现有正式语义认证路径。
禁止通过伪造 proof、修改已签发标签、删除必要检查
或将 unknown 写成 proved 的方式提高生成成功率。

一、开发前审计

1. 阅读当前工作区的真实代码与最新报告。
2. 理清以下模块的调用与数据流：
   - orchestration/controller.py
   - orchestration/services.py
   - strategy_context/gate.py
   - semantic_effects/verifier.py
   - harness_strategy/
   - context_generation/draft_builder.py
   - context_generation/strategy_generation.py
   - context_generation/strategy_publication.py
   - orchestration/quality.py
3. 明确哪些现有条件阻止 DraftPlan 和代码生成。
4. 识别已有 deterministic canonical translator。
5. 不以远端 Git HEAD 替代本地未提交源码。
6. 建立新开发分支，保留当前版本的实验结果和身份。

二、引入 Generation-First 主模式

设计独立 mode=generate。

新模式流程：

Target + Existing FT/Strategy
    → API Contract
    → Execution Preflight
    → ExecutablePlan
    → Deterministic Translation
    → Build
    → Runtime Smoke
    → Result

本阶段先复用现有 FT 和 Strategy，
不重构 Candidate/Slice。

不得将完整 Semantic Obligation Graph 闭合作为
新模式生成代码的必要条件。

三、实现 Execution Preflight Gate

必须检查：
- Strategy schema
- API symbol 与源码身份
- Clang ABI、参数数量与类型
- 资源来源及参数绑定结构
- 明确的非法调用顺序
- 有可信依据的已知 API 契约冲突
- 当前 source/build/recipe 身份

契约状态区分：
SATISFIED / VIOLATED / UNKNOWN。

VIOLATED：
拒绝生成。

UNKNOWN：
保留风险与来源，可以允许候选进入
受控编译运行，但不得标记已证明。

不允许把 may-alias、may-flow 转换为 must 证明。

四、分离 Plan 身份

正式 Verified FrozenPlan 维持现有严格语义。

新增 ExecutablePlan 或复用独立 DraftPlan 构建机制，
要求：

- 保存真实 Strategy/FT 或等价授权身份
- 保存 API Contract 和未知前提
- 保存源码与编译身份
- 保存可重放的确定性翻译输入
- 保持 semantic_verified=false，除非另行通过正式 Gate
- 不修改旧 generation_allowed 的含义

五、确定性生成 Harness

优先使用已有 canonical translator。

对于可表达的 Strategy：
直接生成 C/C++ libFuzzer harness。

默认不请求代码 LLM。

生成的代码必须与 Strategy 的 API、参数、顺序、
guard、输入限制、资源绑定与 cleanup 一致。

不允许编译失败后私自修改 Plan。

六、编译与运行

复用现有真实 recipe 和 sandbox runner。

保存：
- plan/code/source/recipe digest
- compile and link command
- compiler diagnostics
- sanitizer results
- runtime exits and timeouts
- target execution observations
- quality status and uncertainties

必须分开：
- code_generated
- build_success
- runtime_passed
- fuzz_effective
- semantic_verified

没有有效性观察时返回 unknown。

已知 NULL handle 导致提前返回的调用
不得冒充有效 fuzz processing。

七、单次生成控制器

本轮只支持一次生成尝试：

Strategy → Plan → Code → Build → Runtime → Stop。

不实现：
- 根据 build error 自动重新生成
- 根据 sanitizer 失败重新规划
- 根据 coverage 打分并再生成
- Feedback Controller
- 自动多轮 Strategy 搜索

保存完整失败原因，为以后 Feedback 留数据接口即可。

八、保留原有正式路径

mode=verify 维持：
Effect Verifier
→ Mandatory Obligation Graph
→ Strict Gate
→ Verified FrozenPlan。

已有正式 proof、publication 和 checkpoint 认证
不得被新 generate 模式污染。

SVF 可用于辅助证据，但不是默认生成前置依赖。

九、必须执行的验收

正例：
1. json_parse 已保存合法 Strategy
   在 Context 仍有未闭合根时生成并运行 Harness。

2. 合法 create → use → cleanup
   可以生成可执行代码。

3. 简单 bytes/size parser
   不需要额外的代码 LLM 生成调用。

负例：
1. 错误 ABI 或参数类型必须拒绝。
2. 确定错误的资源绑定必须拒绝。
3. 已证实违反必要前置条件的 NULL handle 不得放行。
4. 错误调用顺序不得被标记为已验证。
5. 已知 double-free/UAF 协议错误不得被认证。
6. 目标运行崩溃不能自动判定为 Harness 错误。
7. unknown ownership 不能改写成 proved。
8. 新模式不能修改旧 Verified Gate 的正式许可。
9. 不得在 build/runtime 后触发新一次模型生成。

十、交付内容

1. 变更设计文档
2. 新旧数据流图
3. 修改文件列表
4. 新 CLI 参数与兼容关系
5. ExecutablePlan schema
6. Execution Preflight 规则
7. 真实编译运行结果
8. 正反例测试
9. 与旧正式路径的回归对照
10. 尚未支持的功能与下一阶段 Feedback 接口说明

先审计并实施最小必要修改。
优先复用现有代码，避免新建平行的完整流水线。

```

## 十二、关于未来 Feedback 闭环，我建议现在只保留什么？

虽然本轮不实现反馈驱动再生成，但应避免以后再次大规模重构。

建议在生成结果中保留以下信息：

```
HarnessCandidate
 ├── Target / FT / API Scope
 ├── Strategy ID
 ├── ExecutablePlan ID
 ├── Generated Code
 ├── Compiler Diagnostics
 ├── Runtime / Sanitizer Diagnostics
 ├── Target Execution Evidence
 ├── Coverage Artifacts（如实际收集）
 └── Quality Measurements
```

这些数据将来可以用于判断：

- 编译失败是缺头文件、类型错误还是链接问题；
- Harness 为什么只执行了目标的错误返回路径；
- 输入是否真正影响目标程序行为；
- Harness 是否存在明显资源使用问题；
- 哪个 Strategy 比较适合继续优化。

下一阶段才引入：

`Execution Report → Feedback Analyzer → Strategy Replanning → New Harness`

届时还需要专门设计如何避免模型通过固定输入、提前返回或跳过复杂 API 来“刷高”质量评分。

现在不要提前实现这套评分和优化系统。

## 十三、如何判断这次方向调整是否成功？

我建议首轮只选择三个目标：

| 目标                              | 希望验证的能力                                  |
| ------------------------------- | ---------------------------------------- |
| `json_parse`                    | 已有有效 Strategy 不再被复杂 cleanup 证明阻断         |
| Expat                           | 合法 parser 创建、解析和释放，并排除 NULL parser 的无效候选 |
| 一个简单 create/use/destroy fixture | 生成链路、资源绑定及已知非法调用的基础正确性                   |

这三个目标足以判断新的主链是否可用，不需要立刻重新运行全部五类复杂结构目标。

如果这三个测试通过，再使用相同的新版本运行多次 fresh 实验，明确区分：Candidate/Slice 失败、Strategy 失败、编译失败、运行失败以及有效 Harness 交付。

当前最新 188 文件版本还没有统一全链验收，所以新的 `generate` 模式必须先在冻结 fingerprint 下建立自己的基线。

### 最后建议

不要再把“完整证明复杂 C 库内部语义”作为 Harness Generation 的基础前提。

我建议 HG 以三个彼此独立的能力模块为长期架构：

1. Harness Generator（当前主线）：LLM 结合静态分析生成可编译、可运行的 Harness。
2. Harness Evaluator（当前基础实现、未来完善）：衡量可执行性、稳定性、实际目标执行和覆盖表现。
3. Feedback Optimizer（以后再开发）：根据评估结果修改 Strategy，迭代产生更好的 Harness。

原来的 `Semantic Effect Verifier`、SVF 和 Formal Obligation Graph 可以继续作为高级语义认证能力存在，但不再占据整个生成系统的核心控制地位。

这样调整后，HG 的研究问题就会重新聚焦于：

如何让 LLM 利用真实代码结构、API 调用契约和有限静态分析，生成实际可执行的高质量 Fuzz Harness，并最终利用测试反馈改进其质量。

这比继续试图自动证明整个 C 库的内存管理实现，更贴近你最初的自动化漏洞挖掘目标，也更容易设计出能够客观比较的实验。/home/luchitong/work/HG/docs/fix2_plan