你正在维护一个“LLM + Fuzz Harness Generation”的科研原型项目。

当前项目已经完成了 C 源代码分析、函数抽取、函数角色标注、结构数据流分析以及 Structural Flow Graph（SFG）构建。

当前已经可以得到如下 artifacts：

artifacts/simple/
├── annotations.json
├── candidates.json
├── flows.json
├── functions.json
├── sfg.dot
└── sfg.json

现在请你在现有代码基础上继续实现 SynapseFlow 风格的后续框架：

SFG
 ↓
Function Triplet Extraction
 ↓
Function Triplets
 ↓
Stage 1: Function Documentation Generation
 ↓
Stage 2: Structure Snippet Stitching
 ↓
Stage 3: Rough Code Assembly
 ↓
Stage 4: Harness Optimization / Transformation
 ↓
Validation
 ↓
Staged Rollback
 ↓
Final libFuzzer Harness

这是一个科研原型，不要求一次做到论文完整性能，但要求：
1. 架构清晰；
2. 中间产物全部可检查；
3. 各阶段可以独立执行；
4. 可以替换 LLM；
5. 可以逐步加入新的评分、反馈、coverage feedback；
6. 优先保证 Function Triplet Extraction 正确；
7. 不破坏当前已经存在的 SFG pipeline。

============================================================
一、首先分析当前仓库，不要立即重写
============================================================

开始编码前先完成以下工作：

1. 阅读整个仓库结构。
2. 找到当前：
   - function extraction
   - candidate detection
   - annotation
   - structural flow inference
   - SFG generation
   的实现位置。
3. 阅读真实的：
   artifacts/simple/functions.json
   artifacts/simple/annotations.json
   artifacts/simple/flows.json
   artifacts/simple/sfg.json

非常重要：

不要根据下面的示例擅自假设 JSON schema。

必须首先读取当前项目实际 JSON 数据结构，然后设计兼容层。

优先复用当前已有：
- dataclass
- model
- config
- JSON loader
- CLI
- logger
- LLM client

如果已有相应组件，不要创建平行的重复实现。

完成分析后，再进行代码修改。

不要破坏现有命令的行为。

============================================================
二、总体架构目标
============================================================

请在当前代码风格下建立类似以下职责分层。

实际目录名称可以根据当前项目结构适配，不要求机械照抄：

harness_generation/
    models/
        function.py
        flow.py
        triplet.py
        generation.py

    graph/
        sfg_loader.py
        triplet_extractor.py

    generation/
        stage1_docs.py
        stage2_snippets.py
        stage3_assembly.py
        stage4_harness.py
        orchestrator.py

    validation/
        intermediate.py
        compiler.py
        runtime.py

    llm/
        base.py
        provider.py
        prompts.py

    pipeline/
        harness_pipeline.py

核心原则：

SFG construction 与 Harness Generation 解耦。

上游输出：
    functions.json
    annotations.json
    flows.json
    sfg.json

下游首先产生：
    triplets.json

Harness Generation 不应该重新分析整个项目，而应该主要围绕：

    FunctionTriplet
        +
    functions metadata
        +
    relevant source code

执行。

============================================================
三、实现 Function Triplet 数据模型
============================================================

实现明确的 FunctionTriplet 数据模型。

论文定义：

FT = (I, P, H)

I:
    一个且只有一个 ISF
    Input Stream Function

P:
    0 个或多个 PRF
    Process Functions

H:
    0 个或多个 HPF
    Helper Functions

一个 source project 可以产生多个 FT。

一个 FT 必须由唯一 ISF anchor。

建议 FunctionTriplet 至少保存：

- id
- isf
- prfs
- hpfs
- functions
- structures
- edges
- metadata

其中不要只保存函数名。

应尽量保留 structural flow：

{
    "function": "...",
    "src": "...",
    "dst": "...",
    "roles": [...]
}

这样 Stage 2 可以直接利用数据流关系。

如果当前 sfg.json 已包含更多信息，应保留有用字段，而不是降级信息。

triplets.json 必须是稳定、可序列化、可重复生成的中间产物。

保证同一个输入多次运行时：
- FT id 稳定
- 函数顺序稳定
- JSON 顺序稳定

方便 git diff 和实验复现。

============================================================
四、实现论文 Algorithm 1：Function Triplet Extraction
============================================================

这是当前优先级最高的任务。

根据论文 Section 3.2.3，实现 Function Triplet Extraction。

对于每一个 ISF f_isf：

    newG = SFG with other ISF edges pruned

    InNodes =
        ancestors(input_struct)
        ∪ {input_struct}

    OutNodes =
        descendants(output_struct)
        ∪ {output_struct}

    FTGraph =
        subgraph(InNodes ∪ OutNodes)

    PRFs =
        functions on FTGraph edges
        whose annotation contains PRF

    HPFs =
        functions on FTGraph edges
        whose annotation contains HPF
        and which are not already treated as PRF

    FT =
        (current ISF, PRFs, HPFs)

最终：
    one unique ISF → one FunctionTriplet

需要特别实现以下问题。

------------------------------
4.1 其他 ISF 隔离
------------------------------

生成某一个 ISF 的 FT 时，不允许其他独立 ISF 继续作为新的 input entry point 混进这个 FT。

例如：

ByteStream
   │
   ├─ parse_from_memory [ISF]
   │        ↓
   │      Image
   │
   └─ parse_from_file [ISF]
            ↓
          Image

应该产生两个 FT，而不是：

parse_from_memory
parse_from_file
decode
free

全部塞进一个 FT。

目标是：

FT1:
    parse_from_memory
    relevant PRFs
    relevant HPFs

FT2:
    parse_from_file
    relevant PRFs
    relevant HPFs

------------------------------
4.2 multi-role function
------------------------------

函数可能同时具有：

ISF + HPF
ISF + PRF
PRF + HPF

不要假设角色互斥。

论文特别指出：

如果最终 FT 中某函数同时是 PRF 和 HPF，
Generation priority 按 PRF 处理。

另外：

对“其他 ISF”进行 pruning 时，如果一个函数同时拥有其他角色，
不要粗暴丢失所有语义。

建议内部建立 role-aware graph view：
- mask/remove ISF role
- 尽量保留其允许作为 PRF/HPF 的语义

请结合当前 annotations.json 的真实表示实现。

------------------------------
4.3 Multi-edge
------------------------------

检查当前 SFG 是否允许：

StructA --func1--> StructB
StructA --func2--> StructB

如果允许多个函数拥有相同 src/dst，不要使用会覆盖 edge 的简单表示。

如果使用 networkx，优先考虑 MultiDiGraph。

如果当前项目已经实现自己的 graph representation，则复用它。

必须增加单元测试：

A -> B via func1
A -> B via func2

FT extraction 后两个函数都不能丢失。

------------------------------
4.4 null structure
------------------------------

论文 SFG 中存在特殊 "(null)" node。

当前项目可能使用：
null
NULL
(null)
__NULL__
None

不要直接硬编码。

读取现有 SFG representation，并建立统一 normalization。

注意：

共享 null node 可能对 ancestors()/descendants() 产生很宽的 reachable set。

论文没有充分描述该 corner case。

因此：

1. 默认尽可能保持论文 Algorithm 1 的行为；
2. 将 null handling 封装在独立函数；
3. 不要偷偷加入复杂 heuristic；
4. 如果发现当前数据中 null 会明显导致整个图错误聚合，在 README / code comment 中记录；
5. 为以后改进保留扩展点。

============================================================
五、生成 triplets.json
============================================================

新增 pipeline：

annotations.json
flows.json
sfg.json
functions.json
       ↓
FunctionTripletExtractor
       ↓
triplets.json

建议输出：

artifacts/simple/triplets.json

必要时同时输出：

artifacts/simple/triplets/
    ft_0001.json
    ft_0002.json
    ...

但 triplets.json 必须作为 canonical output。

每个 FT 最少需要能够回答：

1. 谁是唯一 ISF？
2. 哪些 PRF 与它相关？
3. 哪些 HPF 与它相关？
4. 涉及哪些 structure？
5. 每个 function 对应什么 structural flow？
6. 从 fuzz input 到内部结构的大致数据链是什么？

提供 CLI。

请优先沿用当前 CLI 体系。

如果当前项目没有统一 CLI，可以加入类似：

python -m harness_generation triplets \
    --artifacts artifacts/simple

或者：

python main.py triplets \
    --project simple

不要硬编码 simple。

============================================================
六、加入 FT inspection 功能
============================================================

为了科研调试，非常需要人可以检查 FT。

增加：

python ... triplets show --id ft_0001

输出类似：

Function Triplet: ft_0001

ISF:
    mp_parse
    ByteStream -> mp_context

PRFs:
    mp_execute
        mp_context -> mp_result

    mp_query
        mp_result -> NULL

HPFs:
    mp_destroy
        mp_context -> NULL

Structures:
    ByteStream
    mp_context
    mp_result

Edges:
    ...

同时增加简易统计：

#functions
#ISFs
#PRFs
#HPFs
#FTs
average functions per FT
max FT size

这对后续实验非常重要。

============================================================
七、Stage 1：Function Documentation Generation
============================================================

FT extraction 完成后实现 Harness Generation Phase。

首先实现 Stage 1。

输入：

FunctionTriplet
+
functions.json 中相关函数信息
+
函数真实 source code

注意：
只给 LLM 当前 FT 相关函数，
不要把整个项目源码全部塞给模型。

对于 FT 中每一个 function，让 LLM 生成结构化 documentation：

- function signature
- functionality
- application scenario
- example invocation
- parameter notes
- return semantics（如果能从源码可靠判断）
- resource/lifecycle notes（如果能从源码可靠判断）

核心 prompt 与论文 Appendix B.4 保持同一思想：

Analyze the function's functionality and provide an example call
according to its usage scenario.

不要要求 LLM 重新定义函数。

不要让 LLM 发明不存在的 API。

Stage 1 输出不要只保存 markdown。

优先使用 JSON：

artifacts/<project>/generation/<ft_id>/stage1_docs.json

例如：

{
  "function": "foo",
  "signature": "...",
  "functionality": "...",
  "application_scenario": "...",
  "example_code": "...",
  "notes": [...]
}

原始 LLM response 可另外保存用于科研分析：

raw/
    stage1_foo.txt

============================================================
八、Stage 2：Structure Snippet Stitching
============================================================

Stage 2 不直接生成整个 Harness。

根据 FT edges 建立 structural processing units。

典型：

ByteStream -> Context
Context -> Object
Object -> NULL

对每一个结构转换 unit 生成局部代码 snippet。

例如：

ByteStream -> Context

涉及：
    mp_init
    mp_parse

LLM 只解决这个局部问题。

另一个：

Context -> Object

涉及：
    mp_create_object
    mp_process_object

生成另一个 snippet。

processing unit 至少保存：

- input_structure
- output_structure
- functions
- dependencies
- generated_code

建议把相同 structural transformation：

(src, dst)

上的相关函数组织为同一 unit，
但必须保留所有函数，不得因为 src/dst 相同而覆盖。

Stage 2 输出：

stage2_snippets.json

以及方便阅读的：

snippets/
    unit_0001.c
    unit_0002.c

Prompt 必须明确：

- 只能使用提供的函数；
- 必须调用承担该 unit 结构步骤的函数。只有存在直接委托证据的同端点函数才构成
  同一步骤的可替代实现（例如 `json_parse` 委托给 `json_parse_ex`）。每个独立步骤
  都需实现；同一步骤的可替代函数调用其中之一即可；
- 不得重新实现目标函数；
- 不得发明 API；
- 只生成 C，不生成 C++；
- 优先使用正常 API usage；
- 保持代码局部、简洁；
- 不要负责最终 LLVMFuzzerTestOneInput wrapper。

保存 prompt 和 raw response，方便以后做实验。

============================================================
九、Stage 3：Rough Code Assembly
============================================================

根据 SFG / FT 的 structural dependencies 合并 Stage 2 snippets。

目标不是立即生成最终 Harness，而是：

rough but complete code sequence

要求：

- 尽量包含 FT 的全部必要函数；
- 数据结构初始化顺序正确；
- output structure 正确传给后续 input structure；
- cleanup 顺序合理；
- 不重新定义项目 API。

按照 SFG dataflow 顺序逐步 merge snippets。

不要简单字符串 concat。

LLM 应该看到：

snippet A
snippet B
对应 input/output structures
函数 metadata
dependency information

然后生成合并后的代码。

输出：

stage3_rough.c
stage3_metadata.json

metadata 至少记录：

- invoked_functions
- missing_functions
- unexpected_functions
- involved_structures

============================================================
十、Stage 4：Harness Optimization / Transformation
============================================================

把 Stage 3 rough code 转换成真正 libFuzzer harness。

最终目标：

int LLVMFuzzerTestOneInput(
    const uint8_t *data,
    size_t size
) {
    ...
    return 0;
}

Stage 4 的职责：

1. 接入 data / size；
2. 删除与 fuzzing 无关的固定输入；
3. 删除 printf/fprintf 等无意义 logging；
4. 尽量避免无必要 file I/O；
5. 删除测试/demo main；
6. 保证必要初始化；
7. 保证 resource cleanup；
8. 不定义目标库中已有函数；
9. 不调用不存在的 API；
10. 保持 C syntax；
11. 不生成 C++ constructs；
12. 保持 FT 唯一 ISF 作为主要 external-input entry。

输出：

stage4_harness.c

最终稳定版本可复制/链接到：

artifacts/<project>/harnesses/<ft_id>.c

============================================================
十一、LLM Provider 抽象
============================================================

不要把具体模型 API 写死到 Stage 类里。

建立统一接口，例如：

class LLMClient:
    generate(...)

或者沿用项目现有 interface。

Stage 只依赖 abstraction：

LLMClient

以后应该可以替换：

OpenAI-compatible endpoint
local model
mock client
recorded response

配置至少支持：

model
base_url
api_key env name
temperature
max_tokens
timeout

不要在 git 中写入任何 API key。

如果当前项目已经存在 LLM client，优先复用。

为了 CI/unit test：

实现 MockLLM / FakeLLM。

测试不得依赖真实网络 API。

============================================================
十二、Prompt Template 独立管理
============================================================

不要把长 prompt 散落在 Python source 中。

建立：

prompts/
或者
generation/prompts.py

至少包含：

stage1_function_doc
stage2_structure_snippet
stage3_rough_assembly
stage4_harness_transform

每一个 prompt 应：

- 参数化；
- 可单独打印；
- 可保存；
- 可版本化。

Generation result metadata 中记录：

prompt_version

例如：

"prompt_version": "stage2-v1"

这是科研项目，未来需要比较 prompt strategy。

============================================================
十三、Intermediate Validation
============================================================

论文强调中间阶段验证。

实现 validation framework。

第一版不用过度复杂，但至少检查：

1. expected function 是否出现；
2. unexpected function call；
3. duplicate function definitions；
4. 明显 C++ syntax；
5. 是否出现禁用 I/O / logging；
6. 是否重新定义目标函数；
7. 是否引用明显不存在的目标 API。

不要仅用字符串 contains。

能用当前 tree-sitter parser 的地方尽量复用 tree-sitter。

定义统一结果：

ValidationResult {
    success
    errors
    warnings
    metadata
}

每一次 validation 都写入：

validation.json

============================================================
十四、Compiler Validation
============================================================

Final harness 需要支持 compilation validation。

但不同 C 项目的编译方式不同，
因此不要把：

clang harness.c ...

硬编码到 pipeline 中。

建立：

CompilerValidator / BuildAdapter

支持 config 指定：

include paths
library paths
compiler flags
link flags
build command

如果没有项目 build config：

至少提供 syntax-only fallback：

clang -fsyntax-only

如果由于缺少 target library link 信息无法完整 linking：

明确返回：

syntax_valid = true
link_validation = unavailable

而不是把 unavailable 当失败。

保存：

stdout
stderr
return_code
command

============================================================
十五、30 秒 Smoke Test 接口
============================================================

论文最终 harness 除 compilation 外还运行基本 runtime test。

建立 RuntimeValidator。

默认接口支持：

timeout = 30s

但不要假定所有项目当前都可以完整编译执行。

如果 executable 可用：

执行 smoke test。

如果 unavailable：

明确标记：

status = skipped
reason = ...

不要伪造成功。

============================================================
十六、Staged Rollback
============================================================

建立 Pipeline Orchestrator / State Machine。

Stages：

STAGE_1_DOCS
STAGE_2_SNIPPETS
STAGE_3_ROUGH
STAGE_4_HARNESS

每个 stage：

input
run()
validate()
persist()
checkpoint()

后续失败可以回滚。

主要行为：

Stage 4 validation failure：
    从最近可靠 checkpoint 重新生成 Stage 4

多次失败：
    rollback 到 Stage 3

继续失败：
    rollback 到 Stage 2

再失败：
    rollback 到 Stage 1

设：

max_regen_per_level = 3

参数可配置。

注意：

论文 Algorithm 2 的伪代码与其文字描述在初始 rollback target 的表达上存在一定不一致。

论文正文的语义是：

Stage 4 失败时，不全部重启，
先利用 Stage 3 已有结果重新生成 Stage 4；
持续失败再逐步回滚到 Stage 2 / Stage 1。

本项目第一版请按照这一“正文描述的行为语义”实现。

同时：

- 把 rollback strategy 封装；
- 在 docs 中注明这一选择；
- 不把逻辑散落在各个 Stage 中。

保存 pipeline state：

pipeline_state.json

例如：

{
    "ft_id": "ft_0001",
    "current_stage": 4,
    "attempt": 2,
    "rollback_level": 3,
    "history": [...]
}

这样程序中断后未来可以支持 resume。

============================================================
十七、Artifact-first 设计
============================================================

这个项目用于科研，所以所有重要过程必须留痕。

最终目录建议：

artifacts/simple/
├── annotations.json
├── candidates.json
├── flows.json
├── functions.json
├── sfg.json
├── sfg.dot
├── triplets.json
├── triplets/
│   ├── ft_0001.json
│   └── ...
├── generation/
│   └── ft_0001/
│       ├── stage1_docs.json
│       ├── stage2_snippets.json
│       ├── stage3_rough.c
│       ├── stage3_metadata.json
│       ├── stage4_harness.c
│       ├── validation.json
│       ├── pipeline_state.json
│       ├── prompts/
│       └── raw/
└── harnesses/
    └── ft_0001.c

如果当前 artifact 管理已经有统一模式，
请适配当前模式，而不是机械创建这一结构。

============================================================
十八、测试
============================================================

必须加入 tests。

优先测试 FunctionTripletExtractor。

至少构造以下 synthetic graph case：

Case A：最简单链

ByteStream --parse[ISF]--> Context
Context --process[PRF]--> Result
Result --consume[PRF]--> NULL
Context --destroy[HPF]--> NULL

期望一个 FT：

I = parse
P = process, consume
H = destroy

Case B：两个 ISF 共享后续结构

parse_memory[ISF] -> Context
parse_file[ISF]   -> Context
Context -> process[PRF] -> Result
Context -> destroy[HPF] -> NULL

期望：

两个独立 FT，
每个只有一个 ISF。

Case C：multi-role

parse:
    ISF + HPF

transform:
    PRF + HPF

transform 在最终分类中应该优先进入 PRF。

Case D：parallel edges

Context --foo[PRF]--> Result
Context --bar[PRF]--> Result

foo 和 bar 都必须保留。

Case E：empty PRF / HPF

允许：

FT = (ISF, [], [])

不能 crash。

Case F：cycle

A -> B
B -> A

不能因为 traversal 无限循环。

行为需要 deterministic。

另外测试：

serialization
stable FT ids
CLI
MockLLM pipeline

不得让 unit tests 调用真实 LLM API。

============================================================
十九、CLI 最终目标
============================================================

希望至少能做到类似：

# Phase 1
python ... triplets --artifacts artifacts/simple

# 查看
python ... triplets show \
    --artifacts artifacts/simple \
    --id ft_0001

# 单独运行某一 FT
python ... generate \
    --artifacts artifacts/simple \
    --ft ft_0001

# 执行完整生成
python ... generate-all \
    --artifacts artifacts/simple

# 只执行到某阶段
python ... generate \
    --ft ft_0001 \
    --until-stage 2

# 未来允许 resume
python ... generate \
    --ft ft_0001 \
    --resume

实际 CLI syntax 应尽量遵循当前项目。

============================================================
二十、Logging
============================================================

为 pipeline 增加清晰日志。

例如：

[FT] Loading SFG...
[FT] Found 3 ISFs
[FT] Extracting ft_0001 anchor=mp_parse
[FT]   PRF=4 HPF=2 structs=3
[FT] Wrote artifacts/simple/triplets.json

[GEN][ft_0001][S1] generating function docs
[GEN][ft_0001][S2] generating 3 structural units
[GEN][ft_0001][S3] assembling rough code
[GEN][ft_0001][S4] generating libFuzzer harness

[VALIDATE] compile failed
[ROLLBACK] stage4 -> stage3 checkpoint
...

不要打印 API key 或敏感环境变量。

============================================================
二十一、README / Documentation
============================================================

更新项目文档。

增加：

docs/HARNESS_PIPELINE.md

内容说明：

Source Code
 ↓
Function Extraction
 ↓
Annotation
 ↓
Structural Flow
 ↓
SFG
 ↓
Function Triplet Extraction
 ↓
FT
 ↓
Stage 1 Docs
 ↓
Stage 2 Structural Snippets
 ↓
Stage 3 Rough Assembly
 ↓
Stage 4 Harness
 ↓
Compile / Smoke Test
 ↓
Rollback if needed

解释：

ISF
PRF
HPF
SFG
FT
processing unit
checkpoint
rollback

尤其解释：

为什么 one ISF → one FT → one harness。

============================================================
二十二、不要做的事情
============================================================

本轮不要：

- 重写已经工作正常的 SFG pipeline；
- 加入大型数据库；
- 加入复杂 Web UI；
- 加入 Docker 依赖；
- 引入 Celery/Redis 等任务系统；
- 实现覆盖率反馈优化；
- 自动 fuzz 24 小时；
- 自动漏洞 exploit；
- 盲目增加复杂 agent framework；
- 为了“架构漂亮”把原项目大规模重构。

目标是科研原型的最小完整 pipeline。

尤其不要把所有逻辑重新塞回一个巨大 main.py。

============================================================
二十三、开发优先级
============================================================

请按照以下顺序实际开发，而不是一次性堆大量空壳：

P0:
FunctionTriplet model
SFG loader / adapter
FunctionTripletExtractor
triplets.json
unit tests
CLI

确认测试通过后：

P1:
LLM abstraction
Stage 1
Stage 2
artifacts persistence

然后：

P2:
Stage 3
Stage 4

最后：

P3:
validation
compile adapter
runtime validator
rollback orchestrator

但是最终提交应保证即使没有 LLM API key：

Function Triplet Extraction 仍然完全可运行。

LLM stages 可以：
- 使用 MockLLM 运行测试；
- 或明确报出 missing configuration。

============================================================
二十四、Acceptance Criteria
============================================================

本次任务完成的最低标准：

现有：

artifacts/simple/
├── annotations.json
├── candidates.json
├── flows.json
├── functions.json
├── sfg.dot
└── sfg.json

能够执行一个明确命令生成：

artifacts/simple/triplets.json

并且能够：

1. 自动识别所有 ISF；
2. 一个 ISF 对应一个 FT；
3. 获取相关 PRF；
4. 获取相关 HPF；
5. 保留 structural flow；
6. 不丢失 parallel edges；
7. 正确处理 multi-role；
8. 有单元测试；
9. deterministic；
10. 可 human inspect。

随后整个 Stage 1-4 pipeline 至少架构完整，
且可以使用 MockLLM 在 test fixture 上跑通：

FT
→ Stage 1
→ Stage 2
→ Stage 3
→ Stage 4
→ validation

如果当前 simple target 配置足以真实编译，
再执行真实 compile validation。

如果信息不足，不要伪造。

============================================================
二十五、执行方式
============================================================

现在开始工作。

先：

1. inspect repository；
2. inspect 当前 JSON schemas；
3. 总结你发现的现有数据模型和代码入口；
4. 给出简短 implementation plan；
5. 然后直接开始实现，不要停下来等待确认。

每完成一个主要模块后运行相关 tests。

修改完成后：

- 运行现有 test suite；
- 运行新增 tests；
- 用 artifacts/simple 做一次真实 FT extraction；
- 展示生成的 triplets.json 摘要；
- 如果条件允许，用一个 FT 跑 Mock/real Stage 1-4；
- 检查 git diff；
- 不要自动 push。

最后向我报告：

1. 新增/修改了哪些文件；
2. Function Triplet Extraction 如何实现；
3. 当前 simple target 提取出多少个 FT；
4. 给出其中 1~2 个 FT 的 ISF/PRF/HPF；
5. Stage 1-4 哪些已真实实现、哪些只是接口；
6. validation/rollback 当前支持到什么程度；
7. 测试结果；
8. 下一步最值得实现的内容；
9. 当前发现的设计问题或数据质量问题。

代码应优先追求：
correctness
> observability
> reproducibility
> extensibility
> cleverness

不要为了缩短代码牺牲中间结果的可观测性。
