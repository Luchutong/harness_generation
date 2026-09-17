你正在维护项目：

/home/luchitong/work/harness_generation

当前系统已经完成：

C Source
→ Function Extraction
→ Annotation
→ Structural Flow
→ SFG
→ Function Triplet Extraction
→ Stage 1 Function Documentation
→ Stage 2 Structure Snippet Stitching
→ Stage 3 Rough Code Assembly
→ Stage 4 libFuzzer Harness
→ Validators
→ Rollback / Resume

当前 simple target 已经可以稳定提取：

FT:
    ft_parser_from_memory_a5265df23ba0

ISF:
    parser_from_memory

PRF:
    parser_next
    node_process

HPF:
    parser_from_memory
    parser_free

Data flow:
    fuzz_input -> Parser -> Node

当前完整测试：

206 passed
54 subtests passed

============================================================
本轮唯一目标
============================================================

不要继续扩展架构。

本轮目标是把现有组件串成第一次真实 end-to-end 闭环：

simple source
    ↓
SFG
    ↓
Function Triplet
    ↓
REAL LLM
    ↓
Stage 1
    ↓
Stage 2
    ↓
Stage 3
    ↓
Stage 4
    ↓
Intermediate / AST validation
    ↓
Compile
    ↓
Link
    ↓
Runtime smoke test
    ↓
短时间 libFuzzer smoke fuzz
    ↓
Success

如果某阶段失败：

validation failure
    ↓
orchestrator
    ↓
automatic rollback
    ↓
regeneration
    ↓
revalidation

本轮必须完成的核心能力：

1. validator 真正驱动 orchestrator
2. simple target 可以真实 compile + link
3. 使用真实 LLM 跑 Stage 1–4
4. 产生真正可执行的 libFuzzer binary
5. 做很短时间 fuzz smoke test
6. 完整保存 generation / validation / rollback / fuzz artifacts

不要做 coverage feedback 优化。
不要做长时间 fuzzing。
不要做 exploit。
不要重新设计 SFG。
不要重新设计 FT extraction。

============================================================
0. 开始前必须 inspect
============================================================

开始修改前先检查：

- 当前仓库结构
- simple target 源码
- simple target headers
- simple target build requirements
- Stage 1–4
- LLM abstraction/provider
- validation modules
- compiler validator
- runtime validator
- orchestrator
- rollback policy
- artifact manager
- CLI
- existing tests

重点找到：

1. generate CLI 当前如何执行 stage
2. stage validation 当前在哪里发生
3. orchestrator 如何判断 success / failure
4. rollback target 如何选择
5. compiler validator 当前是否只 syntax-only
6. simple target 如何编译成 library/object
7. 如何生成 libFuzzer executable

不要立即改代码。

先输出一个简短 implementation plan，
然后直接开始实现，不需要等待确认。

============================================================
1. 把 validator 真正接入 orchestrator
============================================================

这是本轮 P0。

当前问题：

stage-local validation 主要检查 artifact 是否存在，
而已经存在的：

- intermediate validator
- compiler validator
- linker validation
- runtime validator

还没有完整驱动 rollback。

需要把 pipeline 改成：

Stage N
    ↓
generation
    ↓
persist artifact
    ↓
validator
    ↓
ValidationResult
    ↓
orchestrator decision

统一使用现有 ValidationResult abstraction。

每个 stage 必须返回明确状态：

passed
failed
skipped
unavailable

不要把：

artifact exists

等价于：

stage passed

--------------------------------
Stage validation policy
--------------------------------

Stage 1：

检查：

- JSON 可以解析
- 所有 FT function 都有 documentation
- 不允许为空
- function name 与 FT 对应

Stage 2：

检查：

- required processing units 都存在
- expected functions 被调用
- 不出现明显 invented API
- snippet 可被 parser 解析（如果适用）

Stage 3：

检查：

- rough code 可解析
- FT 中 required functions 没有明显遗漏
- unexpected target API 被报告
- 不重复定义 target functions

Stage 4：

必须至少执行：

intermediate validation
    ↓
compiler validation
    ↓
link validation（如果配置可用）
    ↓
runtime smoke（如果 executable 可用）

只有满足 policy 后 Stage 4 才能 ACCEPT。

--------------------------------
状态语义
--------------------------------

例如：

compiler = passed
linker = unavailable
runtime = skipped

在 syntax-only 模式可以是：

passed_with_limitations

但在本轮 simple target 中：

最终目标不是 limitations。

simple 必须做到：

compiler = passed
linker = passed
runtime = passed

============================================================
2. 实现 simple target 的真实 build/link 配置
============================================================

检查：

tests/fixtures/simple_project

或实际 simple target 所在路径。

不要假设其 build command。

读取源码后确定：

- C source files
- headers
- include paths
- required compile flags

为 simple 增加最小 BuildAdapter / TargetBuildConfig。

优先复用已有 compiler abstraction。

目标是生成：

target objects/library
+
generated harness
+
libFuzzer runtime

最终产生真实 executable。

推荐 clang：

clang
    -g
    -O1
    -fsanitize=fuzzer,address,undefined
    ...

或者：

clang
    -fsanitize=fuzzer,address

根据当前环境和源码兼容性选择。

不要为了测试加入不必要 flags。

--------------------------------
Build output
--------------------------------

建议：

artifacts/simple/build/<ft_id>/

保存：

compile_commands.json 或 build.json
target objects
harness object
fuzzer executable
stdout
stderr

不要把 build 输出散落到 repo root。

--------------------------------
要求
--------------------------------

最终必须可以类似：

./artifacts/simple/build/<ft_id>/fuzzer

真实启动。

============================================================
3. Real LLM 配置
============================================================

当前 MockLLM 已经通过测试。

本轮要求：

保留 MockLLM，
同时实际跑一次真实 LLM provider。

不要把 provider 写死。

复用当前 LLM abstraction。

真实配置必须来自：

environment variables
或已有 config

例如：

LLM_BASE_URL
LLM_API_KEY
LLM_MODEL

不得：

- hardcode API key
- 打印 API key
- 将 API key 写入 artifact
- commit secret

如果项目已有 OpenAI-compatible client，
优先直接使用。

--------------------------------
CLI
--------------------------------

希望可以类似：

python -m harness_generation generate \
    --artifacts artifacts/simple \
    --ft ft_parser_from_memory_a5265df23ba0 \
    --provider openai-compatible \
    --model <model>

具体 syntax 遵循现有 CLI。

如果缺 key：

明确报：

missing LLM configuration

不要 silently fallback 到 MockLLM。

============================================================
4. Real Stage 1–4 execution
============================================================

使用：

ft_parser_from_memory_a5265df23ba0

进行第一次真实 LLM generation。

必须完整保存：

Stage 1:
prompt
response
parsed docs

Stage 2:
prompt
response
snippets

Stage 3:
attempt_NNN/
    prompt
    response
    parsed
    rough.c

Stage 4:
attempt_NNN/
    prompt
    response
    parsed
    harness.c

metadata 至少包含：

provider
model
prompt_version
attempt
timestamp
rollback source
retry reason

不要删除失败 attempt。

============================================================
5. Compile / Link Validation
============================================================

Stage 4 生成后：

首先 intermediate validation。

然后执行真实 compile。

不要只：

clang -fsyntax-only

本轮 simple 要真正编译。

建议流程：

target source
    ↓
target object/library

generated harness
    ↓
harness object

link:
target objects
+
harness
+
libFuzzer runtime
+
sanitizers
    ↓
fuzzer executable

CompilerValidator 和 LinkerValidator 必须保存：

command
return_code
stdout
stderr

--------------------------------
如果编译失败
--------------------------------

必须：

ValidationResult.failed

并将错误信息提供给 orchestrator。

注意：

不要简单把完整 compiler stderr 直接无限拼进下一轮 prompt。

设计简洁 failure context，例如：

failure_type
error summary
relevant stderr tail
failed stage

控制 prompt 长度。

============================================================
6. Runtime Smoke Test
============================================================

成功 link 后执行 runtime smoke。

不要立即 fuzz。

先验证 binary 能正常启动。

建议两层：

A. empty/small input smoke

准备：

empty input
minimal input

执行目标 binary。

B. bounded execution

timeout 30 秒以内。

记录：

return code
signal
stdout
stderr
timeout

如果：

ASan crash in target code

不能自动判定为 harness failure，
需要根据 stack / location 区分。

如果明显 crash 在 generated harness 自身：

标记 harness invalid。

第一版可使用简单规则：

- crash top frame / source path 属于 generated harness
  → validation failure

- crash clearly inside target
  → potential target crash，记录但不要因此无限 rollback

如果当前 stack parser 尚未支持，
至少保留 raw stderr，明确 status。

============================================================
7. 自动 rollback 闭环
============================================================

本轮必须实际证明：

validation failure
    ↓
rollback
    ↓
new attempt
    ↓
revalidation

不要只证明 rollback unit test。

至少做一个真实 pipeline rollback scenario。

--------------------------------
推荐策略
--------------------------------

Stage 4 compile / link failure：

第一次：
    regenerate Stage 4

持续失败达到 threshold：
    rollback Stage 3

再失败：
    rollback Stage 2

Stage 1 最后一级。

复用现有 staged rollback policy，
不要重写整个算法。

--------------------------------
Failure context
--------------------------------

rollback/retry metadata 必须记录：

failed_stage
validator
failure_type
attempt
rollback_target
reason

例如：

{
    "failed_stage": 4,
    "validator": "compiler",
    "failure_type": "compile_error",
    "rollback_target": 4,
    "reason": "undeclared identifier ..."
}

============================================================
8. 必须加入一个 controlled failure test
============================================================

仅靠“真实 LLM 恰好失败一次”不可重复。

因此增加 deterministic controlled failure test。

例如：

MockLLM / fixture：

Stage 4 attempt 1：

故意返回：

int LLVMFuzzerTestOneInput(...) {
    undefined_function();
}

Compiler validation 必须失败。

然后：

orchestrator automatically retry

Stage 4 attempt 2 返回合法 harness。

期望：

attempt_001
    compiler failed

attempt_002
    compile passed

pipeline success

这条测试必须真正经过：

generation
→ compiler validator
→ orchestrator
→ rollback/retry

不要直接 mock ValidationResult。

目标是测试真实 integration。

============================================================
9. 短时间 libFuzzer Smoke Fuzz
============================================================

当：

compile
link
runtime smoke

都成功以后，

才执行很短的 fuzz smoke。

本轮不是 fuzzing experiment。

只运行：

30–120 秒

默认建议：

60 秒

命令类似：

./fuzzer \
    -max_total_time=60 \
    -print_final_stats=1 \
    corpus/

建立最小 corpus 目录。

可以：

empty seed
+
少量 simple target 合法/半合法 seed

不要手工设计大量 seed。

--------------------------------
保存输出
--------------------------------

保存：

artifacts/simple/fuzz/<ft_id>/smoke_001/

包括：

command.txt
stdout.txt
stderr.txt
final_stats.json
corpus/
crashes/
metadata.json

至少解析：

execs_done
execs_per_sec
cov
ft
corp
crashes
ooms
timeouts

字段根据实际 libFuzzer 输出可获得情况处理。

不要伪造没有的数据。

============================================================
10. Fuzz Smoke 的 success 标准
============================================================

本轮 success 不要求：

发现漏洞
高 coverage
长期稳定

本轮只要求：

1. executable 可以运行
2. libFuzzer 初始化成功
3. 至少执行一定数量 iteration
4. 没有因为 harness 自身立即崩溃
5. 输出 final stats

例如：

execs_done > 0

即可证明闭环工作。

如果出现 target crash：

保存 crash input。

不要 exploit。

不要自动分类成漏洞。

============================================================
11. Artifact 最终布局
============================================================

尽量使用已有 ArtifactManager。

建议最终：

artifacts/simple/
├── functions.json
├── annotations.json
├── flows.json
├── sfg.json
├── triplets.json
│
├── generation/
│   └── <ft_id>/
│       ├── stage1/
│       ├── stage2/
│       ├── stage3/
│       │   ├── attempt_001/
│       │   └── ...
│       ├── stage4/
│       │   ├── attempt_001/
│       │   └── ...
│       ├── validation/
│       │   ├── intermediate.json
│       │   ├── compiler.json
│       │   ├── linker.json
│       │   ├── runtime.json
│       │   └── summary.json
│       └── pipeline_state.json
│
├── build/
│   └── <ft_id>/
│       └── fuzzer
│
└── fuzz/
    └── <ft_id>/
        └── smoke_001/

如果当前 artifact layout 不同，
以当前系统为准。

不要为了目录结构大改现有代码。

============================================================
12. Pipeline Status
============================================================

增加明确最终状态。

例如：

PipelineResult:

generated
validated
compiled
linked
runtime_checked
fuzz_smoke_completed

以及：

success
failure_reason

CLI 最终应打印清晰摘要：

FT:
  ft_parser_from_memory_a5265df23ba0

Generation:
  Stage1: passed
  Stage2: passed
  Stage3: passed
  Stage4: passed

Validation:
  Intermediate: passed
  Compiler: passed
  Linker: passed
  Runtime: passed

Rollback:
  Attempts: 2
  Deepest rollback: Stage4

Fuzz smoke:
  Duration: 60s
  Executions: ...
  Exec/s: ...
  Coverage: ...

Result:
  SUCCESS

============================================================
13. CLI 目标
============================================================

希望最终可以执行一个命令：

python -m harness_generation run \
    --artifacts artifacts/simple \
    --ft ft_parser_from_memory_a5265df23ba0 \
    --real-llm \
    --build \
    --smoke-fuzz \
    --fuzz-seconds 60

具体 CLI syntax 遵循现有设计。

不要为了满足示例重复创建一套 CLI。

至少应该有：

只 generate
generate + validate
完整 e2e

三种能力。

============================================================
14. 测试要求
============================================================

必须增加/更新：

A. validator → rollback integration test

B. Stage4 compile fail → retry → success test

C. simple target real compile/link test
   如果 CI 环境 clang/libFuzzer 可用则运行；
   否则合理 skip，并说明原因。

D. runtime smoke validator test

E. fuzz runner parser test

F. artifact persistence test

G. existing Mock E2E regression

不得让普通 unit tests 调真实网络 LLM。

Real LLM 只在手工验收中使用。

============================================================
15. 真实手工验收
============================================================

本轮最后必须真正尝试：

simple target
+
real LLM

完整执行。

顺序：

1.
重新确认 FT：

ft_parser_from_memory_a5265df23ba0

2.
使用真实 LLM 跑 Stage 1–4

3.
执行 intermediate validation

4.
compile target + harness

5.
link libFuzzer executable

6.
runtime smoke

7.
如果前面成功：
运行 30~60 秒 fuzz smoke

--------------------------------
如果真实 LLM 调用因为：
--------------------------------

API key
网络
provider
地区
model unavailable

失败：

不要伪造 real LLM success。

继续使用 Mock pipeline 完成工程验收，
然后在最终报告明确：

REAL LLM BLOCKED BY ENVIRONMENT

并给出用户下一步只需执行的命令。

============================================================
16. 不要做的事情
============================================================

本轮不要：

- 长时间 fuzzing
- 24h experiment
- coverage feedback optimization
- Harness scoring
- mutation strategy
- exploit generation
- crash exploitability analysis
- 多项目 benchmark
- 重写 SFG
- 重写 FT extractor
- 加数据库
- 加 Web UI
- 加 agent framework
- 加 Docker 依赖
- 自动 push

这轮只解决：

“现有 Harness Generation 框架是否真的能闭环运行？”

============================================================
17. 安全与执行边界
============================================================

只使用仓库自带的 simple target。

不要自动下载或 fuzz 未明确指定的第三方项目。

不要运行长时间 fuzz。

不要生成 exploit。

所有 fuzz execution 都必须有明确 timeout。

============================================================
18. Definition of Done
============================================================

最低完成标准：

A.

已有组件真正形成：

generation
→ validation
→ rollback

闭环。

B.

controlled failure 能真实表现：

Stage4 attempt1
→ compiler failure
→ automatic retry
→ attempt2
→ compiler success

C.

simple target 能：

compile
+
link
+
produce libFuzzer executable

D.

runtime smoke 成功。

E.

如果环境允许：

libFuzzer 至少跑 30 秒并执行真实 iterations。

F.

所有 artifact 被保存。

G.

原有测试全部通过。

============================================================
19. 最终报告
============================================================

完成后请严格报告：

1. 修改了哪些文件

2. orchestrator 原来为什么不能由 validator 真正触发 rollback

3. 现在 validation → rollback 如何连接

4. simple target build/link command

5. 最终生成的 fuzzer executable 路径

6. controlled failure：
   attempt1 为什么失败
   rollback 到哪里
   attempt2 是否成功

7. Real LLM：
   provider
   model
   是否真实执行
   如果失败，具体环境原因

不得输出 API key。

8. Stage 1–4 状态

9. Compiler / Linker / Runtime 状态

10. fuzz smoke：
    duration
    execs
    exec/s
    coverage（如果 libFuzzer 提供）
    crash 数量

11. artifact 路径

12. 新增测试

13. 完整测试结果

14. git diff --check

15. 剩余问题

必须明确区分：

IMPLEMENTED
VERIFIED WITH MOCK
VERIFIED WITH REAL COMPILER
VERIFIED WITH REAL LLM
VERIFIED WITH REAL LIBFUZZER
BLOCKED BY ENVIRONMENT

不要把 mock success 描述成 real success。

============================================================
20. 工作顺序
============================================================

严格按以下顺序：

Step 1
inspect repository

Step 2
确认 simple target 如何 build

Step 3
写 validator→rollback integration regression test

Step 4
接入 orchestrator

Step 5
实现 simple build/link adapter

Step 6
验证真实 clang + libFuzzer compile/link

Step 7
验证 runtime smoke

Step 8
运行现有 Mock E2E

Step 9
运行 controlled compiler-failure rollback E2E

Step 10
配置并尝试 Real LLM Stage 1–4

Step 11
如果 build 成功，执行 30~60 秒 libFuzzer smoke

Step 12
运行完整测试集

Step 13
git diff --check

Step 14
输出最终验收报告

如果中途发生失败：

不要通过注释掉 validation、
降低 correctness check、
硬编码 expected output

来“让测试通过”。

优先修复真实 pipeline。

优先级：

correctness
> end-to-end executability
> observability
> reproducibility
> backward compatibility
> architecture elegance

现在开始。