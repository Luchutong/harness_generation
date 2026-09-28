# Candidate Semantic Validation 实现报告

本次建立 `Candidate Discovery → DeepSeek Agent Semantic Validation → Validated Candidate Artifact`。
Agent 只判断入口假设是否有合理的外部输入可能性，并记录证据缺口。FT Extraction 继续按原有路径工作，
`accepted/rejected/unresolved` 尚未用于删除、筛选 FT，也不代表可编译或语义完整的 harness。

## 1. 文件变更

新增 `harness_generation/semantic_discovery/`：

| 文件 | 职责 |
| --- | --- |
| `__init__.py` | 独立 Agent API 导出 |
| `models.py` | 消息、模型 Protocol、预算、decision schema、Fake/Recorded 模型 |
| `deepseek_client.py` | OpenAI SDK 兼容 DeepSeek provider，配置与安全异常 |
| `tools.py` | Phase 1 快照索引、六个只读工具、源码限制与 evidence ID |
| `agent.py` | system prompt、完整消息历史、工具循环、最终判定校验 |
| `persistence.py` | 原子运行 artifact、完整性校验、可恢复验证目录 |
| `cli.py` | `candidate-validate` 独立入口 |

新增 `tests/test_semantic_discovery.py`、`scripts/smoke_candidate_validation.py` 和本报告。
修改 `harness_generation/cli.py`（分发新命令）、`artifacts.py`（新增路径）、`pyproject.toml`（OpenAI SDK 依赖）、
`.env.example`（独立 DeepSeek 配置）和 `README.md`（入口说明）。
此前 Candidate Discovery/FT 解耦的工作继续保留，本次没有修改 Stage 1–4、Protocol、SFG 或 FT 消费规则。

## 2. Agent abstraction

`AgentModel.complete(messages, tools) → AgentModelResponse` 与旧 `LLMClient.generate()` 分离。
响应包含 `content`、`AgentToolCall(id,name,arguments)`、可选 `reasoning_content` 和 provider metadata。
真实实测后新增 `submit_candidate_decision` 终止工具：最终结构化 JSON 通过原生 function arguments 提交，
与六个 Repository Query Tools 区分。框架也继续支持严格 JSON 文本响应供离线记录回放。
`CandidateValidationAgent` 维护消息和预算；provider 不执行工具，也不保存会话状态。
`FakeAgentModel` 支持固定响应及测试回调；`RecordedAgentModel` 加载显式离线记录。
生产 CLI 只提供 DeepSeek，不会因缺少配置切换到这些离线模型。

## 3. DeepSeek 配置

| 环境变量 | 默认/要求 |
| --- | --- |
| `DEEPSEEK_API_KEY` | 真实执行必须提供；从环境读取，不序列化 |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` |
| `DEEPSEEK_MODEL` | `deepseek-flash`；`--model` 优先，可指定 `deepseek-v4-pro` |

使用 `openai.OpenAI(...).chat.completions.create(model,messages,tools,...)`。
新增依赖 `openai>=1.0,<3`，本轮安装并测试的 SDK 为 2.54.0。
默认 `--thinking disabled`，可改为 `enabled`；两种模式都保留 provider 返回的 `reasoning_content` 并在后续请求中回传。
这遵循 [DeepSeek tool calling](https://api-docs.deepseek.com/guides/tool_calls/) 和
[thinking 对话历史要求](https://api-docs.deepseek.com/guides/thinking_mode/)。

单次请求 timeout 为 60 秒，max_tokens 为 4096，SDK 自动重试关闭。CLI 不自动加载 `.env`。
base URL 拒绝内嵌用户名、密码、query 和 fragment。异常只暴露框架生成的安全错误，
不保存 provider 异常字符串、HTTP headers/bodies 或 SDK request 对象。
Token usage 只保留整数计数。API key 不进入 prompt、trace、metadata 或 canonical result。

## 4. Tool registry

| 工具 | 参数 | 返回范围 |
| --- | --- | --- |
| `get_function` | `function`：优先准确 function ID，也支持名称 | 快照函数体、签名、参数、返回值、定义位置、静态 signal 类型 |
| `get_type_definition` | `type` | 已索引 struct/typedef、aliases、fields、声明位置 |
| `find_callers` | `function` | 已索引函数体中有限数量的直接调用表达式 |
| `find_callees` | `function` | 函数体中有限数量的调用，包括明确标识的未解析间接调用 |
| `find_symbol_references` | `symbol` | 有限 identifier/field/type reference 及所在源码行，排除注释和字符串匹配 |
| `read_source_range` | `file,line_start,line_end` | 已索引、项目所有的 C/头文件的有限行范围 |

优先使用 `functions.json` 内的函数体和 struct 声明。调用/引用索引按需对这些快照函数体做 tree-sitter 解析，
不枚举或重扫仓库文件。索引在候选间复用，各候选的预算、证据表、消息独立。
调用和引用结果标注 `syntactic_only`/`name_only_not_a_proven_call_edge`，同名符号不会自动成为已证明的 dataflow。

实时文件读取复用 `SourcePathResolver`，相对 project 路径以 `functions.json` 所在目录为基准。
拒绝未索引文件、越界路径、绝对读取参数、指向项目外的 symlink，以及 `.env` 等非 C/头文件。
每次请求只读取一个指定文件，文件 I/O 上限 2 MiB；函数体/struct 声明与快照不匹配时返回错误，
不混用冲突源码。实时读取的文件 hash 进入 metadata，恢复时重新校验。
库调用若快照 project 为相对路径，应提供 `functions_path`；缺少解析基准时实时读取失败。

## 5. Agent loop 与终止

消息由框架按 `system → user → assistant(tool_calls) → tool(result) → … → assistant(submit_candidate_decision)` 累积。
终止工具必须是该轮唯一调用，提交后追加工具确认并停止；不计入 repository 查询次数。
工具轮允许短的说明性前言；同时携带 structured verdict 与 tool calls 的响应视为无效。
每个工具调用必须使用注册名称和严格参数；不存在 shell、写源码、编译、fuzz 或网络查询工具。

循环在以下情况停止：

- 收到 schema 合法、证据引用存在的最终 decision；
- 达到轮数、工具次数或源码字符预算；
- provider 失败；
- 最终 JSON 无效、工具调用 ID 无效/重复、跨 run 或伪造 evidence reference。

预算停止写 `unresolved + budget_exhausted`。模型输出无效写 `unresolved + invalid_output`，`run_status=invalid`；
这不是对候选的 `rejected`。provider 错误写 `unresolved + provider_error`，`run_status=error`。
CLI 为 invalid/error 返回非零；合理的 unresolved 和 budget exhaustion 是有记录的完成结果，返回零。

## 6. 预算

| 预算 | 默认 | CLI |
| --- | ---: | --- |
| 模型轮数 | 6 | `--max-rounds` |
| 工具调用次数 | 24 | `--max-tool-calls` |
| 返回证据累计字符（含 JSON 元信息，重复查询也收费） | 48000 | `--max-source-chars` |
| 单次 references/同名函数/type 返回数量 | 10 | `--max-references-per-query` |
| 单次 callers | 10 | `--max-callers` |
| 单次 callees | 10 | `--max-callees` |
| 单次源码范围行数 | 80 | `--max-lines-per-read` |
| 单条证据字符上限 | 12000 | `--max-chars-per-record` |
| 独立 terminal schema repair 次数 | 1（仅允许 0/1） | `--max-terminal-repairs` |

探索预算是不可由模型修改的正整数。批量工具调用逐个计费；总预算不足的查询不发布部分证据。
terminal repair 单独计费，最多增加一次模型调用，不增加探索 round，也不允许执行 repository tools。
首次结构/enum 错误以 `schema_validation_failed` 返回同一对话，由模型重新提交；框架不映射 enum、
不移动字段。证据伪造、缺少候选源码和语义 invariant 失败不触发 repair。第二次无效仍写 invalid。
trace/metadata 保留 `terminal_submission_attempts/schema_repair_attempted/schema_repair_success/initial_schema_errors`。
query 返回数截断显示 `query_truncated`；单条证据截断显示 `truncated`，并缩短实际源码行区间。
局部截断可继续调查，不能拿未返回内容当作证据；accepted 可依据能证明可能输入路径的局部源码，
rejected 必须引用候选本身的完整函数体，避免从截断内容判断整个函数不处理输入。
总预算耗尽则直接 unresolved。`--max-candidates` 是本次处理数量，可为零；余下候选保留并写延期原因。

## 7. Evidence 与 untrusted data 边界

每个工具生成 `ev_<SHA256 前32位>`；hash 包含 Phase 1 source fingerprint、工具、参数和返回记录。
记录包含 `tool,arguments,source,line_start,line_end,content,origin,truncated,evidence_id`，
以及该工具的身份/类型信息。相同快照、工具参数、截断设置与源码得到相同 ID。

工具响应标为 `untrusted_repository_evidence`；system prompt 明确源码注释、字符串、文档及工具数据不能成为指令。
工具 registry、参数校验、冻结预算和最终 schema 在框架代码中执行，模型不能请求 shell 或扩展策略。
测试验证含 “Ignore previous instructions” 的源码只出现在 tool message，越权工具请求被拒绝。
这些检查约束能力与输出格式，并不声称能消除模型受注释影响而做出错误语义判断的风险。

最终 JSON 只允许引用本次运行实际发布的 evidence ID，不能填写自造源码位置。
accepted/rejected 都要求正当 reason code 和源码证据，且必须引用本候选 `get_function` 的定义。
accepted 不要求读完整个大函数；rejected 仍要求完整函数体。
rejected 只允许明确的负面 reason code，不允许 `insufficient_evidence` 等不确定理由。
框架不实现语义完整性证明；“证据存在”与“语义推断正确”需要区分，后者仍须实测和复核。

## 8. Artifact schema 与恢复

`candidate_discovery/candidates.json` 的内容不变。

```text
candidate_discovery/
  candidates.json
  validated_candidates.json
  agent_runs/candidate_<function ID 的 SHA256 前24位>/
    result.json
    trace.json
    evidence.json
    metadata.json
```

`validated_candidates.json` 的 schema_version 为 1：

```json
{
  "schema_version": 1,
  "artifact_kind": "validated_entry_candidate_catalog",
  "policy_version": "recall-first-entry-validation-v3",
  "source_fingerprint": "...",
  "discovery_fingerprint": "...",
  "discovery_artifact": "candidates.json",
  "verdict_is_filter": false,
  "candidates": [
    {
      "candidate_id": "candidate_...",
      "function_id": "api.c:5:parse",
      "function": "parse",
      "status": "accepted",
      "validation": {
        "schema_version": 1,
        "candidate_id": "candidate_...",
        "function_id": "api.c:5:parse",
        "function": "parse",
        "verdict": "accepted",
        "input_mode": "direct_buffer",
        "reason_codes": ["external_input_sink"],
        "evidence": [{"tool": "get_function", "evidence_id": "ev_..."}],
        "discovered_symbols": [],
        "open_questions": [],
        "budget": {"rounds": 2, "tool_calls": 1, "source_chars": 900, "exhausted": false, "limits": {}},
        "model": {"provider": "deepseek", "model": "deepseek-flash"},
        "run_status": "completed"
      },
      "run_directory": "agent_runs/candidate_..."
    }
  ]
}
```

示例计数和 limits 为展示占位，实际 limits 保存全部预算。所有宽候选均在输出目录中：
未分析记录 `status=unresolved, validation=null` 和延期原因；有结果的 unresolved 与尚未运行可以区分。
trace 保存完整 messages（原始 assistant 返回与 canonical result 分离）、每轮 provider usage/metadata、
tool 名称、参数、调用 ID、返回 evidence IDs、错误和截断标记。metadata 保存策略、配置/源码 fingerprint、
termination、实时文件 hash 和三个运行文件的 digest。

每个文件原子写入，metadata 最后作为运行提交标记；每完成一个候选就更新 validated catalog。
恢复从运行文件校验完整性及 evidence/trace 一致性，不盲信目录中的 accepted 字符串。
变更 discovery、快照、预算、模型、thinking、provider 配置或已读实时源码，会使缓存结果失效。
同一候选显式重跑会原子覆盖该目录，历史多次采样比较应使用不同 artifact 目录。

## 9. CLI

```bash
# 使用已有 Phase 1 artifacts；宽发现保留全部函数。
harness-generation candidates --artifacts artifacts/foo --policy broad

# 先在 shell 配置 DEEPSEEK_API_KEY；CLI 不自动 source .env。
harness-generation candidate-validate \
  --artifacts artifacts/foo --provider deepseek \
  --model deepseek-flash --max-candidates 10 \
  --max-rounds 6 --max-tool-calls 24

# 指定一个函数 ID（或 candidate_<hash>），显式要求重新验证。
harness-generation candidate-validate \
  --artifacts artifacts/foo --candidate 'src/parser.c:100:process'

# 恢复兼容的已完成结果。
harness-generation candidate-validate --artifacts artifacts/foo --resume
```

默认只处理 discovery 选中的 unresolved 候选；保留 discovery 的 budget/declaration/legacy 延期原因。
要探索宽候选，应先运行 `candidates --policy broad`。重复 `--candidate` 可覆盖处理选择并重验指定候选，
即使该候选已 accepted/rejected 或原来被延期。不会更改 discovery 文件。

兼容的 accepted/rejected 默认跳过；完成但 unresolved 的结果默认重试。
`--resume` 还会跳过兼容的 completed unresolved（包括预算耗尽），invalid/provider error 会重试。
`--candidate` 的显式重验优先于 resume。若全部可复用或 `--max-candidates 0`，无需 API 调用。
实际有待验证候选且缺少 key 时明确报错，不生成假判定。

## 10. 离线测试

```bash
.venv/bin/python -m pytest -q
```

覆盖 direct uint8_t/size、void/src/cb、struct 字段调查、context/feed 的 callers/callees/references、
证据不足、带证据的明确 rejection、三种总预算耗尽、跨 run/伪造 evidence、源码 prompt injection、
不允许的工具/参数、越界及 symlink、快照冲突、查询截断、完整消息历史、artifact 保留及 resume 失效。
此外使用 `httpx.MockTransport` 跑真实 OpenAI SDK 的序列化/解析，确认两轮 tool roundtrip、
thinking reasoning_content 回传和 usage 保存；该测试没有外部网络请求。

mock verdict 验证框架能承载这些判断及调查路径，不是 DeepSeek precision/recall 的实测结果。
首轮新增 30 项测试通过，完整测试为 55 passed。真实实测修复后新增两项回归，
该实测轮次的完整测试为 **57 passed（4.33 秒）**；`pip check` 与 `git diff --check` 通过。
本轮冻结为 **recall-first-entry-validation-v3**：仅增加一次 terminal schema repair，语义定义保持不变。
最新测试、repair 实测和后续独立 Semantic Slice 实现见 [本轮报告](SEMANTIC_SLICE_IMPLEMENTATION_REPORT.md)。
另在独立小型 C fixture 上完成显式 FakeAgentModel 离线 smoke：2 个候选、4 次模型调用，
resume 为 0 次调用，第三个候选仍保留。discovery 文件字节不变，没有生成 triplets 或启动后续流水线。
可检查本地 [validated artifact](../artifacts/candidate_validation_offline_ortnlr81/phase1/candidate_discovery/validated_candidates.json)。

## 11. 真实 DeepSeek smoke

```bash
.venv/bin/python scripts/smoke_candidate_validation.py \
  --artifacts artifacts/foo --candidate 'src/parser.c:100:process' \
  --model deepseek-flash
```

这是显式真实 provider 入口：检查 key，要求至少一次带证据的 tool roundtrip 和合法 structured final decision。
无 key 返回 2 并提示 `NOT RUN`；不会自动 mock。一次只验证一个候选，最多 6 轮/12 次工具调用。

首次实现时真实 smoke 未运行，专用 `DEEPSEEK_API_KEY` 当时未配置。
后续用户显式指定 `.env` 凭证后，已使用其中的兼容 `LLM_API_KEY` 完成真实测试：
**13 个场景中 12 个符合预期，公开 CLI smoke 通过**，详细证据见
[真实实测报告](DEEPSEEK_CANDIDATE_REAL_EVALUATION_20260928.md)。
真实测试只运行候选验证，没有启动编译器、fuzzer 或 Stage 1–4。

## 12. 留给后续 Semantic Slice 的问题

- 从 syntactic call/reference 走向可复核的有限输入路径：跨文件同名符号、函数指针、callback、宏和条件编译。
- 当前快照没有保留所有 scalar typedef、全局初始化和字段赋值；类型查不到仍属未知。
- 选择支撑 anchor 的最小语义切片，包括必要创建、配置、输入注入、消费、释放及错误分支。
- 切片内 ownership、生命周期、借用数据有效期和长度关系证明，以及强/弱关系的组合。
- 对真实不同项目建立标注集，测 accepted precision、rejected 的误删率、unresolved 比例及预算成本。
- 在独立后续任务中决定 validated artifact 如何接入 FT；本次只增加可审计的判定层。
