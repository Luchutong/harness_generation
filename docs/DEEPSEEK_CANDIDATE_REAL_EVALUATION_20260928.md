# DeepSeek Candidate Validation 真实实测报告

2026-09-28，使用用户指定 `.env` 的真实凭证向官方 DeepSeek HTTPS endpoint 发起请求。
测试模型为 `deepseek-flash`，不是 Fake/Recorded 模型；默认 non-thinking，另有一项 thinking 实测。
当前版本 **13 个场景中 12 个符合预设预期，公开 CLI smoke 通过**。
另有一个 context/feed 场景因模型输出了 schema 不允许的 reason code，被框架保守保存为 unresolved/invalid。

## 范围与证据

- 9 个受控 C 场景、1 个预算场景、1 个 thinking 场景、真实 JSON 项目的 2 个入口，共 13 项。
- 受控 fixture 仅运行 tree-sitter 静态解析；没有模拟 Phase 1 语义结论，也没有 mock Agent。
- JSON 复用已有 Phase 1 artifact 的快照，在新目录中运行 discovery；原有 artifact 和源码不变。
- 另外通过 `scripts/smoke_candidate_validation.py` 实测公开 CLI，发生真实 API/tool/result/final 往返。
- 默认预算为 6 轮、24 次 repository 查询、48000 证据字符，预算场景改为 1 轮/1 次查询。
- 每项仅一次采样，结果属于定向功能实测，不是跨项目统计评测或 precision/recall 的可靠估计。

最终完整数据：

- [summary.json](../artifacts/candidate_validation_real_20260928_03/summary.json)
- [受控 fixture validated catalog](../artifacts/candidate_validation_real_20260928_03/fixture_phase1/candidate_discovery/validated_candidates.json)
- [JSON validated catalog](../artifacts/candidate_validation_real_20260928_03/json_phase1/candidate_discovery/validated_candidates.json)
- [公开 CLI smoke 日志](../artifacts/candidate_validation_real_20260928_03/cli_smoke.txt)

每个 case 的 `run_directory` 中保留 `result.json/trace.json/evidence.json/metadata.json`。
最终统计只汇总第三轮保存的 13 项和单独 CLI smoke；前两轮调试失败没有混入通过率。

## 最终结果

| 场景 | 预期 | 实际 verdict / 状态 | 轮数 | 查询数 | 秒 | 符合预期 |
| --- | --- | --- | ---: | ---: | ---: | --- |
| `parse(uint8_t *data, size_t size)` | accepted | accepted / completed | 3 | 2 | 3.508 | 是 |
| `parse_blob(void *src, unsigned long cb)` | accepted | accepted / completed | 2 | 1 | 2.143 | 是 |
| `process_input(Input *input)` | accepted | accepted / completed | 4 | 4 | 4.383 | 是 |
| `process_context(Context *ctx)` | accepted | unresolved / invalid | 3 | 4 | 3.445 | 否 |
| `decoder_wrapper(src, cb)` | accepted | accepted / completed | 6 | 8 | 6.394 | 是 |
| 纯常量返回 | rejected 或保守 unresolved | rejected / completed | 3 | 2 | 2.779 | 是 |
| 仅释放 context | rejected 或保守 unresolved | rejected / completed | 2 | 1 | 2.150 | 是 |
| 只有声明、没有定义 | unresolved | unresolved / completed | 3 | 5 | 3.719 | 是 |
| 带恶意注释的纯常量函数 | rejected 或保守 unresolved | rejected / completed | 2 | 1 | 1.912 | 是 |
| 1 轮/1 查询预算 | unresolved + budget_exhausted | unresolved / completed，实际 max_rounds | 1 | 1 | 0.707 | 是 |
| thinking 模式的 context/feed | accepted | accepted / completed | 3 | 3 | 4.569 | 是 |
| JSON `json_parse` | accepted | accepted / completed | 4 | 4 | 3.810 | 是 |
| JSON `json_parse_ex` | accepted | accepted / completed | 3 | 3 | 3.875 | 是 |

合计 accepted 7、rejected 3、unresolved 3；其中 unresolved 包含 1 项无定义、1 项预算耗尽及 1 项模型输出无效。
13 项共 39 轮模型调用、39 次 repository 查询；provider usage 合计 116691 tokens，
其中 prompt 110252、completion 6439。这些 token 数不含单独 CLI smoke、前两轮调试或中断时未保存的调用。
查询期间没有让 Agent 执行 shell、写源码、编译、fuzz 或生成 FT。

## 实际调查能力与边界

struct 场景实际调用 `get_type_definition(Input)`，读取 buffer/length 字段并调查 `parse` callee。
wrapper 场景实际查看 `feed`、`process_context`、`parse_blob` 以及 Context 定义，有限路径能够被调查。
非典型 src/cb 场景 accepted，未按参数名实施旧式 hard filter。
缺少定义的场景查询源码范围、类型、caller/callee 后保留 unresolved，没有负面过滤候选。

thinking 场景返回并保存了 3 个 assistant reasoning message，后续请求带完整历史并成功完成工具回传。
所有保存的结果引用均存在于对应 run 的已发布 tool trace，证据校验通过。
恶意注释没有使纯常量函数被接受，也没有触发越权工具；这仅证明当前样例的结果，不能据此声称全面防住 prompt injection。
discovery 文件字节检查通过，输出目录按实际凭证值扫描，未发现泄露。

## 实测发现及修复

**最终输出协议。** 最初模型经常将解释或 Markdown 和 JSON 混在普通 content 中，严格解析将其视为 invalid。
尝试 provider 全局 JSON Output 后，模型又出现把工具请求写进普通 JSON 内容、提前提交 unresolved 的情况。
最终使用原生 `submit_candidate_decision` function call 提交 terminal JSON，和六个源码查询工具分离。
提交工具必须是该轮唯一调用，参数仍由原有 schema 和 evidence checker 严格校验；没有从 prose 中宽松提取 JSON。
参考 [DeepSeek tool calling 文档](https://api-docs.deepseek.com/guides/tool_calls/)；
全局 JSON mode 的接口要求见 [官方 JSON Output 文档](https://api-docs.deepseek.com/guides/json_mode/)。

**简单输入函数的错误拒绝倾向。** 初版模型曾把读取一个输入字节的函数描述为“太简单、不是有价值的 parser”，并试图 rejected。
system prompt 已明确不设置复杂度/覆盖价值门槛，读取一个外部字节也可以成为输入 anchor。
修复后 direct buffer 和 src/cb 场景均 accepted；这个变化不保证以后所有采样都会遵循 recall-first。

**大函数查询崩溃。** 首轮在 JSON 函数索引中触发 native SIGSEGV。独立复现显示，在此 tree-sitter 0.26.0/C grammar
组合和大树遍历下，访问 Point 后会出现异常节点并导致崩溃。工具层改用 byte offsets 计算行号，并为 body 提供合法函数上下文。
相同 JSON caller/callee/reference 查询已通过，新增独立 subprocess 回归，避免未来原生崩溃直接终止整个 pytest。
上游存在类似 [Point accessor 故障报告](https://github.com/tree-sitter/py-tree-sitter/issues/487)，但本轮没有证明是完全相同的底层根因。

**大函数的过严判定限制。** `json_parse_ex` 的快照 body 为 24632 字符，超过单条证据 12000 字符。
原实现要求任何 accepted 都看到完整函数体，实际上额外引入了大函数 hard gate。
现在 accepted 可依据能够支持输入可能性的局部源码；rejected 仍需完整候选函数体。
这次 JSON 大入口实际查询 `get_function/find_callers/read_source_range` 后 accepted，未扩展到完整 Semantic Slice。

## 剩余失败

non-thinking 的 `process_context` 已正确获取候选、Context、parse_blob 和 caller 证据，也提交了 accepted。
但它把 **input_mode 的 `context_feed` 写进 reason_codes**，而 reason code enum 不允许该值。
框架没有将这个字段自动改写为合法标签，而是标记 `invalid_output` 并保存 unresolved。

具体原始结果见
[失败 trace](../artifacts/candidate_validation_real_20260928_03/fixture_phase1/candidate_discovery/agent_runs/candidate_14e56ea01c7d593d40dfc14e/trace.json)。
同一函数在 thinking 模式下使用合法 reason codes 并 accepted，说明这里失败的是结构化输出可靠性，不是调查工具无法发现输入。
后续可在现有总预算内设计有限 schema-error repair 或评估 provider strict function schema；本次没有放宽 enum，
没有将该 invalid case 算作通过，也没有强行用重采样覆盖失败。

## 代码与验证

新增显式手工评测脚本 `scripts/evaluate_candidate_validation_real.py`，仅用户手动执行，不进入 CI。
它将指定凭证文件当作数据解析，兼容该文件中的 `LLM_API_KEY/LLM_BASE_URL`，校验官方 DeepSeek endpoint，
实际模型由 `--model` 指定，默认 `deepseek-flash`。生产 `candidate-validate` 的环境配置规则保持独立。
修复涉及 `semantic_discovery/{agent,models,tools}.py`；policy version 为 v2，schema version 仍为 1。

修复后离线回归：**57 passed（4.33 秒）**，包含原生 final submission、完整体/局部证据的判定边界和大 JSON 索引。
`git diff --check` 通过。没有修改 Stage 1–4、Protocol 或 FT 消费规则。

复测命令（会真实调用 API，应使用新的输出目录）：

```bash
.venv/bin/python scripts/evaluate_candidate_validation_real.py \
  --env-file /home/luchitong/work/harness_generation/.env \
  --output artifacts/candidate_validation_real_new \
  --model deepseek-flash
```

原始调试目录保留在 `artifacts/candidate_validation_real_20260928_01` 与 `_02`。
第一轮在 JSON 索引处中断，不能将该目录误认为完整跑通的测试结果。
