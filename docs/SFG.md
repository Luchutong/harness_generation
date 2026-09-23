# Structural Flow Graph（SFG）构建器

`sfg_builder` 实现 SynapseFlow Phase 1 的项目级结构分析。它只负责 C 解析、候选发现、语义标注、struct 方向和 SFG 构建；不执行 Function Triplet、Harness 生成、fuzz、覆盖反馈或 rollback。

## 运行

默认使用确定性的 Mock semantic analyzer，因此不需要 API key：

```bash
python -m sfg_builder \
  --project tests/fixtures/simple_project \
  --output artifacts/simple
```

也可以安装项目后执行 `sfg-builder`。可重复传入 `--ignore-dir PATTERN` 增加目录名或 glob；默认忽略 `.git`、`build`、`out`、`cmake-build*`、`third_party`、`vendor` 和 `external`。

显式使用 LLM：

```bash
export DEEPSEEK_API_KEY=...
python -m sfg_builder \
  --project target_project \
  --output artifacts/target \
  --semantic-analyzer llm \
  --model deepseek-v4-flash
```

LLM 模式的角色与方向判断只发送单个函数的 signature、body、目标参数、AST hints
和直接相关的 struct 定义，不发送整个项目。usage review 只发送同一资源的一小批
已抽取模式及其中函数的 signature/documentation，不发送无关源码。stream 参数使用
`direct`、`yes_no`、`multiple_choice` 三个不同 Prompt；固定至少两票为 byte stream
才标记 ISF。单个请求超时、异常或非法 JSON 会记录 error decision，并按
unknown/false 或原始静态 usage 保守降级，不中止其他函数。usage review 的批请求
失败时递归拆分；单模式再重试一次，仍失败才使用静态模式。每次尝试都保存在
`semantic_reviews`，便于区分模型判断与服务波动。

`--render` 在系统存在 Graphviz `dot` 时额外生成 `sfg.svg`。Graphviz 不是 Python 依赖，渲染失败不影响已经写出的 JSON 和 DOT。

## 分析阶段与产物

```text
*.c / *.h
  → tree-sitter AST
  → functions.json
  → candidates.json
  → annotations.json
  → flows.json
  → sfg.json + sfg.dot + ownership.json + usage_patterns.json
```

- `functions.json`：扫描文件、typedef/struct、函数 metadata、body 和 AST field read/write hints。
- `candidates.json`：byte-compatible pointer 的 ISF 高召回候选，以及 struct 参数/返回值相关的 PRF/HPF 候选。
- `annotations.json`：ISF/PRF/HPF 多标签、stream 投票、struct direction，以及每个语义判断的 function/file/line/prompt/response/confidence/status。
- `flows.json`：每个相关函数的 input/output structs、源码位置、复杂流标记和 warning。
- `sfg.json`：唯一 struct 节点、`(null)` 节点、函数边以及完整 FunctionFlow。
- `sfg.dot`：同一张图的 Graphviz 表示。
- `ownership.json`：保守静态推断得到的资源 producer/cleanup 关系。
- `usage_patterns.json`：项目内 tests、examples 与 production callers 的调用轨迹、
  同变量生命周期模式、路径条件、支持度，以及受约束的 LLM review/merge 记录。

## 静态与语义边界

tree-sitter 决定函数边界、参数、指针深度、const、typedef/struct 关系和字段读写。ISF 静态阶段只把 `void *`、`char *`、`signed/unsigned char *`、`uint8_t *`、`int8_t *` 列为候选；`filename`、`pathname`、诊断字符串以及真正 byte stream 的区别交给 SemanticAnalyzer。

非 pointer struct 按 C 值传递确定为 input；const struct pointer 确定为 input；明确的 AST read/write 确定为 input/output/both。只有没有充分静态证据的 struct pointer 才调用 `infer_struct_direction()`。

`SemanticAnalyzer` 是协议接口。`MockSemanticAnalyzer` 用于无网络测试和可复现实验；`LLMSemanticAnalyzer` 接收可注入 transport，并严格校验 JSON schema。

类型解析还恢复标量及简单指针 typedef 链的底层类型、隐藏指针深度和 `const`。
`void *` 只有与长度参数形成可信配对时才进入字节流候选；名字表明是
`user_data`、`cookie` 或 `context` 的参数会被排除。

## 图构建的保守工程选择

以下细节是第一版工程选择，不是 SynapseFlow 论文规定的唯一算法：

- `inputs=[A]`、`outputs=[B]` 生成 `A -> B`；缺失一侧使用 `(null)`。
- pointer direction 为 `both` 的原地修改保留在 direction 记录中，但 SFG 按 input-only 输出 `A -> (null)`，避免没有结构层级变化的 `A -> A` 自环。
- 多输入或多输出标记 `complex_flow=true`。生成笛卡尔候选边用于可视化，但每条边必须为 `inferred=true`，携带 `inference_reason`，同时输出 warning。
- `unknown` struct endpoint 不猜测方向，从边中省略并保留 warning。

这些中间产物用于后续 ablation、错误归因和 prompt 优化；不要只根据最终图判断语义分析质量。

复杂多输入/输出映射明确属于：**engineering choice, not specified by SynapseFlow Phase 1**。
