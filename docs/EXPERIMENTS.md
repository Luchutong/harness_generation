# 实验记录

本文档概括结项时保留的主要实验。这里的目标不是展示“所有项目都成功”，而是把流水线
做到哪、哪些证据已经闭环、哪些地方失败讲清楚。

## 总览

| 项目 | Harness 生成 | 编译 | 运行 | 目标 API 触达 | Bug | 主要结论 |
| --- | --- | --- | --- | --- | --- | --- |
| `mini_parser` | 是 | 是 | 是 | 高 | synthetic | 用于验证 protocol-aware structured harness 的基线项目。 |
| `json_parser` | 是 | 是 | 是 | 中 | 未发现 | 真实 API demo，展示 FT 抽取、LLM 生成、编译链接和 smoke fuzz 闭环。 |
| `libexpat` | 需要人工补全 FT | 是 | 是 | 中 | 未记录 | 暴露 opaque handle 生命周期闭包不足：`create/parse/free` 没有自动归入同一 FT。 |
| `markdown-wasm` | 是，部分 FT 需手动指定 | 是 | 是 | 有意义 | 是 | 生成 harness 触发真实缺陷，但也暴露 callback 语义和 FT ranking 问题。 |

## `mini_parser`

目的：提供可控的协议型 parser 目标，用于验证 structured harness、protocol contract、
反馈闭环和基础 validator。

已验证内容：

- Phase 1 可以抽取函数、结构和 SFG。
- FT 可以覆盖 parser 状态路径。
- 手写 structured harness 可作为参考。
- 测试集中保留了 mock LLM E2E 和本地编译回归。

局限：这是人工设计的小项目，不能代表真实 C 项目的构建复杂度、API 习惯和历史代码问题。

## `json_parser`

目的：作为真实 API 最小 demo，给导师或评审提供一条可以立即运行的黄金路径。

运行方式：

```bash
./scripts/run_minimal_demo.sh
```

已验证内容：

- `sfg_builder` 从 `benchmarks/json_parser/project` 构建 SFG。
- `harness_generation triplets` 抽取 `json_parse` 和 `json_parse_ex` 两个 FT。
- `triplets rank --max-ft 1` 选择 `ft_json_parse_26fecbbbfb75`。
- 真实 LLM API 完成 Stage 1-4。
- Intermediate、Compiler、Linker、Runtime、Fuzz smoke 均为 `passed`。

典型生成 harness 行为：

```c
json_value *value = json_parse((const json_char *)data, (size_t)size);
if (value != NULL) {
    json_value_free(value);
}
```

结论：该项目证明流水线在一个小型真实 parser 项目上可以端到端闭环。它的 API 序列较浅，
因此更适合作为 demo，而不是作为泛化能力的强证据。

## `libexpat`

目的：测试 opaque handle 生命周期能否被自动 FT 抽取捕获。

观察到的问题：

```c
XML_ParserCreate
XML_Parse
XML_ParserFree
```

真实 harness 需要上述生命周期闭包，但自动 FT 曾只包含 `XML_Parse`。LLM 在生成时会自然
补上 create/free，可 Stage 4 validator 会因为它们不在 FT 权威边界内而拒绝正确方向的
harness。

结论：这不是单个 prompt 的问题，而是 FT 抽取层的生命周期建模问题。后续应把
opaque resource lifecycle closure 纳入 FT 权威，而不是依赖人工补全。

## `markdown-wasm`

目的：测试稍大真实 C 项目、callback API、wasm 移植代码和多入口选择。

已验证内容：

- `md_parse` 与 `parseUTF8` 两个 entry point 均可构建 reference harness。
- 真实 LLM 生成的 harness 可以通过 compiler/linker/intermediate/runtime gate。
- Smoke fuzz 找到目标缺陷，并可用手写 reference harness 复现。

主要问题：

- 默认 FT ranking 会把一些内部 helper 排在 `md_parse` / `parseUTF8` 前面，因此真实入口
  需要手动指定。
- `parseUTF8` 的 optional callback 语义复杂，生成 harness 容易通过错误 callback 改变
  目标行为。
- Sanitizer 能发现 native crash，但 wasm 中更重要的 label aliasing 是 silent semantic
  bug，需要差分测试才能确认。

详细分析见 [markdown-wasm case study](CASE_STUDY_MARKDOWN_WASM.md)。

## 当前证据边界

这些实验说明项目已经具备研究原型价值：

- 能完成项目级静态分析、FT 抽取、LLM staged generation 和执行验证。
- 能在真实项目上生成可运行 harness。
- 能通过生成 harness 暴露真实目标缺陷。
- 能把失败归因到 FT 抽取、callback 语义、build recipe 和 runtime oracle 等具体模块。

它们还不能证明：

- 任意 C 项目都能零适配生成高质量 harness。
- 编译和 smoke fuzz 通过就等价于语义正确。
- 当前 FT ranking 已能稳定选中最有价值入口。
- 当前 benchmark 规模足以支持统计意义上的有效性结论。
