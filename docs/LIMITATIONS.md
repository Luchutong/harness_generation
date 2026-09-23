# 当前局限

本文档记录项目结项时仍未解决的问题。它们不是附带问题，而是这个方向的核心研究难点：
要让 LLM 生成的 harness 同时具备跨项目泛化能力和高语义质量，需要比函数签名和局部
调用图更强的 API 语义建模。

## 1. 跨项目泛化仍然较弱

观察到的现象：小型 parser 风格项目可以跑通，但一旦目标项目包含 opaque handle、
多阶段初始化、回调表、全局状态或特殊构建宏，自动生成质量会明显下降。

可能原因：静态抽取目前主要基于函数签名、结构流、命名和有限使用模式，不能稳定恢复
项目真实 API 协议。

后续方向：引入更显式的 protocol/state 模型，把 create/configure/parse/free、
callback registration、borrowed/owned pointer 等关系作为 FT 的一部分。

## 2. 编译成功不等于 harness 质量高

观察到的现象：某些 harness 可以通过编译、链接和 runtime smoke，但仍可能存在语义偏差，
例如回调返回值不符合项目约定、可选 callback 被错误启用、输出 oracle 缺失，或输入只触达
浅层路径。

可能原因：当前 validator 更擅长检查结构合法性和 API 边界，较难判断“这个调用序列是否
符合库作者预期”。

后续方向：增加面向输出、覆盖、差分行为和 API 示例的一致性检查，避免把“能跑”误判为
“高质量”。

## 3. Function Triplet 仍不能完整表达复杂生命周期

观察到的现象：在 libexpat 一类项目中，真实 harness 需要
`create -> parse -> free`，但自动 FT 曾只抽到 `parse`。LLM 可能补上 create/free，
却会被 Stage 4 因“调用 FT 外 API”拒绝。

可能原因：FT 的权威边界仍偏函数集合，缺少对 opaque resource lifecycle closure 的
一等支持。

后续方向：把“返回 opaque handle / 消费 opaque handle / cleanup 释放 handle”作为专门
关系抽取，允许 validator 把生命周期补全函数纳入 FT 权威。

## 4. 回调语义难以自动恢复

观察到的现象：`markdown-wasm` 的 `parseUTF8` 需要理解 optional code-block callback
的函数指针类型、返回值语义和 null 行为。生成出的 harness 即使能编译，也可能通过错误
callback 改变目标行为。

可能原因：C 里的 callback 语义常常藏在 typedef、宏、调用点和文档里，仅靠函数签名
不足以判断哪些 callback 必填、哪些应保持 null、返回 0 或 -1 分别代表什么。

后续方向：从 header、调用点、示例和测试中挖掘 callback table / callback typedef 语义，
并在 HarnessPlan 中显式约束 required/optional、arity、return policy。

## 5. Runtime 反馈仍然偏粗粒度

观察到的现象：Sanitizer crash 可以帮助定位明显内存错误，但对 silent semantic bug
帮助有限。`markdown-wasm` 的 wasm label aliasing 就不是 sanitizer 能直接发现的问题。

可能原因：当前反馈主要来自编译诊断、runtime 退出状态、libFuzzer 统计和有限 crash
分类，缺少项目语义 oracle。

后续方向：加入 differential testing、reference implementation、格式 round-trip、
输出稳定性和 target-only coverage，区分 crash、UB、语义偏差和 harness 自身错误。

## 6. 构建系统适配不完整

观察到的现象：对单文件或少量 C 文件项目较容易构建；稍大项目常需要人工写
`target_build.json`，处理 include path、宏、导出注解、可选源文件和链接参数。

可能原因：C 项目构建信息分散在 Makefile、CMake、脚本、wasm build glue 和平台条件里，
自动恢复一个可供 fuzz 的 native build recipe 并不简单。

后续方向：把 build recipe 推断和验证作为独立模块；优先支持 compile_commands.json、
CMake/Ninja、常见 Makefile，再用失败诊断反向修正 recipe。

## 7. Benchmark 规模仍然小

观察到的现象：目前仓库中保留了 `mini_parser`、`json_parser` 和 `markdown_wasm`
等小规模 case。它们足以证明流水线和暴露问题，但不足以支持强统计结论。

可能原因：每个 C 项目都需要构建适配、ground truth、reference harness 或至少人工复核，
扩展 benchmark 的成本高。

后续方向：把 benchmark 分成开发集和最终评测集，记录每个项目的失败类型、人工适配量、
生成成本、覆盖和 bug 归因，而不是只保留成功样例。
