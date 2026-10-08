# json-parser 已知问题修复与 native crash 诊断报告

日期：2026-10-03

本轮没有继续启动真实模型调用，也没有做 blind experiment。目标是基于已保存的 `json_parse_ex` 轨迹修复已知框架问题，并继续确认之前 Python 进程退出 139 的原因。

## 修复内容

### 1. SourceDetails native crash

确认到一个明确的 native 内存错误触发点：`harness_context/source_queries.py` 旧实现使用了 `node.start_point.row` / `node.end_point.row`。在当前环境的 `py-tree-sitter 0.26.0` 下，`Point.row` 属性会返回缺少引用保护的 Python 整数对象；行号超过小整数缓存范围后，循环访问可触发 use-after-free / heap corruption。

修复方式：

- `SourceDetails` 改为只使用 `node.start_byte` / `node.end_byte`。
- 在函数源码 bytes 上建立换行偏移表，用 `bisect_right` 计算绝对行号。
- `contexts()`、`record()`、`at_line()` 全部走 byte-offset 行号计算。
- `bounded-source-detail-queries` 版本从 `v1` 提升到 `v2`。

验证结果：

- 最小复现旧路径 `node.start_point.row`：`PYTHONMALLOC=debug` 下退出 139。
- 旧路径 Valgrind：`ERROR SUMMARY: 190209 errors from 36 contexts`，分配栈指向 `point_new_internal`。
- 修复路径 byte-offset：`OK byte 10000`。
- 修复路径 Valgrind：`ERROR SUMMARY: 0 errors from 0 contexts`。
- 真实保存产物 `json_parse_ex` 上重复执行 `SourceDetails(...).calls("hex_value")` 200 次通过；该函数范围为 333-1123 行，命中调用在 406 行，覆盖了高行号风险。
- 同一真实查询路径 Valgrind：`ERROR SUMMARY: 0 errors from 0 contexts`。
- 当前代码离线 replay 已保存 Context 响应，正常退出到保存响应耗尽边界：`REPLAY_END 12 incomplete execution_failure`，没有 `Fatal Python` / `Segmentation`。

边界说明：旧真实实验的崩溃日志没有 native 栈，因此不能把历史那次 139 绝对证明为同一个 bug。但保存轨迹中的 `json_parse_ex -> hex_value` 源码细节查询确实会访问 406 行以上的 `Point.row`，本轮最小复现和真实查询路径都支持这是高度可信的根因。

### 2. 长函数源码覆盖与 Slice 截断恢复

修复了长函数只靠单条完整 `get_function` 记录才能证明 source coverage 的问题：

- 新增共享 `source_evidence.complete_bodies()`。
- 支持 gap-free 的 `read_source_range` fragment union。
- 对 range fragment 校验 `source_sha256`、行区间连续性、内容一致性和来源工具。
- `semantic_slicing/core_proofs.py` 与 `harness_context/value_flow.py` 复用同一套 coverage 判定。
- `semantic_slicing` policy 从 `source-choice-semantic-slice-v3` 提升到 `v4`。

同时给 `BoundedAgentLoop` 增加一次受预算约束的 protocol recovery：

- `finish_reason=length` 或没有 native terminal tool 时，不执行截断 tool call。
- 若仍有预算，只允许一次 terminal-only 恢复轮。
- 截断 terminal arguments 会被记录为 tool error，不会被接受或执行。
- 默认保持关闭，当前只由 Slice Agent 打开。

这修的是 `json_parse`/`json_parse_ex` 长函数和 4096 token 截断导致 Slice 失效的问题，不代表 coverage 或 Context completion 已经自动提高。

### 3. callback helper 的定向源码读取

`prepare_local_evidence()` 现在会在已授权 subject 函数内识别 callback table 字段赋值，例如：

```c
opts->drop = discard;
```

它通过已有 `find_field_writes` 工具读取字段写入，再用工具返回的 `possible_callee_ids` 定向读取 helper 源码。这个过程仍然满足当前工具预算和 scope 限制：

- 不根据项目名、函数名或 `drop/free` 等名字做特殊规则。
- 字段赋值本身只作为取证入口，不作为 cleanup proof。
- helper 源码进入 evidence inventory 后，后续 proof grounding 再决定是否能证明 cleanup/callback effect。

对应测试确认：Agent 首轮调查时，`find_field_writes(parse, drop)` 可以直接进入 issued evidence inventory；proof agenda 不再重复建议同一查询。

### 4. lifecycle 修复不再静默覆盖 cleanup API 缺口

修复了旧 `lifecycle` resolution 合并中“先有旧事实、后有新事实”容易变成 subject-level 冲突的问题：

- 只在同一 exact subject、除 `cleanup.mandatory` 外其他属性一致、且 ownership 已证明需要释放时，允许撤回旧的 `mandatory=false`。
- 撤回证明明确标记 `cleanup_api_proved=false`。
- 如果新事实仍然没有 cleanup API，Gate 仍必须阻塞，不能因为修正了 mandatory 就放行。
- 非同一属性变化仍保留冲突，不做 last-wins 覆盖。

这解决的是“错误事实后又补正确事实时形成不可闭合冲突”的一类局部修复问题；它没有放宽 cleanup API 的证明要求。

### 5. native diagnostic 留存

CLI 现在会在 Harness Context 运行目录中打开 `native_diagnostics()`：

- 写入 `native_checkpoint.json`，记录最近阶段、pid、时间和当前 requirement 信息。
- 打开 `native_fault.log`，使未来 native fault 至少保留 faulthandler 输出。
- Python 异常会记录为 `phase=python_exception`。

这不能防止 native 崩溃，但能避免下一次只看到 exit 139 而没有阶段信息。

## 验证

定向测试：

```text
.venv/bin/python -m pytest -q tests/test_known_issue_repair_smoke.py
12 passed

.venv/bin/python -m pytest -q tests/test_source_detail_tools.py
16 passed
```

轻量编译检查：

```text
.venv/bin/python -m py_compile \
  harness_generation/harness_context/source_queries.py \
  harness_generation/harness_context/native_diagnostics.py \
  harness_generation/harness_context/construction.py \
  harness_generation/source_evidence.py \
  harness_generation/semantic_discovery/loop.py \
  harness_generation/semantic_slicing/core_proofs.py \
  harness_generation/semantic_slicing/models.py \
  harness_generation/harness_context/tools.py \
  harness_generation/harness_context/repair_proofs.py \
  scripts/replay_context_native_crash.py \
  tests/test_known_issue_repair_smoke.py \
  tests/test_source_detail_tools.py
```

Native / replay 证据保存在：

```text
artifacts/json_parser_known_issue_repair_20261003/
```

关键文件：

- `point_accessor_debug.log`
- `point_accessor_valgrind.log`
- `byte_accessor_debug_stdout.log`
- `byte_accessor_valgrind.log`
- `source_details_actual_stdout.json`
- `source_details_actual_valgrind.log`
- `current_replay_debug.log`
- `known_issue_smoke.xml`

## 当前仍未解决的问题

### 复杂 cleanup proof 仍然是缺口

本轮没有把复杂 cleanup 彻底证明化。以下情况仍可能保持 `missing` 或阻塞：

- cleanup 通过 while/switch/递归遍历释放内部节点。
- cleanup 参数不是单一直接释放对象，而是对象图根。
- 回调间接释放、释放发生在 helper 的 helper 中。
- 多参数 cleanup 或同类型多个 pointer 参数，需要精确绑定释放对象。
- 条件路径释放、错误路径释放、所有权转移和容器内部元素释放混合出现。

这不是 bug 修复遗漏，而是当前证明器能力边界。为了避免对 `json-parser` 过拟合，本轮只修复了通用证据获取和 native crash，没有把 `json_value_free_ex` 的树形释放写成项目专用规则。

### Context completion 不能由 replay 结果推出

当前离线 replay 只证明“同一保存轨迹不会再 native crash”。它最终为：

```text
REPLAY_END 12 incomplete execution_failure
```

原因是 replay 使用旧保存响应，响应耗尽后进入诊断边界。它不是新的模型实测，也不是 Context complete / Harness compile 的成功证据。

## 结论

本轮修复把两个真实阻塞点从“不可定位失败”降级为“可验证边界”：

- 段错误已有可复现 native 根因，并通过 byte-offset 行号计算修复。
- Agent/Context 侧重复调查、长源码覆盖、callback helper 取证、lifecycle 局部修复的若干已知问题已用定向测试锁住。

下一步若继续提升 `json-parser` 生成 harness 的能力，最值得做的不是 blind experiment，而是把复杂 cleanup 建模成可证明的对象图释放摘要：先支持单根对象、字段递归、数组/链表遍历和 callback release effect 的保守证明，再让 Gate 消费这类摘要。
