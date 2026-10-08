# 跨义务证据复用与 canonical cleanup 绑定修复

日期：2026-10-03。基于本地 `v0.2` 实现；本轮按用户要求只进行小型定向验证，未运行完整回归、真实模型调用或 blind experiment。

## 修复内容

### 跨义务复用源码依赖

`HarnessContextTools.activate` 现在从当前主体、相关 semantic fact 的 API，以及该主体已经授权的 discoveries 恢复相关源码。只有已签发的具体 callee / callback 字段引用才形成 helper 依赖边；单纯类型、函数名匹配不能新增依赖边。

复用检查 evidence ID、原始文件 SHA 和现有 discovery/depth 限制；过期记录同时退出可见证据和查询缓存。EXCLUDE helper 不重新进入作用域，已有 EXCLUDE caller 的只读来源规则保留。未增加工具、生产默认预算或新 contract。

旧调查没有闭合，也可以给同一主体的其他义务留下有效源码。切换 ownership、lifecycle、argument construction 后可以重新计算 callback release；不会把旧 `proved` 直接迁移成新义务的证明。恢复证据不新增读取、source chars 或 discovery，真实的新工具请求仍计费。bootstrap 和 Agent trace 保存复用的 evidence IDs 与依赖边。

### cleanup 消费与资源实例绑定

现有源码 transfer function 增加内部 release 次数区间，并通过直接调用、alias 和已绑定字段 callback 传递。只有目标参数在全部受支持的非空路径中被释放一次，且没有 escape / 已识别的释放后使用，才能投影现有 `cleanup_consumption`。

其他 cleanup 指针参数不会自动获得非空前提；callee 只继承调用点已有的非空证明，避免将实际为 NULL 的 callback userdata 假设为非空。

`project_cleanup_consumption` 不再仅接受单参数的直接 `free(param)`。它可以把上述已证明的间接释放参数绑定到唯一 owned producer；其他参数保留独立构造义务。多个 producer、多个运行时 origin，或多个同类型释放参数不能凭类型猜测绑定。生命周期的必需 cleanup 与 owned-return 事实仍须独立成立。

Resource Identity、Argument Graph、Reconciler 使用同一严格释放判定。canonical cleanup 参数成为 `resource_reference`，携带 producer 参数依赖和 helper 源码证据，复用已存在实例。依赖列表规范化，消除 Graph 与 semantic recipe 仅因顺序不同造成的假冲突。

HarnessPlan 不再按类型给 cleanup 参数补资源；它要求 canonical 现有实例引用，并检查 cleanup invocation 确实绑定其 `resource_instance`。既有生成代码校验继续验证实际传入对象。

## 定向验证

复现命令：

```sh
.venv/bin/python -m pytest -q tests/test_cleanup_connection_smoke.py
```

12 个定向用例全部通过，无失败或跳过。涉及 Agent 的 fixture 使用生产默认 ContextBudget：24 model calls、64 tool calls、96,000 source chars、16 discoveries、depth 2；语义和翻译均为显式 fixture，不调用模型提供商。

| 验证对象 | 结果 |
|---|---|
| ownership → lifecycle → cleanup ownership/argument 的源码复用 | helper 完整定义仍可见，复用不增加读取成本 |
| 过期源码 / 查询缓存 | 拒绝复用 |
| EXCLUDE helper | 不重新授权，不签发 callback cleanup |
| callback userdata 实际为 NULL | 不凭非空假设证明释放 |
| 条件释放、错误对象、重复释放、释放后写对象 | 不投影 cleanup 消费绑定 |
| cleanup 额外参数 | 独立 unknown 保留，不因主资源闭合而自动解决 |
| 多个同类型 producer / 多个释放参数 | 不猜测共享实例 |
| 字段 callback cleanup 完整链 | Context complete、frozen=true、hard gaps=0，Plan 引用同一返回资源 |

完整链用例为 `parse → node_free → invoke → release_storage → free`，从真实静态 artifact 和 issued source 开始。helper 只参与证明，Plan 中实际调用仅为 `parse` 与 `node_free`。固定翻译 fixture 通过正常 `context-generate --build --runtime`，编译成功，6 个运行输入通过。

另外，将生成代码的 cleanup 参数替换成 fuzz data，既有代码校验报告 `canonical_resource_binding_mismatch`，没有接受错误对象绑定。

证据存放于 `artifacts/cleanup_connection_smoke_20261003/`：`results.xml`、`summary.json` 和 `accepted_final/` 中的 Context、Plan、生成代码与 build/runtime artifact。开发中暴露的 canonical 依赖顺序冲突也已修复；早期尝试单独保留，不计入最终通过成绩。

## 验证边界

本轮证明了两个连接点在上述受支持代码形态上可用，没有评价真实 Agent 的 helper 获取稳定性，也没有重新测试真实 `json-parser`。复杂树遍历、loop/switch、完整子资源覆盖、allocator 配对、非平凡错误路径和多实例清理安排仍需独立证明；本轮不把这些未知项改成通过。

持久化配置更新了工具复用、source grounding、construction、resource identity、Argument Graph、Reconciler 和 Plan 版本，避免用旧缓存替代本轮实现的验证结果。
