# 字段 Callback 绑定证明与测试报告

日期：2026-10-03（Asia/Shanghai），基于本地 `v0.2`。

**新增可重算的局部 callback 字段绑定证明，并把已证明的同对象释放接入 Context 的 signed support candidate。它仍是现有源码验证的投影，没有增加工具、Graph 节点类型或 semantic contract。小规模真实模型测试没有证明正例 cleanup 选择率提高；真实 `json-parser` 和固定事实的 Context 集成仍未生成 harness。**

## 1. 实现范围

此前 `find_field_writes` 可以发现函数地址，`get_call_sites` 可以取得实际参数，但这些片段只能作为源码线索。现在 `proof_grounding.analyze` 在已签发、可认证的完整函数体上追踪：

```c
Hooks setting = {0};
setting.dispose = release_storage;
invoke(&setting, node);
// invoke 内部：table->dispose(node, table->cookie)
```

验证器保持对象身份，将实际对象字段值传入精确的 callee formal，再核对 callback 声明、目标函数 ABI、实参数量和已取得的目标定义。直接函数地址、`&function`、局部 aggregate、zero initializer、单字段 designated initializer、同对象指针别名、setter 中的字段赋值和两分支相同目标可以重算；目标名和字段名没有角色特判。

每条 `source_callback_bindings` 诊断包含 root function、完整 invocation site 路径、owner origin、字段、候选目标、argument origins、证明状态、参与的源码定义与 evidence IDs。不同对象、不同调用点独立编号。只有每条受支持路径均出现同一绑定，才签为 `proved`；多个目标、条件缺写、重赋值、ABI 不匹配、未知副作用、缺少完整 body、指针表的嵌套成员和 aggregate copy 等不会获得确定目标证明。

`static` 等 storage/linkage specifier 通过 AST 从目标函数的 ABI 比较中移除，返回类型、参数类型和 qualifier 保留。`&pointer` 与其 pointee 分开；取 callback 字段的地址不等于项目函数地址；歧义项目函数不能回退成 libc intrinsic。

当完整源码还证明 wrapper 在所有受支持路径释放了其确切参数时，Context registry 可以为对应 parent parameter/return 签发既有 `parameter_release` effect。candidate 引用 wrapper、dispatcher 和目标 helper 的完整证据。**该 effect 不自动证明 cleanup 必需性、allocator 配对、userdata lifetime、复合资源覆盖或调用次数。**工具取得的一个函数地址片段仍不能直接授权 cleanup。

诊断随证据重算；`source_callback_bindings_current` 替换此前诊断，避免旧 missing 与新 proved 行在模型历史视图中并存。它不修改 Agent 的 semantic facts，也不替代 Canonical Construction Contract。

## 2. Unknown 与 contradiction

现有 ownership projection 新增 `cleanup_checks`，区分三种结果：

| 源码结果 | 状态 | Gate 行为 |
|---|---|---|
| 所有受支持路径释放确切对象 | proved | 可提供已有 cleanup effect |
| 可重算的路径没有释放对象，或明确释放另一对象 | contradicted | 阻止闭合，允许已有局部修复机制识别反证 |
| 循环、间接绑定缺证据、未知 pointee/conditional origin、缺少定义等 | missing：`cleanup_effect_unproven` | 继续阻止闭合，不能当作旧 proposal 已被否定 |

`contradictions` 仅返回确定的反证；`SemanticProofEvaluator` 单独将 missing effect 加入义务缺口。这避免因验证器能力不足而撤回已有提案，同时没有允许 unknown cleanup 通过 Gate。

## 3. 离线验证与版本

新增 `tests/test_field_callback_proofs.py` **45 个用例**。包含 10 个重命名/构造正例，以及错误 receiver/field、条件目标、重赋值、未初始化指针、未知 mutation、短路副作用、aggregate copy、函数名遮蔽、ABI 不匹配、缺失/截断定义、多个 invocation、释放 userdata、释放指针存储地址、歧义项目 intrinsic、诊断刷新和 missing cleanup 的 Gate 行为等反例与集成检查。

最终完整回归：**578 passed，286.17 秒**。日志见 `artifacts/field_callback_proofs_20261002T161817Z/pytest_final.log`、`pytest_final.xml` 与 `evaluation.json`。工具集合保持 18 个，默认预算仍为 24 model calls、64 tool calls、96,000 source chars、16 个发现函数、深度 2；源码路径分析保留 32 paths、递归深度 2 的限制。

| 项目 | 版本 / fingerprint |
|---|---|
| 旧版对照 | `31a62f5ad4d5738d60e18f68707fd3a1dc0c730f61b7da38a47f42b2bcdacf6c` |
| 真实模型测试的绑定初版 | `283463aaa59222a90ada1534354ce46c07bfbde370ebc41dadafead5bc7a923d` |
| 最终版 | `07c6b7048521b0e50ac42fd8d2ef8b7e9d7a4661653ab7811239c5d3695ad581` |
| Context policy / prompt | `source-grounded-harness-context-v6` / `source-grounded-context-agent-v20` |
| 最终源码验证 / callback 声明 | `source-obligation-grounding-v5` / `callback-declarations-v3` |
| support effect / proposal registry | `subject-support-effects-v2` / `subject-effect-semantic-proposals-v5` |

最终的指针地址、歧义符号和未知 free origin 修复只做离线验证；真实模型结果属于绑定初版，不能作为最终版 native 成绩。开发中间版本的 572、575 项完整回归与一次因后续修复而中止的回归分别保留，不与最终结果合并。configuration 纳入 callback 声明版本，并更新 policy、prompt、grounding、support effect 和 proposal version。

## 4. 固定预算真实模型组件测试

两种开发片段：无条件字段绑定到实际 deallocator；条件绑定到 deallocator 或不释放对象的另一函数。每版每种仅一次可评估调用，共四个 trial。两版源码与 Minimal FT 完全相同；FT 来自显式 fixture，不运行模型 Candidate/Slice，也不供应 semantic facts。

使用实际 `HarnessContextAgent` 调查公开 wrapper 的 `support_decision`，固定 **4 model calls、12 tool calls、24,000 source chars**。请求 `ark-code-latest`、thinking disabled，所有可评估响应实际模型均为 `deepseek-v4-flash-ga-260731`。

| 指标 | 旧版 | 绑定初版 |
|---|---:|---:|
| 正例选择 required cleanup | 0/1 | 0/1 |
| 负例完成结构化保留 unresolved | 0/1，终态 `invalid_output` | 1/1 |
| 错误选择 required cleanup | 0 | 0 |
| model calls / HTTP 200 响应 | 7 | 5 |
| tool calls / tool errors | 13 / 0 | 10 / 0 |
| 重复工具查询 | 0 | 0 |
| source chars | 9,912 | 6,082 |
| total tokens | 71,100 | 49,028 |

两版正例都提交了 `rejected`，没有取得全部 callback 目标定义，也没有签发相应 cleanup candidate。初版更早结束；调用和 token 减少来自提前否决，不能视为调查效率或证明能力收益。旧版负例虽未选择危险 cleanup，但终态未被接受，不能计作完成的正确拒绝。这里没有测量整体 Context completion、compile/runtime 或 coverage。

可评估 trial 共 **12 个成功供应商响应、120,128 tokens**。此前一个旧版正例在模型结束后的统计代码中误用 `actual_model` 字段，轨迹尚未保存；该次独立标为不可评估，额外调用为 1–4 次、token 成本无法恢复，不计入上述分母，也不能将 120,128 写成整轮全部成本。后续 driver 在统计前先保存原始结果、证据和轨迹；没有 mock、重放或预算上调替代这次失败。

## 5. 集成与真实 json-parser

另一个显式 semantic fixture 先取得全部 helper body，再尝试 Context → Plan。结果仍为 **Context incomplete**，硬缺口为 `mandatory_cleanup_unresolved`、`mandatory_requirement_unresolved`、`owned_return_lifecycle_unresolved`；没有进入 Plan/build/runtime。

轨迹显示：在一个 Requirement 内读到的 helper，在切换到生命周期 Requirement 后并未完整保留为可见的源码依赖。已有事实主要携带 parent/wrapper body 的引用，部分内部 helper 在新 scope 或 visible evidence 中丢失，因此 registry 的 callback effect 无法重现。这是源码证据跨义务复用的边界，不能通过把所有已读函数变成 callable support 来绕过。

即使修复可见性，现有 `project_cleanup_consumption` 还围绕 plain release，局部 callback effect 尚未全面下沉到 cleanup 参数的 canonical resource binding。正面的绑定单测不能替代这条下游集成验收。本轮没有为解决该边界继续增加 certificate。

最终版对真实 `/home/luchitong/work/json-parser` 执行九次确定性查询：16,493 source chars，取得默认 deallocator 完整定义及四个间接释放调用。结果仍为 `json_value_free` signed cleanup candidate **0**，wrapper release effect 为 **missing**。树遍历包含 while/switch、parent/child alias、节点内资源释放与 allocator/userdata 配对，超出本轮局部验证范围。此次没有运行完整 Context Gate 或生成 harness；目标 57 个文件未变，git status 仍为空。

## 6. 后续优先项与复核材料

下一步先修两处连接：让已授权、已认证的 helper 源码依赖在相关 Requirement 间可复用并保持审计；让已有同对象释放证明进入既有 cleanup consumption / canonical resource binding。然后用相同小规模正反例验收“补齐缺口 → Context closure → Plan”，再决定是否需要增强路径分析。

Agent 调度也需要防止把“尚未签发 candidate”当作“已经证明不需要 cleanup”：先按 missing proof 读取目标定义，预算内仍无法证明则 unresolved。四个 trial 不足以估计稳定性，尚无跨项目泛化或完整 harness 成功率提高证据，blind cohort 继续暂停。

实验目录：`artifacts/field_callback_proofs_20261002T161817Z/`。`manifest.json`、`frozen/`、`frozen_final/` 保存 native 与最终快照；四个 arm/case 目录保存原始模型记录；`logging_failure.json` 单独记录不可评估尝试；`deterministic_integration/` 保存未闭合的 fixture 集成；`json_parser_probe.json` 保存最终真实项目查询；`evaluation.json` 与 `integrity.json` 分别汇总结果和代码/目标完整性。

只读收集：`.venv/bin/python artifacts/field_callback_proofs_20261002T161817Z/collect.py`。`run_component.py` 会实际调用供应商，不能当作收集脚本重跑。
