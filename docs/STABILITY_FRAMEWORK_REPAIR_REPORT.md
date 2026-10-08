# 框架稳定性修复与 Agent 能力增强

日期：2026-10-05。正式 A 固定 `b2e80a81…` 得到 **9/20**，正式 B 固定 `3dfec961…` 得到 **7/20**，两轮各 20 次 fresh run 均完成，**尚未达到稳定目标**。A 全量回归为 **1055 passed**；B 为 **1232 passed / 4 failed**，不能宣称通过。B 的独立完整性、预算、成本与源码审计通过。当前在隔离候选树补齐 B 暴露的末轮终态纠正、代码校验误拒、上游 scope 诊断和公开 transport deadline，并在新 fingerprint 下验证。全部历史失败与未知用量保留，离线回放不补算 fresh 成功。

本轮修复来自 [旧版固定 fingerprint 重复报告](FROZEN_FRESH_STABILITY_REPORT.md) 及其 [逐失败分析](../artifacts/fresh_stability_f348_20261004/failure_analysis.md)。旧版 `f34899aa9221087c9a92f3c1989826264591983fcdcac129c4146c81d80d0b41` 的正式开发 cohort 为 **7/20** 全链成功：JSON 3/5、五个结构样例合计 4/15；Slice 18/20，Context 7/18，到达下游的 Plan/build/runtime 各 7/7。条件性的 7/7 不能代替全链分母。旧记录保持原样，新版本使用独立目录与 fingerprint。

## 修复范围

修复面向源证据、参数/对象身份、调用位置和终态协议，不按 `json_parse` 或 fixture 入口名制定规则。它强化已签发 choices 的使用、明确已有 proof 的作用范围，并为以前无法投影的有限结构增加 source certificate；未证明的对象、所有权、生命周期和调用关系仍留在 Gate 的缺口中。

| 问题与结果 | 实现与证据 |
| --- | --- |
| Slice 对同一 function 选多个竞争 choice，或多个 unresolved 行缺少问题时，旧反馈只暴露首个错误。本轮一次返回所有重复身份/空问题行，并在最后普通轮次提示紧凑提交；一次协议纠正只使用剩余轮次。 | [models.py](../harness_generation/semantic_slicing/models.py)、[proposals.py](../harness_generation/semantic_slicing/proposals.py)、[agent.py](../harness_generation/semantic_slicing/agent.py)、[终态负例测试](../tests/test_slice_terminal_robustness.py) |
| 第一次 callback smoke 把与 CORE 使用同一对象的 dispose 选成 EXCLUDE/unrelated。本轮仅在完整源证据证明 fresh creator、唯一对象 origin、CORE 字段读取和后续 exact cleanup 时撤回该 EXCLUDE；显式 SUPPORT 或 UNRESOLVED 仍由模型选择。旧的 native choice 和 canonical classification 都经同一边界拒绝，错误反馈包含源证书。 | [source_exclusions.py](../harness_generation/semantic_slicing/source_exclusions.py)、[proposals.py](../harness_generation/semantic_slicing/proposals.py)、[排除边界正反例](../tests/test_slice_source_exclusions.py) |
| Context 提示中反复携带任务与图诊断，使 exact subject 和最终提交规则难以辨认。本轮只压缩 Agent transport 视图，保留 exact requirement、subject、candidate 与证据身份；原始事实、证书和 Gate 输入不变。 | [prompt_projection.py](../harness_generation/harness_context/prompt_projection.py)、[agent.py](../harness_generation/harness_context/agent.py)、[projection 与纠正测试](../tests/test_stability_prompt_projection.py) |
| 输入 buffer/extent、保留输入的 context、cleanup 消费对象容易混淆。本轮明确相关终态调查指导，并在 requirement/input flow 中连接 source-backed producer 与同对象 forwarding，避免把 context 或释放参数默认解释为 fuzz bytes。 | [requirements.py](../harness_generation/harness_context/requirements.py)、[input_contracts.py](../harness_generation/harness_context/input_contracts.py)、[input_flow.py](../harness_generation/harness_context/input_flow.py)、[agent.py](../harness_generation/harness_context/agent.py) |
| callback 的间接 endpoint 与 creator 返回的 userdata 原点未对齐。归一化只连接完整源码证明的同步 forwarding 及唯一对象身份；具体模型事实保留，错误 creator 或多个 dispatcher 原点不能被合并。 | [resource_identity.py](../harness_generation/harness_context/resource_identity.py)、[argument_graph.py](../harness_generation/harness_context/argument_graph.py)、[精确资源与冲突负例](../tests/test_resource_stability_proofs.py) |
| 释放参数、owned return、out pointee 和指针地址存储容易被误作不同或重复资源。本轮只在精确 producer/consumer 与完整释放路径证明成立时投影 cleanup consumption；多个独立调用示例保持原身份，一个新 harness invocation 绑定自己的结果。 | [construction.py](../harness_generation/harness_context/construction.py)、[repair_proofs.py](../harness_generation/harness_context/repair_proofs.py)、[owned-return 调用范围测试](../tests/test_owned_return_invocation_binding.py)、[out pointee/错误 owned 负例](../tests/test_resource_stability_proofs.py) |
| callback 中声明的 `void *` cleanup subject 与实际具体对象类型不一致，导致 same-origin cleanup 仍无法使用。本轮只对 fresh creator、精确 forwarding、非逃逸使用和同一局部对象的 exact release 建立源码连接；owned-return 的未知 release API 只能在该连接与 mandatory lifecycle 一起成立时投影。旧事实保留，显式不同 cleanup API 不覆盖。 | [resource_identity.py](../harness_generation/harness_context/resource_identity.py)、[construction.py](../harness_generation/harness_context/construction.py)、[cleanup 来源与归属测试](../tests/test_resource_stability_proofs.py) |
| 擦除类型的 callback `void *` userdata 已证明引用同一 owned creator 结果，却因缺少 consumer 自身 lifecycle row 被 shared identity 检查阻断。本轮仅对唯一、同步、exact forwarding 和完整 create/use/release 的源链建立 identity reference，要求 producer 已有 owned/until-release 与 mandatory cleanup、consumer 已有 borrowed/during-call；保留原契约，不新增 lifecycle、ownership 或 fuzz root。已有 consumer lifecycle 行或明确冲突不能走桥接。 | [callback_resources.py](../harness_generation/harness_context/callback_resources.py)、[semantic_proofs.py](../harness_generation/harness_context/semantic_proofs.py)、[builder.py](../harness_generation/context_generation/builder.py)、[独立 peer review](../artifacts/stability_callback_reference_peer_review_20261004.json) |
| stream helper 将同一资源声明为 per-context，而源 caller 每次都 fresh create → use → cleanup，导致 reuse 标签阻断整个 Context。本轮保留原声明，单独证明有限 invocation scope，仅对相同 creator/cleanup/type 的两种标签投影有效 per-input scope。Plan 重建该证明；生命周期或所有权缺失仍是 hard gap。 | [invocation_scope.py](../harness_generation/harness_context/invocation_scope.py)、[invocations.py](../harness_generation/harness_context/invocations.py)、[有限调用范围正反例](../tests/test_finite_invocation_scope.py) |
| stream parser 内部 reader 被误作 harness 应独立调用的 API，局部数组和 `sizeof` 容量也没有 canonical 构造。本轮加入窄范围内部调用证书，使 reader 通过已证明的 parent API 执行，局部 storage 生命周期留在该 invocation 中；Plan 独立重建证书并拒绝额外独立调用。 | [internal_invocations.py](../harness_generation/harness_context/internal_invocations.py)、[builder.py](../harness_generation/context_generation/builder.py)、[recipes.py](../harness_generation/context_generation/recipes.py)、[recipe_validation.py](../harness_generation/context_generation/recipe_validation.py)、[validation.py](../harness_generation/context_generation/validation.py)、[内部 stream 正反例与 sanitizer 测试](../tests/test_internal_stream_invocations.py) |

这些 certificate 不等于新增默认契约。例如，完整 allocated-return 证明只允许补齐该 API 自身的 creator 身份；不能推导所有指针都 owned。out-parameter 的 allocated pointee 与存放地址的 storage 分别建模。cleanup 的 `transferred` 消费语义只作用于已经证明的精确释放对象，显式冲突的 owned claim 保留为冲突，不能因另一个对象已正确释放而退休。

内部 stream 证书只覆盖受限 C 源结构：一个顶层 `while` 条件中的唯一直接 helper call、精确 context 参数 forwarding、固定普通 byte array 与同一数组的 `sizeof` 容量、已验证的非逃逸关系。它描述调用位置与 storage 生命周期，不证明 callee 终止、任意 IO 行为、通用内存安全或所有权；复杂分支、未知调用、VLA、pointer rebinding、escaped buffer 和不同 context 的错误连接均不能获得该证书。

## 预算内的 Agent 恢复与严格边界

共享 [BoundedAgentLoop](../harness_generation/semantic_discovery/loop.py) 的新增能力默认关闭，由任务 Agent 显式启用。所有原始失败事件保留，纠正回答重新经过同一 strict validator。

| 能力 | 上限与停止条件 | 离线测试 |
| --- | --- | --- |
| `terminal_guidance_factory` | 在剩余轮次提示完整、紧凑的原生终态；不补问题、不替模型选择 role 或契约。 | [Slice 终态测试](../tests/test_slice_terminal_robustness.py)、[Context projection 测试](../tests/test_stability_prompt_projection.py) |
| Candidate `max_semantic_recoveries=1`、`max_protocol_recoveries=1` | CLI 显式启用，Agent API 仍默认 0。终态 strict validation 失败时，反馈完整错误与已签发 exact evidence IDs，只在剩余普通轮次一次 terminal-only 完整重新提交；未签发 ID 与无效 verdict 继续拒绝。普通 protocol correction 单独至多一次。 | [Candidate terminal recovery 测试](../tests/test_candidate_terminal_recovery.py) |
| `max_protocol_recoveries=1`，Slice 启用 | 截断/未提交终态或可修复行形状错误，只允许在剩余普通轮次中一次 terminal-only 提交；无额外 repository tools 或 ordinary rounds。 | [Slice 终态测试](../tests/test_slice_terminal_robustness.py) |
| `max_provider_recoveries=1`，Candidate CLI、Slice 与 Context 启用 | 仅普通轮次的 `timeout`、`http_429`、`http_5xx` 且还有轮次时继续一次；authentication/client/config/未知 transport 错误、末轮和额外 terminal repair 的失败直接停止。Candidate Agent API 仍默认关闭。 | [provider recovery 测试](../tests/test_bounded_provider_recovery.py)、[Slice provider 稳定性测试](../tests/test_slice_provider_stability.py)、[持久化诊断测试](../tests/test_request_diagnostics.py) |
| `max_semantic_recoveries=1`，Context 启用 | 非 schema 的终态 strict validation 失败后，已有普通轮次内允许一次完整重新提交。原无效事实不会成为 decision；第二次失败、混合调用协议错误或额外 schema repair 中的失败不再扩展。聚合错误的 `to_dict()` 全部放入反馈与事件。 | [semantic recovery 测试](../tests/test_bounded_semantic_recovery.py)、[Context 集成纠正测试](../tests/test_stability_prompt_projection.py) |

`provider_recovery`、`semantic_recovery`、`protocol_recovery` 与 audit counters 区分实际普通轮次恢复和额外 terminal schema repair。Provider 失败保留 `model_error`、category、request diagnostics 和 attempt number；未知 usage 继续记为未知。一次失败可有多个诊断事件，事件数量不能直接相加为 provider 请求数量。

这里的恢复发生在同一次 Agent investigation 中，使用已签发 evidence/choice 和原先可用的普通轮次。**没有 whole-trial retry、resume、成功替换失败或手填 Context 事实。** 仍保留历史允许的最多一次独立 terminal schema repair，并受 Context 全局 model call budget 约束。

第四次 smoke 后，Candidate policy 提升为 `recall-first-entry-validation-v4`，Slice policy 为 `source-choice-semantic-slice-v8`，Context policy 保持 `source-grounded-harness-context-v8` 并将 recovery limits 纳入 run configuration。当前 runner 的 registration 显式登记逐 stage recovery limits：Candidate semantic/provider/protocol 各 1，Slice provider/protocol 各 1，Context semantic/provider/protocol 各 1；Candidate flags 显式传入 CLI。collector 与独立 auditor 按 stage 比较登记配置，普通 rounds、tool calls、source chars 和 output token 预算均保持原值。旧 freeze registration 未登记 limits 时沿用其历史 CLI 行为，不能反向宣称旧 run 已启用新增能力。

第五次 smoke 后新增的 bridge policy 为 `source-callback-resource-reference-v1`，Context policy 提升至 v9、prompt v23、Plan policy v15，run configuration 纳入 bridge version。source-only graph 的 callback forwarding row 自身不带 resource ID；证明沿 authenticated `source_node` 唯一追至 call-site origin，并比较 creator/caller/offset/rid 与独立 exact cleanup connection，不靠 model resource label 填补源图。错误 `source=context` 缺口被路由到该 exact parameter 的 input_binding 调查，不再让已证明的 ownership 反复接收同一缺口。Gate 用当前完整 evidence ledger 重建证书并与 Context retained proof 相等；Plan 再独立重建并拒绝删除/篡改，完成验证后只携带 compact certificate，不放完整 `source_records` 正文。

Candidate 增强专项为 **145 passed**，Slice/provider 增强专项为 **57 passed**。它们覆盖已签发证据的终态纠正、严格拒绝未签发 ID、有界暂态恢复及持久化配置；测试批次有重叠，不能相加为新的独立全量测试总数。旧 **973 passed** 仅对应 `eb6dc975…`；增强后的 `1668b0a1…` 单独全量回归为 **1008 passed**，不能替代后续 source bridge 修复版本的最终回归。

严格负例覆盖：foreign choice/unissued evidence、额外 role 字段、空白问题、重复 function；错误 applicability；partial/wrong release、第二个 concrete cleanup、不同 creator、不同 context、多个 callback 原点；局部 buffer 逃逸或容量不匹配；缺少 mandatory ownership/input/lifecycle 时不能靠内部调用证书通过 Gate。负例与正例一起验证，不能只靠已有开发样例的成功输出判断规则正确。

历史 JSON 失败终态的 [离线 replay 脚本](../scripts/replay_recorded_slice_terminals.py) 重建真实 issued choices 与证据，验证 [replay 记录](../artifacts/slice_terminal_replay_20261004.json)：r01 两次原提交分别一次报告 3、2 个缺失问题；r04 原提交一次报告 2 个重复函数。显式测试纠正保留 unresolved，不自动升级角色。此 replay **0 model/provider calls**，是 validator/诊断验证，不是新的 native fresh 成功。

第一次 callback smoke 的 [最新 v2 离线 replay 记录](../artifacts/slice_callback_exclusion_replay_v2_20261004.json) 按真实工具调用顺序重建相同 evidence IDs，并回放原 native 提交与 canonical Slice：二者均因完整 same-origin cleanup 证书拒绝错误 EXCLUDE。SUPPORT/UNRESOLVED 仍可选择，证据与原 smoke 产物未修改，**0 model/provider calls**。该证书只反证 unrelated exclusion，不产生默认 owned/lifecycle，也不自动提升角色；多 origin、rebinding、escape、partial/double/wrong-address release、static creator、不同 callback context 或不完整/被篡改源证据均不能触发排除约束。

边界复核又发现 CORE 的已释放/可能释放、已定义 helper 的 escape/may-release、creator 发布全局 alias 等反例。v2 因而要求：CORE 任一路径均不释放该 subject；creator 返回的 fresh object 未逃逸；caller 是同一局部变量的 creator → CORE → cleanup 三个精确调用，且变量只出现在初始化与两个精确参数位置。额外调用、alias/store 或其他对象使用不签发证书，包括一些无害额外使用；这些结构仍需显式模型调查和 unresolved。此保守限制避免把 graph 尚未传播的 callee 副作用当作无副作用。

进一步复核发现，fresh allocation 与 effect summary 单独不足以证明 exclusive return：`saved[0]=fresh`、额外 out slot、field/static alias 保存和已定义 callee retention 可能超出 effect interpreter 的完整 vocabulary。v3 源排除证书因此与 Context 共用独立的 exclusive pointer-use guard，保守追踪局部 aliases，拒绝指针 rebinding、额外对象导出和未证明的 callee 使用。它只收紧正向 certificate 的签发边界，不把被拒绝的源结构默认判为实际 escape，也不增加任何角色、ownership 或 lifecycle 默认事实。Slice policy 提升至 v7，configuration 纳入 `source_exclusion_proof_version`，旧 proof policy 的 resume 不能兼容新版本。

## 新冻结与执行协议

第一次开发 smoke 使用 [registration.json](../artifacts/stability_repair_smoke_20261004/registration.json) / [manifest.json](../artifacts/stability_repair_smoke_20261004/manifest.json)。此 fingerprint 只对应第一次 smoke，随后修复使用新的独立冻结与实验目录；不把不同版本合并为正式 cohort。

- fingerprint：`139ea2697eeb454627b8528e4de7152c6a713a6a16752b8f46ab814a97d875c3`。
- 生产清单 **162 个文件**：`harness_generation/**/*.py`、`sfg_builder/**/*.py` 与 `pyproject.toml`；沿用 sorted compact JSON 文件 hash map 的 SHA256 算法。相对旧冻结新增 `internal_invocations.py` 与 `prompt_projection.py`。
- 框架 HEAD：`59b6afb55e382eec3c62427e3273502455315285`；目标仍为 `/home/luchitong/work/json-parser` / `9d50ae5ea2cdeef3b75146c621ec7b26e2e3642f`。工作区修复通过文件 hash 冻结，HEAD 相同不代表代码相同。
- smoke 注册六类各一次，`protocol_role=targeted_development_smoke`，用于发现集成阻断；正式重复实验单独登记。它们不能拼接成同一 cohort 的成功分母。
- source、anchor、dataset role 与旧版一致：`json_parse` 是 known-project-development-regression；callback/shared/owned/out 来自既有 [smoke CASES](../scripts/smoke_argument_graph.py)；[memory_stream](../benchmarks/blind/synthetic/memory_stream/source/api.c) 已作为 synthetic-development-regression 使用，仅覆盖 memory stream abstraction。

修复 Slice 排除边界后，第二次 [boundary smoke registration](../artifacts/stability_repair_boundary_smoke_20261004/registration.json) 于 `2026-10-04T03:39:53.159264+00:00` 单独冻结 `6f26c3fe512face5cf3fc1a104432cf94569cb3c7478801456c2ca309fe0bfd2`，生产 inventory 为 **163 个文件**，相对第一次 smoke 新增 `source_exclusions.py`。schedule 为 callback_context 与 memory_stream 各两次，共四个 fresh trial；边界复核发现反例后已停止并保留真实记录，后续 v2 修复不属于该 freeze。这次同样是 targeted development smoke，不能将第一次 smoke 的其他四个通过补入其分母。

第三次 [boundary v8 registration](../artifacts/stability_repair_boundary_v8_20261004/registration.json) 于 `2026-10-04T07:21:03.838248+00:00` 单独冻结 `cca17e8235e7dbd99b95039d8108a6d60418c1dfe656da27517ea665f0a453fe`，生产 inventory 为 **164 个文件**，包含有限 invocation scope 证明。schedule 同样为 callback_context 与 memory_stream 各两次。源码复核发现内部 reader 对 `memcpy` 等 intrinsic 的局部同名 function-pointer shadow 未完全阻止 source-owned internal invocation certificate，有限 scope 的更严格检查虽已拒绝该结构，较早的 graph certificate 仍必须独立正确。因此停止这次 smoke 与并行 full suite，保留所有原始观察；后续最小 source guard 修复必须使用新的 fingerprint 与实验目录。

第四次 [post-shadow registration](../artifacts/stability_repair_post_shadow_20261004/registration.json) 于 `2026-10-04T07:25:57.349705+00:00` 冻结 `eb6dc9754c2f7d0bc5223250f7516b0415a6ecf5496a23b0a4900d9dcd413f0b`，仍为 **164 个生产文件**。internal invocation proof 升至 v3：callee 中真实的局部 declaration 标识符也进入 intrinsic shadow 检查，不把同名 function pointer 当作系统 intrinsic。callback_context 与 memory_stream 各两次的四个 fresh trial 已完整结束，并行 [同版本全量回归](../artifacts/stability_framework_regression_post_shadow_20261004/pytest.log) 为 **973 passed / 640.78 秒**，[result.json](../artifacts/stability_framework_regression_post_shadow_20261004/result.json) 记录 exit code 0。它是 targeted smoke，不能代替正式的 JSON 5 次与五类结构各 3 次，共 20 次；后续生产修复仍需新的 fingerprint 与最终回归。

第五次 [agent-v4 registration](../artifacts/stability_repair_agent_v4_smoke_20261004/registration.json) 于 `2026-10-04T07:46:54.590707+00:00` 冻结 `1668b0a196f245b4f58d104a2cf0d7f9a78b6c8a21536df3bb2a2f441f626a8c`，生产 inventory **164 个文件**，明文登记新增逐 stage recovery limits。四个 fresh trial 均完整结束；[同版本全量回归日志](../artifacts/stability_framework_regression_agent_recovery_20261004/pytest.log) 为 **1008 passed / 633.76 秒**，[result.json](../artifacts/stability_framework_regression_agent_recovery_20261004/result.json) 为 exit 0、`production_unchanged=true`、`tests_unchanged=true`。它同样是 targeted smoke，尚未开始默认正式 20 次。

当前 [正式 A registration](../artifacts/stability_repair_formal_20261004A/registration.json) 于 `2026-10-04T08:57:05.254386+00:00` 冻结 `b2e80a813875792942e24fc59d92c64388b40dc8310767e996c9c5081411256d`，完整生产 inventory **165 个文件**，新增 `callback_resources.py`。`protocol_role=formal_development_repetition`，schedule 明确 JSON **5 次**与 callback/shared/owned/out/memory_stream 各 **3 次**，共 **20 次**；沿用相同目标、已知开发样例、普通预算、build/runtime 输入和 2 workers。先 JSON phase 后结构 phase，全部独立 fresh roots，不 resume/整 trial retry。对应 [同版本全量回归](../artifacts/stability_framework_regression_callback_reference_20261004/result.json) 为 exit 0、**1055 passed / 648.47 秒**，production/tests 清单在测试前后完全相等。20 次 native trial 已完整结束；正式 A 的实际结果与失败原因如下。

预算与旧 baseline 一致，runner 显式把登记预算传入各 CLI：Validation/Slice 6 rounds、24 tools、48,000 source chars、4096 output；Context 每 requirement 4 rounds、全局 24 model calls、64 tools、96,000 source chars、16 discoveries、depth 2、3 completeness passes、1 terminal repair、8192 output。Agent timeout 60 秒。代码翻译 8192 output、temperature 0.2、timeout 120 秒；build target recipe、C11 target 构建和六个固定 ASan/UBSan/leak-check runtime 输入保持既有协议。

Provider 为 openai-compatible，请求 `ark-code-latest`，thinking disabled，2 workers。实际 served model 与 usage 以各响应记录为准，不能只用请求 alias 代替供应商响应身份。先完成 json phase，再运行结构 phase；每 trial 都使用独立 artifacts 与新 static parser 结果，重新执行 Candidate → Validation → Slice → Minimal FT → Context → frozen Plan → 模型翻译 → build/runtime。

升级的 [runner](../scripts/repeat_fresh_stability.py) 默认仍要求旧报告 fingerprint；新修复必须显式 `--freeze-current`，捕获包含新增文件的完整 inventory。每次前后审计当前代码、frozen、target、fixtures、runner 与 build recipe；pre-directory worker 失败也保存 supervisor 记录。[collector](../scripts/collect_fresh_stability.py) 从持久化 trace 与 supervisor 统计结果；[独立 auditor](../scripts/audit_fresh_stability.py) 交叉核对 inventory/manifest、fresh roots、预算、Gate、Plan、生成调用与成本，审计可信性不能替代稳定性结论。

## 验证与结果更新

第一批与 Slice/shared loop/runner 直接相关的离线专项验证为 **122 passed**，覆盖 aggregate feedback、strict choices、bounded transient/semantic recovery、Context 错误持久化、完整 freeze inventory、正式默认 20 个独立 roots、小规模 selector 和 pre-directory failure 保留。加入 v2 源排除约束后，Slice/shared loop/Context 诊断与 projection 的扩展专项验证为 **144 passed**，含 29 个 source exclusion 正反例。v3 共用 pointer-use guard 后，相同专项 batch 扩展为 **163 passed / 3.58 秒**，含 **48 个** source exclusion 正反例，新增 creator/CORE alias array/out/field/static/known callee retention、interior address、pointer update/offset rebinding 与 proof policy resume 兼容验证。三批测试有重叠，不能相加为独立测试总数。全项目回归将在完整日志及后续源冻结后记录。

第一次 smoke 注册六类各一次：JSON/shared/owned/out 四次全链完成；callback 因错误排除 cleanup 被 Context 阻断；memory_stream 在 Context 阶段被外部中断。记录为 **6 个尝试、5 个完整 pipeline trial、4 次全链成功、1 次失败、1 次中断**。原结果保留，不把中断补算失败或成功，不用已完成下游的条件通过率替代六个计划尝试。停止时完整性记录通过；当前生产源码已继续修复，因此对该旧 smoke 的“当前源码仍匹配”审计不成立，中断 trial 的最终 worker integrity 也未知。这些状态不能写成正式重复完成或稳定通过。

第二次 boundary smoke 的 [completion audit](../artifacts/stability_repair_boundary_smoke_20261004/completion_audit.json) 标记 `review_stop=true`：四个尝试中 callback r02 全链成功，callback r01 与 memory r01 被 Context 阻断，memory r02 在 Context 阶段中断，即 **1 次全链成功、2 次失败、1 次中断**。停止时 source/frozen/runner/target/fixtures 完整性全部为 true；随后生产继续修复，不把当前 hash 不匹配归因于旧试验期间漂移。中断期间已发生的 provider timeout 与预算内 recovery 原事件保留；未响应请求的未知 usage 不填零。

第三次 boundary v8 的 [completion audit](../artifacts/stability_repair_boundary_v8_20261004/completion_audit.json) 记录 **4 个计划 trial、0 个完整完成、2 个中断、2 个尚未启动**。两个 r01 保留为 `worker_interrupted`，两个 r02 为 `not_started`；无 Plan/build/runtime 成功可报告，Context hard gaps 尚未观测而非零。停止理由为 `source_proof_local_intrinsic_shadow_counterexample`，停止时全部 source/frozen/runner/target/fixtures 完整性为 true。[已保存 metrics](../artifacts/stability_repair_boundary_v8_20261004/metrics.json) 共记录 **16 次 model responses、30 次 tool calls、141,736 个已知 tokens**（prompt 129,404、completion 12,332），16 个 `provider_response` 事件，未观测到 provider error/recovery；被停止期间尚未持久化的请求用量仍未知，这些成本是下界。并行 [full suite 停止记录](../artifacts/stability_framework_regression_20261004_v8/stopped.json) 同样标记 review stop，不能报告全量回归通过；原 `result.json` 的 running 状态保持不改。

旧 v8 metrics 的 cohort `completed_trials` 曾把中断 trial 计为完成。新增的独立 [accounting recheck](../artifacts/stability_repair_boundary_v8_20261004/metrics_accounting_recheck.json) 将 completed/interrupted/not_started 分开，[recheck provenance](../artifacts/stability_repair_boundary_v8_20261004/metrics_accounting_recheck_provenance.json) 记录新 collector hash 与 `raw_inputs_mutated=false`。原 metrics、archived collector 和全部 raw inputs 保持原样；完成分母以 completion audit 与修正后的独立统计一致为准。

第四次 smoke 的 [completion audit](../artifacts/stability_repair_post_shadow_20261004/completion_audit.json) 完整登记四个终态，全部 source/frozen/runner/target/fixtures 完整性为 true；[independent audit](../artifacts/stability_repair_post_shadow_20261004/independent_audit.json) 为 `complete=true`、`audit_passed=true`。全链结果是 callback **1/2**、memory_stream **2/2**，合计 **3/4**，不能写成四次稳定通过。

| Trial | 全链结果 | Context hard gaps | model calls / tool calls | 已知 tokens |
| --- | --- | --- | --- | --- |
| callback_context r01 | passed | 0 | 19 / 24 | 312,732 |
| callback_context r02 | candidate-validate_failed | 未观测，未进入 Context | 4 / 5 | 13,220 |
| memory_stream r01 | passed | 0 | 19 / 27 | 323,586 |
| memory_stream r02 | passed | 0 | 19 / 29 | 385,338 |

到达 Slice 的三次均为原生 final decision、无 unresolved/fallback/validation error/protocol recovery。callback 的 CORE 为 handle/parse，SUPPORT 为 acquire/dispose；两次 memory 的 CORE 均为 sv_read/sv_parse_stream，SUPPORT 均为 sv_open_memory/sv_close。到达 Context、Plan、build/runtime 的三次各为 **3/3**，每个 harness 均完成六个固定 sanitizer 输入；这些条件分母不能替代全链的 3/4。

[完整 metrics](../artifacts/stability_repair_post_shadow_20261004/metrics.json) 合计 **61 model calls、85 tool calls、59 successful provider responses**，已知 **1,034,876 tokens**（prompt 961,836、completion 73,040）。两次 Context timeout 均在原预算内使用一次 `provider_recovery` 并完成；两条失败请求 usage 未知，所以总 tokens 是下界。59 个 provider response、2 个 failed_request 和 2 个 provider_recovery 单独记录；另有工具 execution/schema 诊断，不应把它们另算成 provider 请求失败。

两次 memory 的原 `execution-semantics-v2` Plan binding signature 记为两个变体。对持久化 binding projections 的逐字段比较发现，仅两处 `invocation_contract.transitions[].transition_id` 不同；真实 producer/consumer endpoint、参数绑定、调用顺序、有效资源范围和容量语义一致。该 ID 是证明 provenance，仍保留原 v2 metrics；下一轮 collector 将单独升级 signature normalization，再独立重算，不覆盖历史原始记录，也不通过删除真实绑定差异制造稳定结论。

callback r02 的失败是 Candidate 终态引用一个拼错的 evidence ID（少一个 `c`）。四次 provider response 均为 HTTP 200，没有 provider error/recovery，已用 4/6 普通轮次，仍有两轮预算，但该 freeze 的 strict validation 错误后尚未允许一次完整重新提交。当前新实现已在 Candidate CLI 启用有界终态纠正及已签发证据提示，继续拒绝未签发 evidence IDs，原错误事件与用量保留；不自动修正 ID、不改变 verdict、不增加普通轮次或 whole-trial retry。此能力在第四次 smoke 的 freeze 中不存在，后续实现和验证不能补算为其成功。

第五次 agent-v4 的 [completion audit](../artifacts/stability_repair_agent_v4_smoke_20261004/completion_audit.json) 完整登记四个终态且全部 identity 检查通过。[完整只读独立审计](../artifacts/stability_agent_v4_complete_readonly_audit_20261004.json) 的内嵌原始 auditor 结果为 `complete=true`、`audit_passed=true`、`raw_mutations=false`，逐 stage 注册预算与恢复 caps 均一致。全链依然为 callback **1/2**、memory_stream **2/2**，合计 **3/4**。

| Trial | 全链结果 | Context hard gaps | model calls / tool calls | 已知 tokens |
| --- | --- | --- | --- | --- |
| callback_context r01 | harness-context_failed | 2，shared_resource_identity_unresolved | 25 / 26 | 491,883 |
| callback_context r02 | passed | 0 | 17 / 22 | 304,747 |
| memory_stream r01 | passed | 0 | 20 / 34 | 348,029 |
| memory_stream r02 | passed | 0 | 20 / 29 | 437,029 |

Candidate 与 Slice 各 **4/4** 通过；Context **3/4**，到达 Plan/build/runtime 的三次各 **3/3**。合计 **82 model calls、111 tool calls、79 successful provider responses**，已知 **1,581,688 tokens**（prompt 1,479,294、completion 102,394）。共三次 timeout 和三次预算内 provider recovery，三条失败 usage 未知；另有两次 protocol recovery。全部原失败与恢复事件保留，tokens 仍是下界；一次已发生的恢复也不能保证全部同结构 trial 都成功。

失败的 callback r01 在 userdata `source=context` 处已有 canonical creator call 和 callback forwarding，但没有 consumer 自身的 lifecycle row，该 freeze 的 Gate/Plan 要求它以自己的 lifecycle subject 建立 shared identity。该一个身份缺口阻断 root 与依赖，报告成两个 hard gaps，Gate 因而保持关闭，**0 code model calls**。后续 bridge 已在已认证源码、唯一同一资源 origin、精确 creator/forwarding 和已存在 canonical lifecycle 定义证明一致时连接这个 erased callback reference；不默认新增 consumer ownership/lifecycle，不将任意 `source=context` 指针连接到同类型资源。新增证明不能补算第五次 smoke 的失败。

bridge 集成专项为 **260 passed**。[独立 peer review](../artifacts/stability_callback_reference_peer_review_20261004.json) 在真实保存的 r01 上离线重建得到 Gate allowed、0 hard gaps/errors 与 frozen Plan；**14 个**契约/源证据负例拒绝，删除 certificate、错误 RID、篡改 certificate evidence ID 的 **3 个**负例在 Gate 与 Plan 两侧均拒绝。projection 前后 raw facts、ownership、lifecycle、input contract 和 external input flow 完全相同；原 trial 的 **247 个文件**逐 SHA256 未变，生产哈希也未变，**0 provider calls**。审查时 fingerprint 与当前正式 registration 一致，但离线 replay 仍不是 native fresh 成功，也不能代替 20 次重复。

第五次的早期 collector transport projection 曾漏掉 recovery caps 字段，派生 `configuration_audit=false` 与直接读取 raw configs 的原始 auditor 检查不同。[只读审计记录](../artifacts/stability_agent_v4_complete_readonly_audit_20261004.json) 已明确标记 `collector_recovery_caps_projection_issue`；这是 collector 投影缺失，实际注册与执行配置没有漂移。后续修正 collector 仅会另存派生 recheck，不改 raw configs、provider events 或 trial 结果；审计通过也不能消除 callback 的真实 Context 失败。

Smoke artifact roots：[第一次六类 smoke](../artifacts/stability_repair_smoke_20261004)、[第二次 boundary smoke](../artifacts/stability_repair_boundary_smoke_20261004)、[第三次 boundary v8](../artifacts/stability_repair_boundary_v8_20261004)、[第四次 post-shadow](../artifacts/stability_repair_post_shadow_20261004)、[第五次 agent-v4](../artifacts/stability_repair_agent_v4_smoke_20261004)。正式 A 为 [formal A](../artifacts/stability_repair_formal_20261004A)，20 次已全部完成。分母、hard gaps、model/tool calls、已知 tokens、未知失败 usage、provider events 与 Plan 变体分别报告；未进入 Context 的运行不记为零 hard gaps。

只会在相同新 fingerprint 的完整小规模重复结果完成后判断这组已知开发样例是否稳定。n 较小、目标公开且样例已知，不能推断跨项目泛化、Candidate recall、覆盖提高或长期成功率。六个 runtime 固定输入也不等于长期 fuzz 或任意生命周期安全。

## 正式 A：完整结果与新增修复边界

[独立最终摘要](../artifacts/stability_formal_A_readonly_metrics_review_20261004/final_summary.json)、[原始 metrics](../artifacts/stability_repair_formal_20261004A/metrics.json) 与 [完成审计](../artifacts/stability_repair_formal_20261004A/independent_audit.json) 均保留。20 个 trial 全部完成，无整 trial retry、resume 或删失败；执行期间固定生产清单、runner、fixtures、target 和 build recipe。

| 同一 fingerprint 的样例 | 全链成功 | 主要阻断 |
| --- | ---: | --- |
| json_parse | 1/5 | 3 次 Slice native terminal JSON 截断；1 次 owned return cleanup/identity 缺口 |
| callback_context | 1/3 | 1 次 Context 全局预算耗尽；1 次显式错误 owner/release 与后续 borrowed 冲突 |
| shared_context | 0/3 | retained input lifetime、冲突声明、input feeder/state 缺口 |
| owned_return | 2/3 | 1 次 input alignment 未知，旧反馈未精确定位参数/字段 |
| out_parameter | 2/3 | 1 次代码重复 dispose 调用；Plan 正确但翻译未通过严格校验 |
| memory_stream | 3/3 | 三次均完成；运行间有 timeout，均在原预算恢复 |

条件 stage 通过数为 Validation **20/20**、Slice **17/20**、Context **10/17**、Plan **10/10**、build/runtime **9/9**。9 个成功 trial 共完成 **54 个**固定 ASan/UBSan/leak replay。成功的同类 Plan 各只有一个真实 execution binding signature；strict semantic signature 的数量为 memory 3、out 3、owned 2，其余只到达一次，主要差异是源证据/契约 annotation，原文不删除。不能用成功子集推断失败样例稳定。

累计 **332 model calls、519 tool calls、325 provider responses**；已知 **6,021,376 tokens**（prompt 5,667,052、completion 354,324）。**7 次 timeout 的 usage 未知**，总量为下界。已执行 provider/protocol/semantic recoveries 分别 **7/4/1**；protocol events 为 6，含 2 次 declined，不能全算成请求。全部 events：provider_response 325、failed_request 7、provider_recovery 7、protocol_recovery 6、semantic_recovery 1、execution_error 28、schema_error 18、history_normalization 7。95 个 Context attempt groups 的 cost owner 唯一、nonowner counters 为零，trace copies 一致。全部独立源码审计通过，raw artifacts 未改，离线验证 0 provider calls。

完整 Context 中累计 hard gaps **31**：ownership_escape_lifetime_conflict 10、subject_repair_conflict 10、cleanup_effect_unproven 4、state_precondition_unresolved 2，mandatory_cleanup_unresolved/resource_identity_multiple_origins/mandatory_requirement_unresolved/input_constraints_unresolved/core_fuzz_input_path_unresolved 各 1。相同源问题可对应多个 blocked roots，gap 数不等于独立错误数。

新增候选修复明确区分恢复和放宽：合法 terminal envelope 的 malformed JSON 仅在剩余普通轮次、已登记 protocol cap 内请求完整重交，不自动补 JSON 或证据；retained borrowed until_release 仅在 exact owner/mandatory cleanup/retention 源证据同时成立时可退休原 borrowed/during_call，显式错误 owned/release 仍冲突。cleanup investigation 优先合法 discovery 并复用已读 exact release，诊断定位 exact parameter/unknown_fields/retention/state/feeder，不新增默认事实。

代码修复是新的公开预算：`context-generate --max-code-repairs 1` 允许 **最多 2 次** 8192-token 翻译请求，默认 0 保持单次。仅 `invalid_code`/`compile_failed` 可触发第二次，同一 FrozenPlan 和完整 binding/input/cleanup 限制不变。runtime、provider、auth、超时、Plan blocked、existing harness、plan-only 不触发代码重试。第一失败归档 `code_attempts/attempt_0001`，第二响应有唯一位置，metadata 与 collector/auditor逐次核对费用、哈希和 immutable Plan。新 budget 必须登记到新 cohort，不把第二调用补算到正式 A。

## 正式 B：恢复路径验证与仍存缺口

正式 B 的 fingerprint 为 `3dfec96118823cabaa0ed9eaae35dfc49373e84230a040cc561f041e839106d1`，166 个 production 文件。[只读复核](../artifacts/stability_formal_B_readonly_metrics_review_20261004/README.md) 验证完整 20 个 trial、原始 3936 文件 SHA、成本 owner、响应唯一性和同一 Plan 的代码修复链；审计捕获时当前 production 与 B frozen 均一致，之后 C 修订的漂移单独登记，B snapshot 与原始失败不变。

| 样例 | 全链成功 |
| --- | ---: |
| json_parse | 1/5 |
| callback_context | 0/3 |
| shared_context | 0/3 |
| owned_return | 2/3 |
| out_parameter | 3/3 |
| memory_stream | 1/3 |

条件通过数为 Validation **20/20**、Slice **19/20**、Context **9/19**、Plan **9/9**、代码 **7/9**、build **7/7**、runtime **7/7**，共 **42 个** sanitizer 输入。两次代码修复各保留两条独立响应与原 Plan，均未隐藏调用，但最终仍被代码校验拒绝。

累计 **338 model calls、556 tool calls、319 provider responses、19 timeout**。已知 **5,959,110 tokens**，失败 usage 未知，总量为下界。Context 10 个失败中，6 个存在组级 provider 失败，4 个为语义缺口；这只是观察分类，不证明延长 deadline 必然解决。B 没有逐请求 start/end/elapsed 字段，不能将配置 60 秒当作实测耗时。

已确认的 C 修复如下：

- B JSON r02 缺 `open_questions` 属于 schema 形状错误，原错误标成 choice ID 未签发。新增可信 typed selection 异常，区别形状与 foreign choice；末轮共享 extra1 仅允许登记类别完整重交。源矛盾、无效 envelope、超时/auth 和预算耗尽不获得新的 extra。
- B JSON r05 的合法 C++ 指针 cast、shared r01 的 natural byte alignment 被 validator v6 误拒。v7 只允许来源不变的指针 cast，以及 frozen Plan 证明的普通字节类型/纯 typedef；带属性、缺定义的别名、偏移、错误 extent、错误 RID 仍拒绝。[原代码离线回放](../artifacts/stability_validator_compatibility_20261005/final_conservative_replay/replay_summary.json) 两例各完成 4 条 build 命令和 6 个 sanitizer 输入，0 model/provider calls，raw SHA 不变；原 native failure 保留。
- public cleanup 被上游 Slice EXCLUDE 后，Context 不能凭类型相同改 role、填 ownership 或绕过 scope。新诊断区分 `upstream_excluded` 与合法 discovery，有限结构冲突提示不签发证据、callable choice 或事实；multiple origins 与显式冲突继续阻断 Gate。Slice 提示在必要性尚未知时保留 UNRESOLVED 并调查。
- `--agent-timeout 60|120` 为公开配置，默认 60，不增加 ordinary rounds、工具预算或 SDK retries。新请求记录 start/end、monotonic elapsed、deadline 和 `sdk_max_retries=0`；collector 区分 extra terminal 操作、实际 provider 请求和本地 budget stop，auditor 核对登记策略与原始事件。

终态模块候选回归 **365 passed**，validator 候选回归 **163 passed**，公开 deadline/collector/代码费用测试 **84 passed**。这些专项结果不能替代全框架回归或新的小规模重复结果。C 的正式结果将独立登记，不修改 A/B 分母。

## 正式 C 完整结果与 D/E 后续修复

C 固定 `b85dc1b14f8f003a5ceecb9cc7fe60b0080ba5380174d62d100430b65a1e5262`，注册 20 次 fresh run。JSON 阶段 **4/5** 端到端成功，另一次最后普通轮返回 `finish_reason=stop` 的分析文字，未提交 native terminal；已登记的 schema/parse/typed-selection extra1 没有涵盖该协议错误，原失败保留。全部 20 次已完成：JSON 4/5、callback 1/3、shared 2/3、owned/out/memory 各 3/3，总计 **16/20**。条件通过数为 Validation 20/20、Slice 19/20、Context 17/19、Plan 17/17、代码 16/17、build/runtime 16/16，成功 trial 共 96 个固定 sanitizer 输入，仍不能称稳定。

C 完整回归为 **1459 passed / 1 failed，654.39 秒**，生产和测试 SHA 不变。失败只因 [call-order 测试](../tests/test_call_order_investigation.py) 的旧 assertion 要求 investigation v7，实际冻结实现为 v8；独立重现与其余功能断言均归档。为保留 C 注册身份，该 test 在另一隔离树 D 修正。

D 固定 `315d0215efcaaddb6ae6d01410307de6a1bb8fafc27d1e9c84102cf875f338e4`，新增显式 `terminal_native_submission_missing` 类别：完成的零 native-call 响应只能在最后普通轮、共享 extra1 内获得一次完整原生提交请求，不能把 prose 当决策。`length`/未知 finish、混合或非法工具调用、source contradiction、provider/auth 与预算耗尽均不获此入口。Candidate、Slice 和 Context 注册各自 allowlist；Context extra 仍受 global24 限制，不能新增全局模型额度。审计要求原始同轮错误、完成状态、零调用原文和实际纠正请求逐一匹配。

D 还针对代码重复 target cleanup 的真实错误加强翻译/纠正反馈：一个 cleanup section、每个目标 API 一个文本调用位置、所有 storage 活到最后 cleanup。严格 call-count/order 校验不放宽。C shared r01 的 [离线代码回放](../artifacts/stability_C_shared_code_repair_offline_20261005D/summary.json) 按原 Plan 从 duplicate-dispose 的 invalid_code 改为 valid，完成 build 与 6 个 sanitizer 输入；2 次显式离线模型操作、0 provider calls，原 raw SHA 不变，原 native failure 保留。D 专项 **291 passed**；[完整回归](../artifacts/stability_framework_regression_20261005D/result.json) 为 **1477 passed / 635.26 秒**，production 与 tests SHA 均保持不变。D 未启动正式重复；新增的 Context 调度修复会使用另一隔离树 E 重新冻结和登记，避免修改 D 或 C 的已验证身份。


C 的[独立最终摘要](../artifacts/stability_formal_C_readonly_metrics_review_20261005/checkpoint_0050_final/summary.json)记录 **302 model calls、539 tool calls、302 provider responses、0 failed requests**，总 tokens **5,647,579**（prompt 5,294,408、completion 353,171），全部响应 usage 完整，此轮 token 统计不是下界。provider events 为 response 302、protocol recovery 10、execution error 6、extra terminal repair 2、semantic recovery 2、history normalization 2。9 次已执行 protocol recovery 与 10 条 protocol events 分开，后一项包含未执行纠正的终态。284 次请求有真实计时，18 次代码请求耗时未知，不以配置 deadline 代替实测。

C 剩余两个 callback Context failure 分别是复合 lifecycle 更正产生的显式冲突，以及最后 completeness pass 激活了此前未调查的 acquire call-order，但旧 scheduler 没有把新 root 加入当轮 targeted set。后一例只用了 14/24 Context model calls，不能归因于总预算耗尽。E 会重新计算 mandatory frontier，只把没有 resolution/调查尝试的新前置问题放入当前 pass，继续使用已有 24 model calls、64 tools、96k source chars 和 3 passes；不添加默认事实、不替已调查的失败重复购买新尝试。resume 已完成 requirement 继续复用，另存 activation 原因、graph digest 和当轮调度记录。

C 的[独立源码审计](../artifacts/stability_formal_C_sourceproof_audit_20261005/summary.json)完成全部 20 个 trial：Gate 与 frozen Plan 独立重建相同、raw SHA 不变、0 model/provider/network calls；[最终成本审计](../artifacts/stability_formal_C_readonly_metrics_review_20261005/checkpoint_0050_final/independent_audit.json)也通过。审计通过只验证记录可信性，不改变 C 的 16/20 结果。E 完整回归通过后，Main 已按逐文件 SHA 前置条件合入 56 个审阅文件；[合入记录](../artifacts/stability_main_integration_20261005E/result.json)保留原文件备份，Main production fingerprint 与 E 相同，未覆盖其他工作区修改。

## E 完整结果与 F 候选修复

E production fingerprint 为 `480fc105ea1b65bc43c6e21a6b01471ec11b5c1272bc6067db1874cd08d7f0ea`（166 个 production 文件），正式协议仍为 JSON 5 次、五个结构样例各 3 次、2 workers、deadline 120、SDK retries 0、code repair 1。E 的 [启动注册审计](../artifacts/stability_repair_formal_20261005E/launch_identity_audit.json) 与 parent audit 全通过；启动检查前 provider calls 为 0。[完整回归](../artifacts/stability_framework_regression_20261005E/result.json) **1479 passed / 747.42 秒**，source/tests/scripts SHA 均保持冻结身份。正式 fresh 全部完成，**12/20**：JSON 4/5、callback 0/3、shared 0/3、owned 3/3、out 2/3、memory 3/3，仍未达到稳定目标。

E 的阶段条件分母为 Validation 20/20、Slice 20/20、Context 19/20、Plan 19/19、代码 12/19、build/runtime 12/12（72 个固定 sanitizer 输入）。7 次代码失败均触发登记的一次同 Plan 纠正，未得到有效代码。JSON r05 的 3 个 hard gaps 属于同一 owned-return lifecycle 根：公开 cleanup 被 Slice 选为 EXCLUDE，Context 正确保留上游边界而拒绝闭合。[最终成本摘要](../artifacts/stability_formal_E_readonly_metrics_review_20261005/checkpoint_0035_final/summary.json)记录 **319 model calls、594 tool calls、319 provider responses、0 failed requests、6,104,732 tokens**（prompt 5,733,145、completion 371,587，全部 usage 完整）。provider events：response 319、protocol recovery 8、execution error 10、semantic recovery 1、extra terminal repair 4、history normalization 4；293 次请求有实测计时，26 次代码请求耗时未知。成本、终态预算与独立 source Gate/Plan 审计全部通过，原始失败未重分类。

F 在另一隔离树修复 E 暴露的问题：完整已签发的返回对象 consumer body 如果把该指针交给尚未证明的 callee/callback，不再凭未知 effect 签发 unrelated EXCLUDE，而是保留具体调查问题与 UNRESOLVED；SUPPORT、ownership 和 cleanup 仍须独立源证明及模型决策。真实 JSON r05 的[离线证据回放](../artifacts/stability_E_json_effect_replay_20261005F/summary.json)撤回两项不具备充分依据的 EXCLUDE，未新增 source evidence、授权函数或调用模型。独立 policy/interpreter 版本进入 Slice resume 与 Minimal FT 上游认证。

F 的输入绑定校验只合流仍能执行到后续调用的分支，避免把 failure branch 的 `free(copy); return` 污染到正常 live-copy 路径；含 goto/label/break/continue/throw/try 的未建模跳转仍保守保留状态。5 份 E callback/shared 原始 initial code 按原认证 Plan 的[离线编译回放](../artifacts/stability_E_code_branch_replay_20261005F/build_summary.json)全部通过 build 和 30 个 sanitizer 输入，0 model/provider calls、原 raw SHA 不变。手写逐元素复制循环仍不在绑定语法内，F 翻译与纠正提示明确优先使用 Plan 允许的直接 data 或精确 live allocation + memcpy/memmove；不会放宽错源、偏移、提前释放、变异、容量、调用次数或 Gate 检查。

F 已于 2026-10-05 12:14:31（Asia/Shanghai）[冻结并启动](../artifacts/stability_repair_F_launch_preparation_20261005/final_freeze.json)，production fingerprint 为 `4d43a73bc44843cbf1d00d3ffb8ac3ef99ebe54e998bdfc6680574dfd98d4302`（167 个 production 文件）。协议继续为 JSON 5 + 五个结构样例各 3、2 workers、原预算、code repair 1，启动注册和冻结前置检查全部通过。[完整回归](../artifacts/stability_framework_regression_20261005F/result.json)为 **1527 passed / 679.06 秒**，全部 source/tests/scripts/target/environment freeze 检查通过。F 与 E 的 14 个审阅 source/tests 文件已按 SHA 前置条件[合入 Main](../artifacts/stability_main_integration_20261005F/result.json)，保留旧文件备份；合入时 Main production 和 tests 与已验证 F 逐文件相同。F 正式 fresh 已完成 **18/20**，整批尚未稳定。返回资源问题投影限于完整签发源、单层返回指针和同 base-type consumer 的可追踪指针流；它不能作为 `void*` 泛型 consumer、任意 CFG 或跨项目完整覆盖的证明。

F 的[最终只读审计](../artifacts/stability_formal_F_readonly_metrics_review_20261005/checkpoint_0055_final/summary.json)记录 JSON 5/5、callback 2/3、shared 3/3、owned return 2/3、out parameter 3/3、memory stream 3/3。Validation 与 Slice 为 20/20，Context 19/20，Plan 19/19，code 18/19，build/runtime 18/18。全链成本为 **305 model calls、546 tools、5,928,340 tokens**，0 failed requests；semantic recovery 3、protocol recovery 10、code repair 1。callback r03 的冻结 Context 已闭合，代码重复使用非 Plan callback 包装函数而被严格校验阻止；owned r03 已读完整源码却漏填 `src↔cb` 绑定，随后多个依赖一起阻塞。两项原始失败均保留，后续 Context 定向 feedback 与修订验证另记于 [闭合反馈报告](CONTEXT_CLOSURE_FEEDBACK_REPORT.md)。

F 的[首个 JSON5 阶段](../artifacts/stability_formal_F_readonly_metrics_review_20261005/checkpoint_0005_json5_phase_complete/summary.json)已完成 **5/5** 全链，各 hard gaps 为 0；62 model calls、192 tool calls、62 responses、0 failed requests、1,119,393 tokens，2 次普通 protocol recovery、0 code repairs。FT/Slice core/support 各一个集合变体，但 Plan 原始 semantic 与 binding 签名各两个变体：[逐字段记录](../artifacts/stability_formal_F_readonly_metrics_review_20261005/checkpoint_0005_json5_phase_complete/structure_variants.json)保留 r03 `success=nonzero` 与其他 `nonnull`，实际 `json_value*` cleanup guard 均为 `!=NULL`，其他执行绑定相同；`error_cleanup=true/false` 则是尚无独立真值证明的 return 语义注解漂移，Gate 完整性检查不证明其源码语义一致。不能把执行成功率等同于全部注解稳定。

另已准备[同身份确认控制](../artifacts/stability_repair_F_confirm_preparation_20261005/preparation.json)，只在首批 20/20、完整回归与各审计全部通过后启动 15 个独立 fresh roots（JSON 5、结构各 2）；同 F 累计将达到 JSON 10、五类结构各 5，总 35 次，预算与身份不变。F 首批为 18/20，未满足启动条件，确认批次未运行，0 provider calls。

[真实 C callback 调度回放](../artifacts/stability_C_callback_scheduler_offline_20261005E/summary.json)保持原 14 条 provider 输出，仅新增 1 条显式离线 call-order 回答：3 passes、15/24 model operations、18/64 tools、10,509/96,000 source chars，Gate allowed、0 hard gaps/errors；原 C trial 与 raw SHA 不变，0 provider/network calls。回放保留原 C FT 文档，不改旧 commit marker 以冒充 E fresh 上游。新行为回归的旧 scheduler 对照仅剩 acquire call-order 一个 gap；新 scheduler 能询问该前置问题。单 requirement 的显式 offline fixture 上限 80 用于测试三轮修复流程，另一 cap24 负例在本地总预算处正确停止；正式 grouped Context cap24 保持不变。

恢复行为按错误类别处理：终态 parse/schema/登记选择错误在剩余普通轮次或共享 extra1 请求完整重交；最后普通轮零调用的完成响应可请求一次 native terminal；可证明的语义冲突和新前置义务在原 Context 预算内补证据；代码 invalid/compile failure 可在明确 `--max-code-repairs 1` 下按同一 FrozenPlan 请求一次纠正。无效证据、错误资源、源反证与未闭合 Gate 持续拒绝，runtime/provider/auth/budget 失败不会通过修改事实、增加 hidden retry 或重新跑整个 trial 掩盖。

## 复现

先确保现有 `.env` 配置齐全；实验归档不包含凭证。输出目录必须全新。smoke 与正式重复使用不同目录，执行期间不修改 production、runner 或已注册的 ancillary 文件。

```bash
cd /home/luchitong/work/harness_generation
.venv/bin/python scripts/repeat_fresh_stability.py \
  --freeze-current --output artifacts/stability_repair_smoke_NEW \
  --json-repetitions 1 --sample-repetitions 1 --workers 2
.venv/bin/python scripts/collect_fresh_stability.py \
  --experiment-root artifacts/stability_repair_smoke_NEW
.venv/bin/python scripts/audit_fresh_stability.py \
  --experiment-root artifacts/stability_repair_smoke_NEW --require-complete

# 正式默认：json_parse 5 次 + 五个结构样例各 3 次，共 20 次。
.venv/bin/python scripts/repeat_fresh_stability.py \
  --freeze-current --output artifacts/stability_repair_repeat_NEW --workers 2 \
  --max-code-repairs 1 --agent-timeout 120
.venv/bin/python scripts/collect_fresh_stability.py \
  --experiment-root artifacts/stability_repair_repeat_NEW
.venv/bin/python scripts/audit_fresh_stability.py \
  --experiment-root artifacts/stability_repair_repeat_NEW --require-complete
```

受控 selector 为 `--cases json_parse callback_context shared_context owned_return out_parameter memory_stream`；JSON repetitions 允许 1–10，结构 repetitions 允许 1–5。改变 selector/repetitions 后按 registration 的 schedule 分母报告，不能称为完成默认正式协议。
