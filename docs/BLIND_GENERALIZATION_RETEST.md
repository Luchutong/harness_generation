# 模型服务恢复后的复测：暂停收集报告

2026-09-29，按用户“暂停测试，收集结果，写入报告”的要求停止全部 native runner / worker。**计划 240 次，已完成 52 次，启动后中断 4 次，未启动 184 次。** 不再发起模型请求；本报告是部分 cohort 的观察结果。原始 summary、trial、trace 和上一轮结果均未覆盖。

**已完成试验：Slice success 45/52（86.5%），Context complete 0/52；Plan、代码生成、编译、runtime 均未尝试。** 52 次都取得模型响应，未观察到 HTTP 429；23 次出现请求错误。29 次无 provider error 的试验中，22 次进入 Context，也全部未获生成许可。当前证据仍不足以证明端到端跨项目泛化。

## 1. 实验身份与暂停边界

- 本轮为同一 V2 目标集的独立 native replication，**不是新一批未知目标**，也不替换上一轮失败。12 个 synthetic API 模型与 4 个 pinned 真实 C 项目入口保持相同。显式 anchor 不评价全项目 Candidate recall。
- 分支 `v0.2`；HEAD `11c27c084a0b96c4c9ca016721b7ddb8d7536d5f`，包括此前冻结的本地未提交实现。production fingerprint：`d2b183cb70503604b98e7024790f93f4829e513a9005fed7f26a60a0583988f9`。
- requested `ark-code-latest`，served `deepseek-v4-flash-ga-260731`；provider `openai-compatible` / Ark，thinking disabled；未改变模型、prompt、Gate、工具、启发式或预算。
- A/B/C 各 case 原计划 5 次，4 workers，schedule seed 20260929；模型 seed 未指定。A/B 是评测侧证据投影消融，C 使用当前全部规则；其他条件相同，具体定义沿用[正式报告](BLIND_GENERALIZATION_EVALUATION.md)。
- Candidate/Slice 每阶段 6 rounds、24 tools、48k source chars、4096 output tokens；Context 每组 4 rounds、全局 24 model calls、64 tools、96k source chars、8192 output tokens；code 8192 tokens / temperature 0.2。本轮未到 code。
- 服务健康检查 2 次成功，共 629 tokens，独立记录，排除 native 指标。健康检查成功并未消除实际 pipeline 请求错误。
- 启动时间 `2026-09-29T02:04:41.513139+00:00`（北京时间 10:04:41）；停止动作是向 native 进程组 139710 发送 SIGTERM。精确发信号时间没有单独记录，不能将收集时间当作暂停时间。
- 收集时间 `2026-09-29T03:08:12.849446+00:00`。生产、root runtime dependencies、native evaluator、benchmark 与 ground-truth schema 的冻结校验均通过；收集前后 native trial 文件摘要和两个 cohort 的原始 summary 摘要一致。
- 已完成 52/240 = 21.7%；各 case/config 完成数为 0–3，**没有任何单元达到预定 5 次**。异步完成前缀和用户暂停造成样本不平衡，不能估计稳定性或做 A/B/C 因果比较。

## 2. 已完成试验的阶段结果

成功率只使用 52 个完成 native worker / supervisor 处理的试验作为当前描述性分母。中断 4 次属于删失观测，184 次未启动；两者不充当失败或成功。正式预注册 240 次重复实验尚未完成。

| Config | 完成 | Candidate accepted / unresolved / rejected | Slice completed / with unresolved / invalid / 未运行 | Slice success | Context incomplete / invalid / 未运行 | Context complete |
| --- | ---: | --- | --- | ---: | --- | ---: |
| A | 15 | 14 / 0 / 1 | 8 / 6 / 0 / 1 | 14 | 10 / 4 / 1 | 0 |
| B | 16 | 15 / 0 / 1 | 9 / 6 / 0 / 1 | 15 | 10 / 5 / 1 | 0 |
| C | 21 | 17 / 4 / 0 | 8 / 8 / 1 / 4 | 16 | 10 / 6 / 5 | 0 |

合计 Candidate accepted 46、unresolved 4、rejected 2；1 次 invalid output 与 verdict 分类重叠。Slice completed 25、completed_with_unresolved 20、invalid 1、未运行 6；成功包含 with-unresolved，不能视为全部必要 API 已闭合。Context incomplete 30、invalid 15、未运行 7。
Context complete 0，complete-but-invalid 0，complete-and-runtime-valid 0；已完成行均未获生成许可。Plan/code/compile/runtime 的实际尝试和成功数均为 0，条件编译和运行成功率为 N/A，不能称为“编译失败 52 次”。confirmed false-complete 事件没有观测到；零 complete 样本使其条件风险为 N/A，尚未验证 Gate 放行后的 soundness。

## 3. 各 API 模型及真实项目

下表 A/B/C 列是完成数，不是成功数；hard gaps 只统计有完整 Context 产物的试验。所有行 Context complete 均为 0。

| Case | Set | A / B / C 完成 | Slice success / 完成 | Hard gaps 均值 / 最大（观测数） |
| --- | --- | --- | --- | --- |
| `configured_decoder` | blind_synthetic | 1 / 1 / 2 | 3/4 | 5.00 / 11 (3) |
| `output_handle` | blind_synthetic | 0 / 0 / 2 | 2/2 | 3.00 / 4 (2) |
| `helper_allocated` | blind_synthetic | 0 / 2 / 0 | 1/2 | 12.00 / 12 (1) |
| `saved_allocator` | blind_synthetic | 2 / 0 / 3 | 5/5 | 12.20 / 20 (5) |
| `aliased_refcount` | blind_synthetic | 0 / 2 / 2 | 4/4 | 8.75 / 11 (4) |
| `private_session` | blind_synthetic | 1 / 2 / 2 | 5/5 | 2.60 / 4 (5) |
| `registration_object` | blind_synthetic | 2 / 0 / 0 | 2/2 | 13.50 / 15 (2) |
| `three_level_callbacks` | blind_synthetic | 1 / 0 / 1 | 1/2 | 4.00 / 4 (1) |
| `signed_pull_reader` | blind_synthetic | 1 / 1 / 1 | 2/3 | 20.50 / 23 (2) |
| `three_feed_transaction` | blind_synthetic | 1 / 1 / 1 | 3/3 | 8.00 / 14 (3) |
| `paired_snapshots` | blind_synthetic | 2 / 2 / 1 | 4/5 | 8.50 / 17 (4) |
| `out_memory_stream` | blind_synthetic | 2 / 0 / 1 | 3/3 | 14.67 / 29 (3) |
| `tomlc99_owned_string` | blind_real | 0 / 1 / 1 | 2/2 | 7.50 / 11 (2) |
| `expat_opaque_feed` | blind_real | 1 / 1 / 0 | 2/2 | 15.00 / 18 (2) |
| `libcsv_callback` | blind_real | 0 / 1 / 2 | 3/3 | 23.67 / 30 (3) |
| `mpack_stream_tree` | blind_real | 1 / 2 / 2 | 3/5 | 11.67 / 13 (3) |

已保存 Slice CORE 的 46 次观测：micro precision / recall 均为 91.2%（TP 52、FP 5、FN 5）；有 Context support 集的 45 次观测：92.3% / 84.7%（TP 72、FP 6、FN 13）。这些是条件 API 集合重合度，不是全项目 Candidate recall，也不是端到端契约正确率。额外合法 helper 不自动构成错误；MPack 的合法 initializer 替代路线未在原始 support-set 分数中归一化。

## 4. Provider 可用性与判读异常

| Config | 完成 | 有模型响应 | HTTP 400 | HTTP 429 | 无 HTTP status 的错误 | 无 provider error | 无 provider error 且进入 Context |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 15 | 15 | 3 | 0 | 4 | 9 | 8 |
| B | 16 | 16 | 4 | 0 | 5 | 10 | 9 |
| C | 21 | 21 | 9 | 0 | 4 | 10 | 5 |

16 个 trial 有 HTTP 400，13 个有无 status 的请求错误，合计 23 个受影响 trial；类别可重叠。trace 中 terminal_repair 错误影响 17 个 trial，exploration 10 个、terminal_budget 1 个，亦可重叠；不能把这些请求问题全部归因于语义规则。无 status 错误的具体服务端原因尚未确认。
`libcsv_callback/B/4` 的 worker 已保存 `harness-context_failed` / incomplete，但 supervisor 遇到 callback declaration field=null 导致 TypeError。原始行保留为 adjudication_error。独立观察提取仅恢复其阶段、已记录成本、API 集合与规则命中，语义各维度仍为 unverified；未修改 frozen callback checker。该次仍计入 52 次完成试验，不填补语义成功。

## 5. Context 瓶颈和规则命中

失败标签允许重叠：argument construction unknown 42/52、lifecycle unknown 36/52、ownership unknown 30/52、state unknown 29/52、input binding unknown 21/52、return semantics unknown 16/52、callback unknown 13/52、resource identity unresolved 12/52、identity conflict 4/52。缺少必要事实的 incomplete/invalid 产物在 necessary-contract comparison 中也会标为 incorrect，这并非错误放行事件。
45 份 Context 的 hard gaps 均值 10.38、中位数 9、最大 30；soft unknowns 均值 12.71、中位数 1、最大 156；API closure 大小均值 2.98、中位数 3、最大 5。`private_session` 平均仍有 2.6 个 hard gaps，`output_handle` 为 3；`signed_pull_reader` 为 20.5、`libcsv_callback` 为 23.67。部分较小生命周期样例同样未闭合，不宜仅以大型 API 的 requirement 数量解释失败。

| C 组规则 | 应用 trial / C 完成 21 | 状态解释 |
| --- | ---: | --- |
| `cleanup_consumption` | 1/21 | did_not_fire=20, fired=1 |
| `creator_return` | 0/21 | did_not_fire=21 |
| `local_state_transition` | 0/21 | did_not_fire=21 |
| `nul_contract` | 0/21 | did_not_fire=21 |
| `ordering_projection` | 11/21 | fired=11, did_not_fire=10 |
| `public_callback_object` | 0/21 | did_not_fire=21 |
| `resource_identity` | 5/21 | produced_unresolved=11, did_not_fire=5, fired=4, blocked=1 |

identity 的 applied 包含被 validator blocked 的投影；命中不等于事实正确。C 组只有 `configured_decoder` 和 `private_session` 各 1 次 resource identity 必要检查为 correct，但整个 Context 仍被 Gate 拦截。creator-return、public callback construction、local state-transition 证书零命中；cleanup consumption 仅在 private_session 命中 1 次。结果支持继续调查参数构造、局部生命周期闭合和 callback ctx construction，却不足以衡量证书的端到端成功率增益。
静态表示边界及证书 proof subset 仍见[正式报告第 16 节](BLIND_GENERALIZATION_EVALUATION.md#16-narrow-deterministic-proof-subset)。本轮没有进入 Plan/runtime，不能把源码中调用实例、refcount 或 repeated feed 的限制当作实测崩溃。

## 6. 成本与中断试验

| Scope | Model calls | Tool calls | Prompt tokens | Completion tokens | Total tokens | 记录 source chars |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 完成 52 次 | 1,385 | 2,700 | 11,584,046 | 993,960 | 12,578,006 | 1,863,249 |
| 中断 4 次：已保存下界 | 43 | 90 | 282,691 | 19,375 | 302,066 | 52,311 |

合计已记录 1,428 model calls、2,790 tool calls、12,880,072 tokens；另有健康检查 629 tokens。完成试验平均耗时 239.95 秒、中位数 241.37 秒、最大 494.82 秒；并发耗时不能按单 trial 均值直接当作实验墙钟时间。
中断试验的分组 trace 先按 response id / 唯一事件前缀去重，避免多个 requirement 保存同一请求而重复计费；Context metrics 尚未落盘，因此这些 call/tool/source/token 值只代表保存下界。未完成请求、未返回 usage 的错误和停止时尚未保存的轨迹都未知，不能当作零成本，也不能推断实际账单。

| 中断 trial | 最后保存完成阶段 | 保存的 Slice success | Context / Plan / runtime 最终结果 |
| --- | --- | --- | --- |
| `helper_allocated/C/4` | minimal-ft | 是 | 用户中断，未知 |
| `out_memory_stream/B/2` | minimal-ft | 是 | 用户中断，未知 |
| `output_handle/C/5` | minimal-ft | 是 | 用户中断，未知 |
| `registration_object/C/4` | minimal-ft | 是 | 用户中断，未知 |

4 次都已经通过 minimal-ft，正在 Context 阶段；没有最终 completeness/metadata。pipeline 中 `status=not_started` 是冻结 worker 只在退出阶段改写状态造成的旧 checkpoint 字段，stage_exits 才能说明已完成阶段。它们不算 Context incomplete 或 semantic failure，不加入 52 次阶段成功率分母。

## 7. 与上一轮的关系及证据归档

| Cohort | 完成 / 计划 | Slice success | Context complete | 有模型响应 trial | HTTP 429 trial |
| --- | ---: | ---: | ---: | ---: | ---: |
| 原始冻结 V2 | 240/240 | 127/240 | 0/240 | 142/240 | 104 |
| 服务恢复复测，用户暂停 | 52/240 | 45/52 | 0/52 | 52/52 | 0 |

两轮的样本量、case/config 构成及服务可用性不同；本表只描述已保存结果，不能由 Slice 比例变化推断生产规则提升，也不能与原轮合并后声称完成了预算匹配的五次重复实验。未启动作业不补跑，中断作业不恢复；本次仅收集与报告。

- [原始复测 summary](../artifacts/blind_generalization_v2_retest_20260929_1003/summary.json)：52 行 native 结果，保持原样。
- [暂停记录](../artifacts/blind_generalization_v2_retest_20260929_1003/pause_record.json)：计划/完成/中断/未启动分区、冻结核验、两个原始 summary 的摘要。
- [独立收集 summary](../artifacts/blind_generalization_v2_retest_20260929_1003/paused_collection/summary.json) 与 [逐次 CSV](../artifacts/blind_generalization_v2_retest_20260929_1003/paused_collection/trials.csv)：完成与删失行分别标记，含 artifact_root。
- [aggregates](../artifacts/blind_generalization_v2_retest_20260929_1003/paused_collection/aggregates.json)：各 case/config 的实际完成数、尺寸分布、语义检查和请求错误。
- [观察提取代码](../artifacts/blind_generalization_v2_retest_20260929_1003/paused_collection/analysis_code.py) 与 native_artifact_digests.json：不调用模型、不修复语义判读、不覆盖原始产物。
- [正式 V2 报告](BLIND_GENERALIZATION_EVALUATION.md)与[异常记录](BLIND_GENERALIZATION_OBSERVED_FAILURES.md)：原轮 240 次结论保留。

此前完整单元/回归检查 298 tests passed；暂停收集完成后另核对冻结身份、分区计数、产物不变和 native 进程清零。单元/回归成功与 reference harness 可编译运行都不充当本轮生成 harness 的端到端成功。
