# Blind evaluation: observed failures

本文件记录实验中的基础设施和判读问题；不修改生产算法、原始 trial、预算或 Gate。最终结果以 BLIND_GENERALIZATION_EVALUATION.md 为准。

## Invalidated V1 infrastructure pilot

`artifacts/blind_generalization_20260929/` 因 evaluator worker 构建配置缺少必要的 `schema_version: 1` 而终止，原始产物保留。20 个完成、4 个开始后中断的 trial 不进入正式盲测成功率。修复的是评测接线，随后重新冻结并创建完全不同的 V2 API 模型和真实项目集合；没有在旧集合中重试挑选成功。

V1 的 callback_setter 自动 false-complete 标记也未经确认：公开结构体允许合法的 stack/field 初始化，旧人工预期和 field 匹配可能过度约束 creator/setter 路线。此标记不能当作已证实的生产 Gate 缺陷。

## Frozen V2 native cohort

`artifacts/blind_generalization_v2_20260929/` 预注册 240 次独立试验：12 个新 synthetic patterns、4 个原始真实 C 项目入口，A/B/C 各 5 次。运行中的生产源码、评测源码、fixture、schema 和预算均保持冻结。

### Callback annotation adjudication exception

原始 evaluator 在直接 callback 的 declaration field 为 `null` 时可能执行 string + None，抛出 TypeError。首次观察到 `libcsv_callback/C/4`；底层 worker 已正常保存 `harness-context_failed` 和 incomplete Gate 产物。异常只发生在 worker 退出后的 supervisor 判读，不影响原生模型轨迹。

本轮不修改运行中的 evaluator。异常行保留为 `unverified_evaluation_failure`，仍进入分母。收集完成后可以在独立、版本化 post-hoc 结果中恢复原始阶段指标并进行契约审计；不能覆盖原始 summary 或 evaluation。没有新的模型调用、pipeline retry 或 paired replay。

### Provider terminal repair failures

部分冻结的 terminal-repair 请求返回 HTTP 400。原始 trace 保留 `model_error`、phase 和 HTTP status；不更换 provider、prompt、工具协议或追加预算。这类失败单独标记 provider_error，不能全部解释为 deterministic rules 的语义覆盖不足。

### Interpretation limits

Gate incomplete/invalid 时，未产出的必要契约会在自动 necessary-contract comparison 中表现为 incorrect；这表示部分产物没有满足 ground truth，并不意味着 Gate 放行了错误。没有运行代码生成时，compile/runtime 为未执行，不能称作编译或运行失败。零 complete 样本不能用来证明 false-complete 风险低。


## Final V2 availability and collection status

240/240 预注册 fresh attempts 已完成，生产/evaluator/benchmark freeze checks 均通过。142 次取得模型响应，98 次没有响应；104 次受 HTTP 429 影响，47 次受 HTTP 400 影响，另有 6 次无 HTTP status 请求错误；错误类别可重叠，合计 154 次有 provider error。只能确认服务端拒绝，现有 trace 无法区分具体限流或额度项。

Context complete 0/240，实际 Plan/code/compile/runtime 尝试均为零。无 provider error 的 86 次中有 73 次进入 Context，亦全部被 Gate 拦截。这是诊断子集，不替换正式分母，也不满足每 case/config 五次无错误完整模型轨迹的稳定性验证。

原生 runner 的 exit 1 来自唯一 supervisor TypeError，240 次采样和最终冻结校验均已完成。`posthoc_v2/` 在 sampling 完成后追加已存阶段、成本和 provider 可用性统计；没有 callback checker 修复、模型调用或重跑。原始失败和缺失语义原样保留。


## Provider recovery replication paused by user

2026-09-29 同一 frozen V2 实现与目标集启动独立复测；用户要求暂停后，进程组停止，native runner / worker 全部退出。完成 52 次、中断 4 次、未启动 184 次，原始 partial summary 保持原样。已完成行 Slice 45/52、Context complete 0/52，Plan/code/compile/runtime 均未尝试。52 次都有模型响应，无 HTTP 429；16 次出现 HTTP 400，13 次无 HTTP status 错误，多标签合计 23 次受影响。29 次无 provider error 的试验中有 22 次进入 Context，也全部被 Gate 拦截。

`libcsv_callback/B/4` 再次出现 frozen supervisor 的 callback field=null TypeError；独立观察提取只恢复已存阶段/成本，语义保持 unverified。四次中断试验都已通过 minimal-ft，Context 尚无最终 Gate 结果，按用户中断的删失观测保存，不算语义失败。`pause_record.json` 与 `paused_collection/` 保留分区、摘要和成本下界，不新增模型调用或重试。完整部分报告见 [复测暂停报告](BLIND_GENERALIZATION_RETEST.md)。
