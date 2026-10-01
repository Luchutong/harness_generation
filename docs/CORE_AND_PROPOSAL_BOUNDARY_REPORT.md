# CORE / Semantic Proposal 边界重构与六类重复实验

2026-10-01，依据本地 `v0.2` 继续开发。本轮只收紧 CORE、声明主体及 support activation 三个边界，没有扩充 Agent 工具集合，没有提高预算，没有启动新的 240 次 blind cohort。

离线回归 **399 passed**。六类各五次 fresh native，共 **30 次**：Slice **14/30**，Context complete **0/30**；14 次 Context incomplete，16 次停在 Slice，代码生成/编译/runtime 均未执行。有效 FT 中 `usage` CORE 为 **0/14**，48 条 ownership 主体全部通过声明重放，104 条 accepted dependency 均携带签发 candidate ID。边界约束得到实际证据，但有效 Slice 率下降、Context 未完成，不能宣称端到端稳定性或泛化改善。

## 实现边界

### CORE inclusion proof

新增 `semantic_slicing/core_proofs.py`，版本 `core-inclusion-proof-v1`。Slice policy 为 `proved-core-semantic-slice-v2`。非 anchor CORE 不再仅凭 reason 标签、wrapper delegation、示例 caller、共享类型或旧 FT 成员身份进入：分类提交时重算源码证明，证明写入 classification；Minimal FT 再从同一冻结 snapshot 与签发 evidence 重放，不能通过修改存储的 proof 改变结果。

允许的证明为 accepted anchor、anchor 实际观察的处理调用结果、anchor 读取的参数依赖字段更新、读取 anchor 输入依赖返回字段，以及通过签发 caller 实际绑定的处理 callback。非 anchor 证明需要 anchor 与该函数的完整当前 run 源码；纯参数准备/转发 wrapper 会得到 `core_inclusion_unproven`，模型随意换 reason 也不能通过。输出字段分析与 External Input Flow 共用保守静态函数。

这些证明限定 API 的源码关系，不是完整的跨过程语义最小性证明。字段写读关系仍不能单独证明同一运行时对象、必需调度、所有路径上的必要性或 ownership；后者仍由 Context/value-flow/Gate 验证。显式接受的 anchor 即使是 wrapper 仍须保留，Candidate 的选择与非 anchor 纳入是两个边界。未分类的 frontier 留作 unresolved，不能因 CORE 变小就声称 FT 正确。

### Signed semantic proposals

新增 `harness_context/proposals.py`，版本 `signed-semantic-proposals-v1`。框架从冻结函数/类型声明签发稳定主体 ID；ownership 区分 `PointerParameter`、`PointerReturn`、`OutParameterPointee`、`ResourceObject`，普通 scalar parameter/return 和 scalar struct field 没有 ownership subject。OutParameterPointee 除指针深度外还要求函数中的实际解引用写入，storage 与 pointee 有不同 ID。

Native terminal schema 5 使用固定 requirement slots，固定 predicate/function、声明参数、ownership subject ID、已签发 evidence 和允许的 API 选择。scalar return 的 nullable/owned 固定为 null。主体与参数/API 枚举分别生成，避免 schema 对象别名导致枚举串位。已有工具成功返回后刷新 registry 与下次 terminal schema；单个 requirement 与 grouped requirement 共用 compact wire 格式。

展开后的 canonical artifact 保留可读 parameter/return/field 和 subject kind/ID；旧 expanded 回归输入仍经过同一 declaration/source registry 校验。Gate 分别要求 out storage 与 pointee ownership，pointee 不能替代 storage；identity 与 reconciliation 不把指针 cell 的 ownership resource ID 自动改写成产生的对象。

### Support activation

框架仅将已经通过现有 repository tools 获得完整 body、处于授权作用域且未 EXCLUDE 的 API 签入候选目录。signature/type/ABI 关系提供 parent、角色与参数/返回值绑定候选，包括 pointer return/out creator、兼容 cleanup/init/state consumer、callback 参数或结构体字段 ABI。签名查询本身不会签发候选；角色候选明确标记 `necessity_proven=false`，不自动证明 API 必要性。

模型在对应 semantic fact 的 API 字段选择候选，native wire 的 `discovered_api_dependencies` 必须为 `[]`。框架由同一 fact 派生 canonical dependency，绑定 candidate ID/source/parent/role，并保持 initialization/cleanup/callback 的 mandatory/optional 标记；模型不再重复自由生成另一个 dependency 真相来源。expanded compatibility 输入与缓存重验也拒绝未签发的角色组合、API 与候选 ID。

## 离线验证

全量回归：399 项通过，70.82 秒。`pip check` 通过，`git diff --check` 无错误。新增 15 项边界回归，覆盖 wrapper reason 绕过、共享类型/非观察字段、签名与完整 body 的区别、动态候选、ownership 空/伪造/标量主体、参数与 API 枚举独立、out storage/pointee、optional activation 和 native 自由 dependency 拒绝。现有 creator-with-args、out storage、bounded scalar 的真实 clang 编译/runtime 回归保留；语义 proposals 属于明确标注的离线 fixtures，不能计入 native 成功率。

原 bounded-scalar 正向回归曾把准备参数的 `usage` 纳入 `parse` CORE。本轮改为显式接受 `usage` 为 anchor，再以它实际观察的处理结果证明 `parse` 纳入；这验证已有 recipe lowering，但不能替代真实实验中以 `parse` 为 anchor、wrapper 留在 evidence frontier 的输入路径问题。

## 冻结与实验设计

Production fingerprint：`584968f8ac6ae5680f64641d4398328247ebe01f86b8d2af909ad01101fb5d8c`。

源码归档：`artifacts/core_proposal_validation_20261001/source_snapshot/`，172 文件；manifest SHA256：`f4391480eaccf1c65eef0ba07562696718793030489e81d050201be11498a20d`。

批次：`artifacts/core_proposal_native_repeat_20261001/`。使用 `.env` 当前配置的 openai-compatible / `ark-code-latest`，thinking disabled；30 次响应中的实际 served model 均为 `deepseek-v4-flash-ga-260731`。六类 bounded scalar、creator-with-args、out-parameter、shared context、owned return、callback context，各五次，workers=2，无 resume、无替换失败重试、无 Mock/Recorded fallback。

Candidate Validation 与 Slice 各 max_rounds=6、max_tool_calls=24、max_source_chars=48000、输出上限4096。Context 保持 max_total_model_calls=24、max_tool_calls=64、max_source_chars=96000、discovery=16、dependency_depth=2、completeness passes=3、terminal repair=1、每 requirement 4 rounds、定向 follow-up 2 rounds；Context/code 输出上限8192，agent timeout60s。完整限制见 registration 与每 stage configuration。

实验类型仍为 Development / Regression：合成 C fixtures、parser-only 静态入口、显式 `parse` anchor；不能报告 Candidate recall、真实项目 coverage 或跨项目泛化。每个 fresh trial 都尝试 candidate → slice → FT → context → plan → code → compile/runtime，后段以真实 Gate 放行为前提；未运行阶段单独统计，不记作零 hard gap。新的 token 汇总包括 code-generation response；group trace 仅按 cost owner 计一次，local budget stop 与 provider 请求错误分开。

## Native 结果

### 总体与分类结果

全部 30 次 Candidate Validation accepted；这只表示预选 anchor 的验证结果，不能作为 Candidate recall。Slice 14 completed、16 invalid；FT 4 completed、10 completed_with_unresolved、16 not_run。所有进入 Context 的 trial 都是 incomplete，generation_allowed=false，实际 code/compile/runtime attempts=0，不能把它们称作编译失败。

| API 类别 | Slice 成功 / 5 | Context 运行 / complete | 有效 CORE 大小 | Context hard gaps（仅运行项） | Context model / tools | 整链 tokens |
| --- | --- | --- | --- | --- | --- | --- |
| bounded_scalar | 2/5 | 2 / 0 | 1 | 1, 11 | 5 / 9 | 393,351 |
| creator_with_args | 3/5 | 3 / 0 | 1 | 11, 13, 3 | 55 / 114 | 1,165,533 |
| out_parameter | 2/5 | 2 / 0 | 1 | 1, 12 | 25 / 53 | 650,119 |
| shared_context | 1/5 | 1 / 0 | 2 | 4 | 19 / 44 | 654,534 |
| owned_return | 2/5 | 2 / 0 | 2 | 18, 1 | 17 / 42 | 853,503 |
| callback_context | 4/5 | 4 / 0 | 2 | 20, 18, 29, 33 | 84 / 178 | 2,168,798 |

CORE 集合在通过 Slice 的同类重复中一致：前三类仅 parse；shared 为 supply+parse；owned 为 parse+observe；callback 为 handle+parse。这是有效提交中的条件统计，不能推出所有 trial 的 FT 边界已稳定。三份有效 FT 仍把 usage 放入 SUPPORT（out_r01、creator_r05、callback_r04），候选边界尚未完全收敛。

### CORE 与 support 失败定位

16 次 Slice invalid 的第一拒绝原因：support wrapper 未证明具体 setup/lifecycle 理由 **13** 次，CORE inclusion unproven **2** 次，role/reason 不兼容 **1** 次。两个实际 usage CORE 提案被 proof 拒绝；旧 support wrapper 规则的 13 次拒绝不能冒充新 CORE proof 的成果。框架没有静默降级这些提交为成功。

签发目录可以阻止未读源码的 API、未注册 role/API/parent 组合与伪造 candidate ID，但其 signature profiles 仍是候选关系，并非必要性证明。creator_r05 的 usage 被选作 required configuration，其 registry 仅记录与 parse.src 的 byte-pointer signature 关系，仍生成额外 support 义务。这说明目前对每个实际 parameter/resource 的角色与必要性消歧尚未闭合；不能把“有 candidate ID”当作“该 support API 确实必要”。

### 参数图已闭合的实际轨迹

| Trial | Active canonical 参数 resolved | Input-flow diagnostics | 仍阻止生成的义务 |
| --- | --- | --- | --- |
| out_parameter_r01 | 6/6 | 0 | acquire.out 的 argument_resource_lifecycle_unresolved |
| owned_return_r03 | 4/4 | 0 | input_binding 与 buffer_length 的 binding_length_contract_mismatch |
| shared_context_r04 | 5/5 | 0 | invocation initialization ordering、ownership 与两个 requirement unresolved，共四条 hard gap |

out_r01 已提交不同 ID 的 PointerParameter / OutParameterPointee，但仍给 storage 携带了对象 resource ID，Graph/Context 的 storage lifecycle 义务未闭合。typed subject 拆分防止 pointee 替代 storage ownership，并不自动完成其 resource binding。owned_r03 是四个 active 参数 resolved；owned_r02 则四个均 unknown，不能混用两次数据。bounded_r01 只有长度 cb 的 canonical construction gap：wrapper 退出 CORE 后，不再从 wrapper 的 semantic input root 获得 min(fuzz_size,4096)。没有放松 guard 或改用全部 fuzz size。

### Proposal 精度、格式与成本

48 条 accepted ownership：PointerParameter 37、PointerReturn 8、OutParameterPointee 1、ResourceObject 2。逐条通过 ProjectSnapshot 声明重放，没有 scalar/空/伪造主体；ResourceObject 的两条 native 记录是 shared-context bytes pointer field，resource_id=null。这是主体约束的证据，不是所有 ownership/lifetime 语义都正确的证明。104 条 accepted dependency 有 candidate ID；仍有一次 support_activation_candidate_not_signed 被拒绝。

按每个 group cost owner 的 attempt trace 去重，记录到 19 条 schema_validation_failed（12 次初次 terminal schema failure、7 次 repair failure）；其中 13 条为 malformed JSON，其余包括空对象、slot 形状、parent/API/evidence enum。另有 15 条 semantic_fact_requires_untruncated_subject_source、一次 fuzz_input_is_not_a_resource、一次 borrowed/static 带 release API 的拒绝。参数/资源枚举降低了非法值空间，但仍未解决 terminal JSON 稳定性及主体证据选择。

整链 **426 次真实模型尝试、420 个成功响应、5,885,838 tokens**：Candidate 329,700，Slice 819,803，Context 4,736,335，code 0。Context ledger 为 **205 model calls / 440 tools**，unchanged investigation skips 8。tools 按框架 budget ledger 统计，源码缓存复用与原始 tool events 分开保存。tokens 是收到响应的 usage 总和，失败请求没有返回的 usage 不可计。

与此前 12 次实验相比，平均每个整链 trial 约 196k tokens（此前约 223k），但本轮 16/30 在 Slice 提前退出，不能据此宣称效率提升。仅按进入 Context 的 trial 计算，本轮平均约 **338k tokens / 14.64 calls**；此前约 **199k / 15.18 calls**。两个版本没有配对消融，FT 与存活样本不同。source_chars cap 只计签发源码，schema、registry 和 graph metadata 的 prompt 开销另计；新 registry 的重复展开需要进一步压缩。

### Provider 与修复路径

四次 timeout、两次 transport_error，均发生在 Context；没有观测到 HTTP 400 或 429。八个成功响应的 request_diagnostics 确认实际执行了 tool history normalization，分布于 bounded_r03、owned_r02、callback_r03/r04/r05、shared_r04。它们证明真实请求执行了该路径，不能当作新的“原始 400 与修复后 200”配对对照；部分 terminal repair 最终仍失败。旧 paired control 保留。

### 逐次记录

“—”表示 Context 未运行；有效 CORE 外的 fallback anchor 不计入 FT 大小。所有行的 code/compile/runtime 状态均为 not_run。

| Trial | Slice | FT | CORE / SUPPORT 数 | Context hard gaps | Context model / tools | 整链 tokens |
| --- | --- | --- | --- | --- | --- | --- |
| bounded_scalar_r01 | completed | completed_with_unresolved | 1 / 0 | 1 | 2 / 5 | 54,181 |
| bounded_scalar_r02 | invalid | not_run | — | — | 0 / 0 | 38,607 |
| bounded_scalar_r03 | completed | completed_with_unresolved | 1 / 0 | 11 | 3 / 4 | 219,768 |
| bounded_scalar_r04 | invalid | not_run | — | — | 0 / 0 | 38,527 |
| bounded_scalar_r05 | invalid | not_run | — | — | 0 / 0 | 42,268 |
| callback_context_r01 | invalid | not_run | — | — | 0 / 0 | 39,776 |
| callback_context_r02 | completed | completed | 2 / 2 | 20 | 20 / 49 | 389,993 |
| callback_context_r03 | completed | completed_with_unresolved | 2 / 2 | 18 | 20 / 43 | 381,194 |
| callback_context_r04 | completed | completed_with_unresolved | 2 / 3 | 29 | 22 / 43 | 602,543 |
| callback_context_r05 | completed | completed | 2 / 2 | 33 | 22 / 43 | 755,292 |
| creator_with_args_r01 | invalid | not_run | — | — | 0 / 0 | 39,343 |
| creator_with_args_r02 | invalid | not_run | — | — | 0 / 0 | 44,844 |
| creator_with_args_r03 | completed | completed_with_unresolved | 1 / 2 | 11 | 19 / 43 | 349,239 |
| creator_with_args_r04 | completed | completed_with_unresolved | 1 / 2 | 13 | 16 / 37 | 312,101 |
| creator_with_args_r05 | completed | completed_with_unresolved | 1 / 3 | 3 | 20 / 34 | 420,006 |
| out_parameter_r01 | completed | completed_with_unresolved | 1 / 3 | 1 | 11 / 21 | 255,733 |
| out_parameter_r02 | invalid | not_run | — | — | 0 / 0 | 49,335 |
| out_parameter_r03 | completed | completed | 1 / 2 | 12 | 14 / 32 | 261,338 |
| out_parameter_r04 | invalid | not_run | — | — | 0 / 0 | 30,620 |
| out_parameter_r05 | invalid | not_run | — | — | 0 / 0 | 53,093 |
| owned_return_r01 | invalid | not_run | — | — | 0 / 0 | 49,707 |
| owned_return_r02 | completed | completed | 2 / 1 | 18 | 10 / 22 | 579,822 |
| owned_return_r03 | completed | completed_with_unresolved | 2 / 1 | 1 | 7 / 20 | 156,722 |
| owned_return_r04 | invalid | not_run | — | — | 0 / 0 | 29,789 |
| owned_return_r05 | invalid | not_run | — | — | 0 / 0 | 37,463 |
| shared_context_r01 | invalid | not_run | — | — | 0 / 0 | 52,719 |
| shared_context_r02 | invalid | not_run | — | — | 0 / 0 | 42,303 |
| shared_context_r03 | invalid | not_run | — | — | 0 / 0 | 37,903 |
| shared_context_r04 | completed | completed_with_unresolved | 2 / 2 | 4 | 19 / 44 | 472,325 |
| shared_context_r05 | invalid | not_run | — | — | 0 / 0 | 49,284 |

### 复现、完整性与剩余工作

Native 开始至结束的 production/runtime fingerprint 检查通过，原始 trial 不覆盖、不重试替换。批次完成后仅修正观测 collector 对 root Context trace 与 attempt copy 的重复错误计数；生产 fingerprint 不变，该工具修改独立归档在 collection_validation.json 与 collector_after_batch.py。修正后的 collector 与独立 audit 对 30 条 hard gaps、tokens 和 provider errors 全部一致。还用新 token reader 只读重算旧 12 次数据，恢复原已审计的 249 responses / 2,671,396 tokens，未修改历史 summary。

生产/source 归档核对、48 ownership declaration 重放及旧 native/240/paused summary SHA 核对见 verification.json；最终凭证扫描覆盖 3,312 文件，匹配数为 0（credential_scan.json）。原始 API 源码、每次消息/evidence/metadata、completeness、canonical graph 和 closure 均保留。

下一步应优先让 Slice 的合法 role/reason 成为可选择的框架候选，减少无效整体提交；将 support 的 signature profile 收束到实际参数/资源与 source effect，避免 wrapper 因匹配 fuzz buffer 而成为 configuration；统一 input/length 选择，并消除 stack/out cell 的 resource 标记与 lifecycle 义务不一致。随后压缩 registry/history 重复及 terminal 输出，继续保持预算。Construction/Callback 没有扩成新的大型合并合同；完整 blind cohort 仍暂停。

```bash
.venv/bin/python scripts/smoke_argument_graph.py \
  --output artifacts/core_proposal_native_repeat_20261001 --repetitions 5 --workers 2
.venv/bin/python scripts/collect_argument_graph_smoke.py \
  --smoke-dir artifacts/core_proposal_native_repeat_20261001 \
  --output artifacts/core_proposal_results_20261001
.venv/bin/python artifacts/core_proposal_analysis_20261001/audit_native.py
```

前两条创建目录要求输出目录不存在；重现 native 应使用 source_snapshot 中冻结源码与脚本，collection 工具的事后版本仅用于只读收集。audit 不调用模型。

| Evidence | SHA256 |
| --- | --- |
| artifacts/core_proposal_native_repeat_20261001/summary.json | `592fcef73387fe21da4f20e0e55d1fe90d9a3d589af710f0604beac49d3d5af4` |
| artifacts/core_proposal_analysis_20261001/audit.json | `1b83015b29cebee272cfe1632d50689722fe203d5bef6b8845488d3d031b572b` |
| artifacts/core_proposal_results_20261001/summary.json | `40f24951a65d508cf4c784068e9c40976d0d2eb127a3e2f38159f378d631512e` |
| artifacts/core_proposal_analysis_20261001/verification.json | `d438d43d8cade2ce45adec5ae4a07fe3fd3481e7b59bbf5579571858dcfab6d9` |

## 历史证据

此前 [Value / State Contract 报告](VALUE_STATE_CONTRACT_REPORT.md) 的 12 次 native 是不同 fingerprint：Slice 11/12、Context/compile/runtime 1/12，9/11 份 FT 包含 usage CORE；当前批次不与它合并。历史原始 artifact 与 source archive 保留，新的 collector 不改写历史统计。此前真实 provider 400 对照与 normalization 成功仍是独立证据；新批次若未触发该路径不能声称重新验证。
