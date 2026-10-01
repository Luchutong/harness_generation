# Value / Resource / Invocation Contract 重构与固定预算重复实验

2026-10-01，本轮依据本地 `v0.2` 实现继续重构。核心改动是把对象身份、调用点状态义务、外部输入传播和参数语义约束分别表示，再由 Gate 与 Plan 组合。没有增加 Agent 或源码工具，没有提高全局预算。此前报告及所有原始实验均保留；未启动新的 240 次 blind cohort。

最终离线回归 **384 passed**。六类各两次真实模型 trial：Slice **11/12**，Context/compile/runtime **1/12**；十次 Context incomplete，一次上游 Candidate Validation unresolved。已修复的架构边界有定点证据，整体调用语义仍不稳定，不能据此声称跨项目泛化或端到端稳定性提高。

## 1. 资源身份与调用点状态拆分

新增 `harness_context/invocations.py`，发布两个独立 sidecar：

| Contract | 内容 | 校验边界 |
| --- | --- | --- |
| `resource_contract` | 同一 origin 的类型、创建/清理/复用定义与各 API 绑定 | 真正冲突仍为 `conflicting_resource_identity` |
| `invocation_contract` | 按 function/parameter/resource 作用域记录 initialization 与 state preconditions；已有同 origin 字段 write/read transitions | 同一调用点初始化声明冲突阻止生成，调用前义务需有 hard ordering |

原始 lifecycle facts 保留，Reconciler 不通过改写原始 facts 消除差异。`acquire` 返回对象和 `supply` 参数的“无额外初始化”可以与 `parse` 参数的“调用前必须 supply”同时成立。`initialization` 不再进入全局资源定义的 shape 比较，仍参与调用点 Gate 与 Plan。

调用点义务区分 `before_call` 与返回对象的 `after_call`。消费者不能用自己的单次调用满足其调用前初始化要求，这会产生 `self_initialization_obligation_unresolved`；多次调用的 schedule 尚未支持。资源定义中的 cleanup/creation/reuse 冲突未被忽略。

HarnessPlan policy 升至 `frozen-context-harness-plan-v7`，schema 保持 2。Plan 的每个 invocation 保存自己的 preconditions，资源表保存全局定义，initializer 映射合并同一 resource/API 的重复义务；模型不重新猜状态来源。代码 prompt 为 `frozen-plan-code-v7`。

## 2. Input / Resource proposal 边界

新增 `value_roles.py` 与 `typed-value-origins-v1`。plain byte/scalar pointer 不再仅因“是 pointer”得到默认 resource ID。目录包含已证明的 creator/out origin、已签发完整 API 返回声明，以及 public StateObject/opaque handle 的框架存储或外部参数身份；原字段 `resource_id` 对 StateObject 仍为兼容表示，目录明确标注其类别。

Agent 收到 `value_roles`、允许的 origin 候选和已经固定的 identity。terminal schema 4 将 resource ID 限制在当前已知目录中。动态目录随着已有只读工具证据重新验证；模型不能通过字符串自行新增身份。

proposal validation 直接拒绝：

- `input` / `constant` / callback stub 携带 resource ID：`value_role_resource_id_forbidden`。
- lifecycle 的 `creation.kind=input`：`fuzz_input_is_not_a_resource`。
- StateObject/handle 被声明为 direct fuzz input：`state_object_cannot_be_direct_fuzz_input`。
- 未签发身份或明确 origin 与所提 creator API 不符。

被拒绝的 proposal 不进入 facts，不传播到 Reconciler。若独立机械证明已闭合参数，Gate 仍可通过该证明；这不代表错误 semantic proposal 被接受。新增负例直接检查 terminal parser 拒绝，并检查生成参数中没有 phantom resource。

已有 callback 正例测试夹具改为明确的 stack/zero-init proposal；旧 `input + resource` 标签不再用作正例。callback ABI、registration、userdata、lifetime 继续独立验证；没有把 callback 行为塞入 construction recipe。公开 callback 对象的字段初始化仍需已有完整 layout/no-escape 证明；额外未证明状态与 escape 负例继续 blocked。

## 3. Parameter semantic relation × mechanical recipe

新增 `parameter_semantics.py`，记录参数所度量的 buffer、bytes/elements 单位、关系、强制数值上界与证据。Reconciler 升至 `graph-contract-reconciliation-v2`。native 批次使用 `parameter-semantic-relations-v1`；实验结束后补上同名函数指针参数遮蔽检查，最终版本为 `parameter-semantic-relations-v2`。

当前范围证明限于一个 C 源码子集：函数起始处的 literal comparison，超界分支只调用识别到的 nonreturning operation（`abort` / `__builtin_trap`），并排除 snapshot 中同名函数和当前函数的同名参数。正常错误返回、未知调用、带 alternative 的 guard、assertion、先前可变语句和复杂 CFG 不被推断成 caller 的强制范围。该机制依据 C 操作语义，没有项目名、项目 API 名、输入参数名识别规则；它不是完整预处理、链接或调用目标解析，外部宏重定义等仍不在此证明范围内。

在 `parse.cb` 有 `cb > 4096` 的强制 nonreturning guard 时：

```text
candidate A: fuzz_size                   upper = unknown
candidate B: min(fuzz_size, 4096)        upper = 4096
parameter relation: cb must be <= 4096
→ A 不能证明满足约束；B 可成为 canonical recipe
```

不满足或无法保证强制范围的候选保留 diagnostic `construction_candidate_semantic_relation_mismatch`。明确 semantic proposal 与该范围冲突会 blocked；未知 API 语义或多个均满足范围的不同 recipe 仍保留歧义，模型 confidence 不能替代约束。

这是有限语义筛选能力，不代表已经支持任意 header-decoded length、跨函数符号范围、容量/实际长度关系或一般 dependent typing。

## 4. 独立 External Input Flow

新增 `input_flow.py` 与 `external-input-flow-v1`，发布 `external_input_flow.json`。它复用已有局部 AST/value-flow 结果，但存储独立的 FuzzInputRoot、transform、call argument 与 CORE parameter 路径，不包含 Resource、ownership 或 creator nodes。

输入根来自独立已验证 input binding，不能从参数名字或“pointer”猜测。bounded scalar sink 使用 canonical scalar recipe 对应的来源路径，不再把它同时当成直接完整 fuzz size root。CORE 的 fuzz path 由该图重算；没有 root 的情况仍为 `core_fuzz_input_path_unresolved`。

context/feed 与 owned-return 的间接输入在 Invocation 上连接：需要已有同 origin 的字段 write/read hard dependency，或返回对象字段对已验证 fuzz parameter 的局部依赖以及 consumer 对该字段的读取。后者支持 read-modify-write，拒绝被重写的返回对象和 loop/goto/preprocessor 的未证明传播。该分析不是完整 SSA/escape/interprocedural 程序证明。

各 sidecar 与 Context 内数据比较、计算 publication digest，并在加载 Gate 时重算。篡改输入可达集、状态义务或资源定义不能绕过 frozen-input 验证。

## 5. 调查效率与预算

Agent prompt 为 `ft-scoped-value-state-agent-v8`；requirements version 为 `harness-requirements-v4`。改动包括：优先调查 CORE 输入绑定、复用已签发源码和 canonical identity、把自动源码调查限制到当前 subject 的 origin/缺失 dependency，避免按相同类型扩张调查。

follow-up 显式携带一个 `obligation_focus`，要求先解决该缺口、必要时做一次窄查询，然后提交事实或明确 unresolved；follow-up 每次最多两个 model rounds，仍在原四轮上限内。框架按 evidence/fact digest 跳过未取得新信息的重复调查，记录 `unchanged_investigation_skips`，不把 skip 算为 resolved。Agent 仍能使用原有工具集合；“一次窄查询”目前是 prompt 约束，不宣称每次模型执行都严格遵守。

六类真实模型试验均使用同一预算：Context 24 model / 64 tools / 96,000 source chars / 16 discoveries / depth 2 / 3 completeness rounds / 1 terminal repair；Candidate/Slice 默认 6 rounds / 24 tools / 48,000 source chars。无 case-specific 增额。Context/code output 8192；上游 4096；thinking disabled。

## 6. 离线验证与源码冻结

native 冻结前 `.venv/bin/python -m pytest -q`：**382 passed，64.20 秒**。新增九项覆盖调用点 initialization、shared-context 实际编译运行、冲突定义/self-init 阻塞、proposal 拒绝、强制上界筛选与保守负例、独立输入流/篡改。`git diff --check` 与 `pip check` 通过。

离线 semantic facts 为显式测试夹具，代码为 FakeLLM golden translation；源码解析、证据、Gate、Plan、本地 Clang 与固定输入 runtime 均为实际实现。这些验证不计入 native 成功率。

native 生产 fingerprint：`d2a9a5eee5407308b3778affd8fe1858a6ddc421b0a44eb38bc1aac1844eb335`。148 个 production/runtime Python 源码归档于本轮 native 目录的 `implementation.tar.gz` 与 `source_digests.json`；整个批次中未修改，结束时 `completed=true`、`implementation_unchanged=true`。测试日志与测试源码 digest 保存为 `offline_pytest.log` / `offline_validation.json`。

冻结实验结束后，边界审查修复了 `void (*abort)(void)` / `void (*__builtin_trap)(void)` 被误认为 nonreturning intrinsic 的情况，并新增两个负例。最终全量回归为 **384 passed，80.13 秒**。唯一追加的生产文件为 `parameter_semantics.py`，同时升级该 contract 的版本以拒绝旧配置恢复。

最终生产 fingerprint：`842404b98dbb8f249dd2320d03e3defe153eb7643e68bfa71e3dd6b17803c037`。源码、日志及校验存于 `artifacts/value_state_post_repeat_validation_20261001/`。从 native 归档加载旧实现，逐函数比较十二个 trial 的源码，强制上界投影均与修复后相同；这只是离线比较，**最终 fingerprint 未重新运行 native 模型批次**，下表仍属于前一个冻结 fingerprint。

## 7. 六类固定预算 fresh 重复实验

目录：`artifacts/value_state_native_repeat_20261001/`。六类每类两个 fresh trial，共 12 次，两个 worker；同一 source/policy/budget/provider，原始失败不替换，不混入旧版本 Context。没有 fake/recorded semantic facts 或手工补充契约。

全链为 Candidate → Slice → Minimal FT → Context → Plan → code → compile/runtime。仍为 parser-only synthetic Development / Regression fixtures，不报告真实项目 Candidate recall，也不把 `completed_with_unresolved` 当成无缺口的正确 FT。两个重复不足以证明跨项目稳定性。

下列结果来自全部十二次已结束 trial，包含逐次模型/工具/tokens、hard gaps、semantic/protocol/provider 错误及编译运行结果。

### 7.1 总体与分类结果

实际路由配置为 `openai-compatible / ark-code-latest`；成功响应中的 served model 均为 `deepseek-v4-flash-ga-260731`。24/64 等是每个 Context 的统一预算上限，未开始的阶段不算成功或零缺口证明。十二次失败均未替换或重跑。

| API 模型 | Slice completed | FT completed / with unresolved | CORE 大小（r01 / r02） | Context complete | compile / runtime |
| --- | --- | --- | --- | --- | --- |
| bounded_scalar | 2/2 | 1 / 1 | 2 / 2 | 1/2 | 1/2 / 1/2 |
| creator_with_args | 2/2 | 0 / 2 | 2 / 2 | 0/2 | 0/2 / 0/2 |
| out_parameter | 2/2 | 0 / 2 | 1 / 2 | 0/2 | 0/2 / 0/2 |
| shared_context | 1/2 | 1 / 0 | 3 / — | 0/2 | 0/2 / 0/2 |
| owned_return | 2/2 | 2 / 0 | 2 / 3 | 0/2 | 0/2 / 0/2 |
| callback_context | 2/2 | 1 / 1 | 3 / 3 | 0/2 | 0/2 / 0/2 |

Slice 产出 11/12；Minimal FT 为 `completed` 五次、`completed_with_unresolved` 六次。`shared_context_r02` 的 Candidate Validation 用完六轮，verdict 为 unresolved，Slice 未开始；runner 的 `semantic-slice_failed` 是下游 CLI 拒绝未 accepted anchor，并不是已经执行的 Slice 推理失败。

Context complete 1/12（在十一份已执行 Context 中为 1/11），incomplete 十次，invalid 零次。只有一个 trial 进入 Plan/代码生成，编译及六个固定输入 runtime 均通过；其余十一次 **compile/runtime 未执行**，没有十一份编译失败。成功生成的 resume 没有新增模型响应，输出及上游输入均未变化。十一份 Context 全部保存 Argument Graph，保存的实际 prompt 中均可见该图。

### 7.2 逐次结果与成本

下表 FT size 为 CORE + SUPPORT candidates，不是最终 API Closure 大小。canonical 分母为该次 CORE + required support 的参数，随模型产生的 Closure 改变，不能当成统一难度的参数准确率。`—` 为阶段未执行。C/U 分别表示 FT completed / completed_with_unresolved。

| Trial | FT | CORE / FT size | canonical active resolved | Context / hard gaps | Context model / tools | 整链 tokens | compile/runtime |
| --- | --- | --- | --- | --- | --- | --- | --- |
| bounded_scalar_r01 | C | 2 / 2 | 4/4 | complete / 0 | 12 / 19 | 185,831 | passed |
| bounded_scalar_r02 | U | 2 / 2 | 3/4 | incomplete / 5 | 7 / 12 | 131,984 | 未执行 |
| creator_with_args_r01 | U | 2 / 4 | 5/5 | incomplete / 16 | 14 / 34 | 206,441 | 未执行 |
| creator_with_args_r02 | U | 2 / 4 | 5/6 | incomplete / 20 | 16 / 37 | 246,919 | 未执行 |
| out_parameter_r01 | U | 1 / 3 | 2/6 | incomplete / 19 | 11 / 27 | 207,892 | 未执行 |
| out_parameter_r02 | U | 2 / 4 | 5/5 | incomplete / 16 | 15 / 35 | 232,079 | 未执行 |
| shared_context_r01 | C | 3 / 5 | 7/7 | incomplete / 10 | 21 / 45 | 354,629 | 未执行 |
| shared_context_r02 | — | — | — | 未执行 / — | 0 / 0 | 19,569 | 未执行 |
| owned_return_r01 | C | 2 / 3 | 0/4 | incomplete / 31 | 10 / 28 | 119,163 | 未执行 |
| owned_return_r02 | C | 3 / 4 | 6/6 | incomplete / 8 | 14 / 30 | 231,620 | 未执行 |
| callback_context_r01 | U | 3 / 5 | 8/11 | incomplete / 29 | 24 / 51 | 388,090 | 未执行 |
| callback_context_r02 | C | 3 / 5 | 7/9 | incomplete / 24 | 23 / 53 | 347,179 | 未执行 |

整链取得 **249 个成功 response ID，2,671,396 tokens**；其中 Context 为 **167 model calls、371 tools、2,186,245 tokens**。模型调用计数包含已消耗预算的失败调用；没有 token usage 的 timeout 不估算 tokens，也不估算账单金额。框架记录了十五次 unchanged-investigation skip，跳过不等于 resolved。

原 native runner / 通用 collector 的 trace 统计为 248 responses / 2,662,807 tokens，不包含独立代码生成 `response.json`。观察审计按唯一 response ID 补入这次代码生成的 8,589 tokens，因此报告的整链成本比原字段高 8,589；原始 summary 未修改。审计同时将本地 `budget_exhausted` 从 provider 失败中分离，并把未执行 Context 的 hard gaps 表示为 null。

历史六次 canonical native 的 trace 成本为 1,784,867 tokens、105 Context calls、218 tools。本轮十二次的同口径 trace 平均约 221,901 tokens/attempt，历史约 297,478；但本轮包含一次上游提前结束、不同 FT/Closure 和九次 timeout，并非配对消融，不能把差值归因为调查策略的因果改善。callback 两次仍消耗 47 Context calls / 104 tools / 735,269 tokens，未形成 complete Context。

### 7.3 架构定点证据与剩余瓶颈

- **Resource / State**：离线 shared-context 正例实际覆盖 `parse` mandatory init 与 creator/feed 无额外 init 的不同声明，并通过 Gate→Plan→Clang/runtime；不同 cleanup 定义的负例仍 invalid。native `shared_context_r01` 为一个全局 resource、七个 canonical 参数 resolved、无 identity diagnostic；该次 lifecycle initialization 都为 false，`input_fed` 存于独立 state precondition。它没有再次覆盖历史的 initialization shape 差异，不能用 native 结果代替离线定点证明。其十个 hard gaps 仍来自 input/argument 语义、ownership、buffer/state requirements。
- **Input / Resource**：十一份 Context 的 accepted arguments 中 `input/constant/callback + resource_id` 为零。真实提案出现两条去重 `resource_origin_api_conflict` 记录，在 proposal validation 被拒绝；本批未触发 `value_role_resource_id_forbidden`，该路径证据来自离线负例。不能把“未触发”写成模型永远不会产生坏标签。
- **Semantic × Recipe**：两次 bounded-scalar 的 `parse.cb` 均确定性选择 `[0,4096]` scalar recipe，完整 fuzz size 候选因强制上界不匹配被排除。第二次仍因 `usage.extent` 的独立 argument contract conflict 与 ownership 未闭合而 blocked。第一个成功模型生成的二进制还单独运行 4096、4097、65536 字节输入，三次均 return 0；这些补充运行不算 fresh model trials，原六个 runtime artifact 未改写。
- **External Input Flow**：两次 out-parameter 的 direct input roots 与 CORE 输入可达检查均无 input-flow diagnostic，失败转为资源构造/支持 API 激活、生命周期与 ownership。`owned_return_r02` 已闭合六个 canonical 参数及输入路径，仍被 returned-resource ownership mismatch 等八个缺口阻止。`owned_return_r01` 无 accepted input roots，留下两个 `core_fuzz_input_path_unresolved`，图没有凭 Resource origin 补造输入根。
- **Agent 与支持闭包**：本批共有 65 条去重 validation records（按逻辑 requirement/code/detail，不是 65 次请求）。主要是 unsupported dependency role 15、scope 外 facts 11、无 pointer subject 的 ownership 9、unknown parameter 7、无关/未签发 evidence 7；另有 scalar-return ownership 两条。窄调查与 evidence skip 已生效，但 scoped proposal 的准确性、支持 API 的 source/role 证据和 pointer/return ownership 主体仍是瓶颈。
- **FT 边界**：十一份 FT 中九份仍把 `usage` 放进 CORE，out/owned 两次重复的 CORE 大小也不同。本轮未调整 Candidate/Slice 策略，也没有 ground-truth FT 正确性评估；`completed` 只表示该阶段按当前规则产出，不能声明最小核心路径已经稳定。

### 7.4 请求故障与可复现产物

去重后观察到 **九次 provider timeout**：creator-with-args 两次、out-parameter 两次、shared-context 一次、owned-return 三次、callback 一次。另有一次本地 terminal repair `budget_exhausted`，没有发送成功的供应商请求；不归为 provider fault。terminal schema execution error 三条，独立于 provider 故障及 semantic validation records。

本批未观察到 HTTP 400、429 或 malformed historical tool arguments，成功请求中的 normalization 次数为零。此前 canonical 版本的 malformed-history 400→normalization 200 对照及 native repair 证据保留；本批不能追加一份没有发生的供应商修复验证。

```bash
.venv/bin/python scripts/smoke_argument_graph.py \
  --output artifacts/value_state_native_repeat_20261001 \
  --repetitions 2 --workers 2
.venv/bin/python scripts/collect_argument_graph_smoke.py \
  --smoke-dir artifacts/value_state_native_repeat_20261001 \
  --output artifacts/value_state_results_20261001
.venv/bin/python artifacts/value_state_results_20261001/audit_native_results.py
```

以上 runner 命令为本轮实际调用，输出目录需不存在；重现该模型批次需用 native 目录归档的源版本和原配置，而非事后修复的最终代码。第三条仅重读已有 artifact，不调用模型。固定预算重复是在同一冻结批次内匹配，未做新旧版本配对，也没有启动完整 blind cohort。

| Artifact | SHA-256 |
| --- | --- |
| native `summary.json` | `ae4da5efb0266984a202eaaa1a40ee353729d7e0a858868d453b722ed953ad6e` |
| collector `summary.json` | `5a010b60a38a3ed1c168102c9322175bdce8e98749bb22bb9bc79958a192154a` |
| `value_state_results_20261001/value_state_audit.json` | `4cfa4666172b1f7532d1bd3fc5047ee121882ddaa7ea914604159d60a539f588` |
| `value_state_runtime_boundary_20261001/summary.json` | `24cbdef6381290d575386ac88f9d3a3dbc8256e448ab006bf87941053c6c03f3` |
| post-repeat `validation.json` | `f17ca1475ec9ec5d22e5e885866f6d8a1564356914d983dc3f6aa87ae9a37878` |
| post-repeat `semantic_projection_comparison.json` | `28da30d3cf32a4f335f4b1517a9604190795b46dc1b8830f141f9d45882cbb9e` |

## 8. 剩余边界

任意数值语义关系、复杂 callback/ownership、erased object ABI、跨 TU state、复杂 alias/escape、重复 CORE invocation 和完整 error-path/lifetime schedule 仍有限制。construction、input flow、callback 与 state/order 互相提供证据，但不能互相代替 mandatory contracts。

下一轮应由真实失败决定优先级，不提高预算来掩盖未闭合义务，不覆盖此前六个 native trial、原始 240 次或暂停的 52 次 blind 结果。

目前更具体的下一步是：将 support API 激活与 semantic proposal 主体收敛到已签发的 API/source/parameter 候选；把 ownership 的 parameter、pointer return、void/scalar return 从 schema 层区分；继续按单个 hard obligation 调查，保留 unresolved 和 provider 故障。callback 仍按 construction、ABI/userdata/lifetime、state/order 分开推进。FT/wrapper 膨胀需单独评价，不能由 Context 补偿成“正确 FT”。
