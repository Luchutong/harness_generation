# Harness Context 语义边界修复报告

本报告基于本地 `v0.2` 分支实际实现，验证日期为 2026-09-28。保留进入本轮时已有的新生成链改动；本轮集中修复 Context 上游语义，不增加流水线阶段或 Agent。

五类基本 API 的离线 `Slice → Minimal FT → Context → API Closure → Gate → Plan` 测试通过。真实模型首轮完整链通过 direct buffer 和 NUL string；owned-return 在复用真实上游结果的后续调查、确定性投影修复后通过生成、编译和运行。shared-context 和外部 callback context 仍被 Gate 阻止。不能把这些结果解释为五类真实模型完整链全部稳定通过，或跨项目泛化已经成立。

## 修改范围

| 模块 | 本轮职责 |
| --- | --- |
| `harness_context/value_flow.py` | 对已经签发的完整调用者源码做有界、直线值流分析，识别 return、out parameter、局部 alias、成员赋值和参数使用 |
| `harness_context/resource_identity.py` | 生成 framework resource ID，投影已证明的等价关系、唯一 creator/cleanup binding；原始模型事实保持不变 |
| `harness_context/callbacks.py` | 解析精确 callback 声明身份、typedef ABI、owner/field、userdata 来源和 lifetime；核对可证明的字段初始化 |
| `harness_context/input_contracts.py` | 区分输入模型，验证 NUL 消费证据，投影没有显式 length 的字符串契约 |
| `harness_context/ordering.py` | 构建带来源的 hard/soft ordering graph，输出循环边及证据 |
| `harness_context/terminal.py`、`agent.py` | 发送当前组的固定 slot schema，由框架补全 requirement/function/predicate 身份，再运行原有严格验证 |
| Context `tools.py`、`requirements.py`、`loop.py`、`persistence.py`、`completeness.py`、`evidence.py` | 提供受限值流查询、复用证据、投影及重新校验派生契约；对未绑定的外部资源保持阻塞；恢复时保留有效的非 mandatory unknown |
| `semantic_slicing/agent.py`、`frontier.py` | 修复 CORE/SUPPORT reason schema 不匹配；把 producer-return 的潜在 consumer/cleanup 保留在调查 frontier |
| `sfg_builder/parser.py`、`sfg_adapter.py`、Minimal FT fingerprint | 保存精确 callback typedef；有 typedef 时纳入身份与 live-source 校验，无 typedef 的旧输入保持兼容 |
| `context_generation/builder.py`、`stage4.py` | Plan 消费规范资源身份和 hard DAG，表达 out storage、callback 生命周期和有界 NUL heap copy；模型继续只翻译 Plan |
| 共享 `semantic_discovery/loop.py` | 增加默认关闭的 terminal 末轮预留选项，仅 Context 启用，防止全部轮次用于查源码而没有提交；调用预算不增加 |
| `tests/test_context_semantics.py` 及现有回归、`scripts/smoke_context_*.py` | 离线正反例、显式真实模型测试、schema token 计量、原始事实零模型复核 |

新生成入口继续读取 `minimal_ft.json + harness_context.json + api_closure.json`。必须同时满足当前重新验证的 `generation_allowed=true` 和 `frozen=true`。旧 Stage 1–4、legacy `generate` 和 ProtocolIR baseline 保留；没有修改 coverage score，也没有加入 coverage regeneration。

## 资源身份：合并的证据和边界

值流分析只使用已经通过工具签发的、未截断的完整函数体。`find_resource_flows` 将有界 caller 查询结果写入既有证据记录，不允许 resolver 为了补齐契约任意扫描未查询的仓库文件。每个值源的 ID 由 producer function ID、return/out 种类、参数、类型、指针层级、调用者 ID 和调用位置计算。同一 creator 的两个不同调用得到不同源身份。

对于 `a=create(); b=a; feed(b,...); parse(a); destroy(b);`，源码赋值与参数位置把这些端点连接到同一源。成员存取使用完整局部成员路径；out parameter 要求已签发的 creator body 对该参数进行明确调用结果写入。consumer 的基础类型和指针层级必须匹配。资源身份只表示值源关系，并不自行证明分配器、ownership 或成功条件。

| 关系 | 当前处理 |
| --- | --- |
| 同一返回值经局部赋值/alias/成员保存进入多个 API | 源码值流唯一时 merge |
| 显式 out 写入后进入使用/cleanup API | 精确参数及写入证据成立时 merge |
| 一个明确 `creator_api` 参数构造与对应 creator 返回值 | 仅唯一 harness binding 且声明类型/指针层级和 creator body 已取得时连接；不会把多个同类型参数自动合并 |
| 唯一 owned-return 与指定 cleanup 参数的 ID 不一致 | 必须同时具有显式 owned + release API 契约、真实分配返回、该 cleanup 的真实释放证据和类型匹配，才投影为同一资源并把 cleanup 构造改为 derived |
| 普通 fuzz-data、length、标量 | 不凭指针类型附加 lifecycle resource；仍可直接绑定 fuzz bytes/size |
| 两个 creator 调用、重赋值、多 runtime origin | 保留不同源；同一 API 端点存在多个源时保留 unresolved 并阻止不明确的 Plan |
| 同类型、同 struct、相似名称、相同模型 resource 字符串 | 不能单独建立跨端点等价 |
| 分支/循环、复杂 cast、间接调用、复杂 escape | 当前直线分析无法证明的部分保持 unknown，不扩展为完整别名分析 |

模型 facts、fact ID 和证据引用原样保存。规范 ID 位于 projected contracts，`resource_identity.bindings/value_flow/unresolved/reuse_projections` 保留推导依据。Context validator 按当前 snapshot 与 evidence 重新计算投影，不能靠修改派生 JSON 绕过 Gate。

shared-context 实测还暴露 `per_input` 与 `per_context` 被误认为不兼容的问题。仅当同一值流已经证明本次调用里 fresh allocation、使用和 release，且两份已知契约恰为这两个 scope 时，投影采用共同可满足的 `per_input` 并记录证据。`unknown`、`static` 等不会被改写。该修复消除原始 identity conflict，但不会补全缺失的 lifecycle/ownership。

## Callback：精确 ABI、owner、userdata 和存活区间

callback identity 来自函数参数声明、struct 的函数指针字段或精确 typedef 声明。保存 declared type、signature、return type、parameter types、owner type、parameter、field，以及一层嵌套 callback table 的 owner/field path。参数名不能充当 ABI 证据；多个相同 ABI 字段仍需消歧。冲突 typedef、无法解析的 ABI 宏和 variadic 不做猜测。

userdata 关联由实际 callback 调用中对应 `void *` ABI 位置的实参证明，或者由 setter 将声明的 void-pointer 参数写入同一精确 owner 的唯一成员证明。写入别的 context、同时写入多个可能成员不能形成唯一 userdata binding。保存原始 userdata identity、存储 target、source verification，以及 `call_return` / `context_cleanup` 存活终点。registration 明确表达 setup API 或 harness field initialization；模型声明的 lifetime 为 unknown 时仍阻塞。

对于显式 `stack/zero_init` 的公开结构，只在所有已读取字段均被精确 callback 和已验证 userdata 初始化覆盖时，才能确定性满足相应初始化前提。存在额外未构造字段或外部 `input` context 时不能使用这个证明。真实 callback 重试已经获得 ABI/userdata/lifetime，但模型仍把 `ctx` 描述为外部 input，未给出 harness 可执行的资源构造。因此继续阻止生成，没有自动将其改成 stack。

## NUL/string 输入与 Plan

投影明确区分 `binary_buffer`、`explicit_length_buffer`、`nul_terminated_string`、`fixed_scalar`、`structured_input` 和 `context_indirect_input`。NUL 证据限于精确参数上的 libc `strlen/strcmp/strchr` 或 NUL-based loop；项目自己定义同名函数时不能作为 libc 证据。`char *` 本身不证明字符串语义。

当已有 fuzz-data 的 `nul_terminate` transform、声明类型和实际 NUL 消费证据一致时，允许 `size_parameter=null`，投影 `size_relation=nul_exclusive`。缺少旧 buffer-length row 时可按证据生成 no-length link。binary-zero 的模型事实仍独立保留；没有证据的内容规则不自动解释。

Plan 的 `input_transforms` 明确要求：先执行输入上限检查，再进行 `size + 1` 的有界 heap allocation；复制有效 bytes，在 size 位置追加 NUL，使用完成后释放。记录 `max_allocation_bytes=max_bytes+1`，不要求生成模型自行推断字符串或选用 input-sized stack allocation。冲突长度、无 NUL 证据和未知 mandatory 长度关系仍阻塞。

## Owned-return Slice 和 ordering

之前保存的真实 owned-return Slice trace 在 CORE parser 上同时提交 `accepted_anchor/input_consumption/resource_creation`，其中 `resource_creation` 是 SUPPORT reason，触发 `reason is incompatible with role`。本轮 terminal classification schema 按 role 限定 reason 子集，并明确 producer parser 可为 CORE、cleanup 为 SUPPORT candidate。validator 没有放宽，框架也没有把模型非法角色事后重分类。

frontier 保留同返回类型 consumer 的弱线索并标明 ownership 未证明；只有调查源码、usage、cleanup 后才成为有证据的 SUPPORT。六种回归覆盖 owned、borrowed、nullable、cleanup wrapper、两个可能 cleanup API、返回对象保存到 field。Slice 保持 frontier，不承担最终 owned proof。新真实 Slice 已得到 CORE `parse` 与 SUPPORT `node_release`。

ordering graph 的 hard edge 来自已绑定资源的 creator→use、init→use、use→cleanup，或同一资源上实际字段写入/读取的 feed→process、registration→callback use。每条边保存 before、after、strength、reason、resource ID、evidence IDs 和原始 fact ID。模型 `must_precede/must_follow` 建议保留为 soft；没有可证明依赖的 state ordering 也不能被提升为 hard。

Plan 只对 hard edges 排序。soft cycle 留作诊断，不阻止生成；hard cycle 输出带完整来源的循环边，Gate/Builder 都阻止，不删除任意 hard edge。producer 的 returned resource 初始化不能错误生成 init→producer 反向边。

这些 hard 推导依赖已通过现有 evidence validator 的 typed semantic facts 和已取得的源码，不等价于对任意 C 项目的 ownership 或控制流做形式证明；复杂间接状态仍是当前限制。

## Terminal schema 与重复调查

新 wire format 使用当前组固定的 `r0/r1/...` resolution slots；每个 slot 仅携带其 predicate 的 value schema。requirement ID、function ID、predicate 由调用上下文补全；dependency `required_by` 在唯一时也由框架补全，多 parent 时只给当前合法 enum。predicate 的 dependency reason 使用合法子集。模型仅提交未知 value、证据引用、状态、问题和依赖建议，展开后继续通过 shape、证据、语义和 Gate 校验。

canonical requirement 状态仍然独立；共享源码查询、creator/cleanup discovery、identity 推导不代表把一个 predicate 的答案复制给其他 predicate。Context 预留最后一个既有预算轮次用于 terminal，让仍未知的义务明确提交 unresolved。有效 resume 中非 mandatory 的 unknown 可以原样复用；current Gate 新出现的 hard gap 仍会触发定向调查。

通过同 provider、相同计量 prompt 的六次真实请求，单独测量 old `anyOf` 与新 slots 的 prompt tokens。每次 completion 为 1 token，不进行语义回答质量测试。

| Group | 旧 schema chars | 新 schema chars | 旧 prompt tokens | 新 prompt tokens | tokens 降幅 |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 12,406 | 8,511 | 4,304 | 3,021 | 29.8% |
| shared | 17,360 | 12,559 | 5,936 | 4,356 | 26.6% |
| callback | 19,983 | 14,703 | 6,802 | 5,064 | 25.6% |

合计 prompt tokens 从 17,042 降到 12,441，下降 27.0%。这是 provider usage 计量，不是字符换算。它只证明 schema 开销下降；完整调查还受轮次、源码、历史对话和 completion 影响，不能据此宣称整链 tokens 同比例下降。原始数据在 `artifacts/context_schema_tokens_20260928.json`。

## 离线验收

最终 `.venv/bin/python -m pytest -q`：**269 passed**。新增语义边界测试文件包含 39 个测试；pytest 不调用真实 provider。

| API 模型 | 离线验证 |
| --- | --- |
| direct `parse(data,size)` | Slice、Minimal FT、Context、closure、Gate、Plan；普通 buffer 无 phantom resource |
| NUL `parse_string(text)` | 完整投影链；无 length 契约与 bounded heap transform |
| shared `create/feed/parse/destroy` | 独立模型 IDs 经 caller/alias 证据合并；字段数据依赖顺序；soft cycle 不阻塞 |
| owned `parse/consume/release` | producer/consumer/cleanup 值流一致；ownership、nullable return 与 cleanup Plan |
| callback `create/register_table/parse/destroy` | typedef/table/owner/userdata/registration/lifetime 与 hard ordering |

反例包含同类型双资源、重赋值、分支、不同指针层级、无 NUL 消费证据、显式长度 char buffer、多个 callback 字段、冲突 typedef、未知 ABI 宏、错误 userdata owner、多个 userdata store、额外未初始化字段和 hard cycle。现有生成测试还覆盖 C/C++、构建/runtime、冻结输入篡改和恢复校验。

## 真实模型 smoke：分类与原始结果

配置读取当前 `.env`，凭证未写入报告或 artifact。provider 为 `openai-compatible`，endpoint 为 `https://ark.cn-beijing.volces.com/api/plan/v3`，requested model 为 `ark-code-latest`，实际 response model 为 `deepseek-v4-flash-ga-260731`，thinking 为 `disabled`。全部真实调用显式运行在 smoke scripts 中，没有 Fake model fallback。

样例源码是小型合成项目，静态分析为 parser-only，入口选择显式指定 parse anchor；Candidate Validation、Slice、Context、code translation 使用真实模型。这是 API 模型 smoke，不评价项目入口 recall。FT 和 Gate/Plan 为框架确定性阶段。

首轮保存于 `artifacts/context_semantics_real_20260928_01/summary.json`。进程启动后继续修复了 terminal 末轮预留、owned cleanup binding 和部分 Gate/Plan 投影，因此下表是原始首轮结果，后续当前规则结果另列，原始失败没有覆盖。

| Case | 分类 | Slice / FT | CORE / SUPPORT 候选数 | Context / hard gaps | required closure（不含 CORE） | Plan / compile / runtime |
| --- | --- | --- | ---: | --- | --- | --- |
| direct | full model pipeline | completed / completed | 1 / 0 | complete / 0 | 无 | built / passed / 6 passed |
| NUL string | full model pipeline | completed / completed_with_unresolved | 1 / 0 | complete / 0 | 无 | built / passed / 6 passed |
| owned return | full model pipeline | completed / completed_with_unresolved | 1 / 1 | incomplete / 3 | node_release | blocked / 未运行 / 未运行 |
| callback | full model pipeline | completed / completed | 1 / 0 | incomplete / 14 | 无 | blocked / 未运行 / 未运行 |
| shared context | full model pipeline | completed / completed | 3 / 2 | invalid / 13 | create、destroy | blocked / 未运行 / 未运行 |

shared 的 CORE 实际为 feed、parse、example wrapper，不能把它改报为理想化的两 CORE FT。soft unknown 可以存在于已 complete Context；FT `completed_with_unresolved` 也不等于当前 mandatory Context 有缺口。

| Case | Context calls | tools | source chars | Context total tokens | Candidate / Slice / Context / code calls | Agent responses / attempts | 整次 tokens（含 code） |
| --- | ---: | ---: | ---: | ---: | --- | --- | ---: |
| direct | 3 | 5 | 1,712 | 28,228 | 3 / 4 / 3 / 1 | 10 / 10 | 63,017 |
| NUL string | 2 | 3 | 1,143 | 20,423 | 3 / 6 / 2 / 1 | 11 / 11 | 68,705 |
| owned return | 14 | 25 | 2,864 | 131,183 | 2 / 4 / 14 / 0 | 20 / 20 | 161,247 |
| callback | 12 | 35 | 9,045 | 149,153 | 3 / 4 / 12 / 0 | 18 / 19 | 182,185 |
| shared context | 24 | 47 | 8,645 | 272,584 | 3 / 5 / 24 / 0 | 31 / 32 | 320,124 |

callback/shared 各有一次没有 response usage 的 provider error，attempt 仍计入调用次数。tokens 仅累加实际返回的 usage，不能推测失败请求是否产生额外计费。source chars 为 Context 证据计量，不是全链源码量。Closure metrics 包含 CORE，上表 required closure 列排除 CORE。

### 后续定向调查与当前规则复核

后续复制原始真实 Candidate/Slice/FT，再调查 Context；源码和真实上游决策不改写。分类为 `context-only`，且标注 `full_model_pipeline_upstream_reused`，不算新的 fresh full-pipeline trial。

| Case / 动作 | Context calls / tools | source chars | tokens | 结果 |
| --- | --- | ---: | ---: | --- |
| owned Context 重试 | 9 / 11 | 3,305 | 86,971 | 10 项 resolved，剩 cleanup 参数错误 resource ID 的 1 个 hard gap |
| callback Context 重试 | 9 / 17 | 3,558 | 94,533 | ABI/userdata/lifetime 已完整，剩 1 个 state gap |
| callback resume，定向追问构造 | 7 / 17 | 4,462 | 77,204 | 复用 8 项 requirement，仍为 incomplete；当前严格 Gate 明确报告 3 个相关构造/state gaps |
| owned resume，应用 framework cleanup binding | 3 / 5 | 1,999 | 19,257 | complete；再调用一次真实 code model（5,473 tokens），compile 和 6 次 runtime passed |
| 原始 owned 重试 facts 按当前规则重新投影 | 0 / 0 | 0 | 0 | 同样 complete，raw facts 不变；证明 cleanup 修复本身不需要再次模型调查 |

owned resume 的三个调用仅重新调查非 mandatory support unknown，因此本轮又修复了有效 soft unknown 的 resume 复用。它们是实际发生的成本，没有从结果里删掉。由首轮、重试、resume 走到 owned 成功所花成本不可合并成单次最优成功路径。

当前零模型复核中，shared 原始 `conflicting_resource_identity` 已被有证据的 scope 投影消除，状态从 invalid 变为 incomplete，但仍有 13 个 hard gaps：parse lifecycle/ownership、mandatory API 顺序、state 依赖、creator return 等没有完成。callback 保留 `argument_input_binding_unresolved`、`input_resource_without_binding` 和 `state_precondition_unresolved`。两者 `generation_allowed=false`，没有进入 code model/compile。

主要证据路径：

- `artifacts/context_semantics_retry_20260928_owned/retry_summary.json`
- `artifacts/context_semantics_retry_20260928_callback/retry_summary.json`
- `artifacts/context_semantics_callback_resume_20260928/harness_contexts/`
- `artifacts/context_semantics_owned_replay_20260928/`
- `artifacts/context_semantics_negative_audit_20260928_v2/summary.json`

### Plan 翻译与最终编译/runtime 复核

`registered_callback` 与 `owned_consumer` 使用显式 offline fixture 构造 Frozen Context，再调用真实模型翻译 Plan；必须归类为 **plan-translation-only**。前者一次 code call、9,522 tokens；后者一次、6,523 tokens。二者都通过 compile 和各 6 次 runtime；generation resume 未再次调用模型，artifact 不变。数据在 `artifacts/context_semantics_translation_20260928/summary.json`。

最终使用当前代码，从保存的原始 facts/resolutions/evidence 重建 Context/closure/Gate/Plan，复用此前真实模型生成的源码，重新做 static validation、compile 和 ASan/UBSan replay：

| Case | 上游来源 | 当前 Context | compile / runtime | 新 Context / code calls |
| --- | --- | --- | --- | --- |
| direct | 完整真实模型链 | complete | passed / 6 passed | 0 / 0 |
| NUL | 完整真实模型链 | complete | passed / 6 passed | 0 / 0 |
| owned return | 真实模型上游 + 后续 Context 调查 | complete | passed / 6 passed | 0 / 0 |
| registered callback | 显式 Frozen fixture，仅 code 是真实模型 | complete | passed / 6 passed | 0 / 0 |
| owned consumer | 显式 Frozen fixture，仅 code 是真实模型 | complete | passed / 6 passed | 0 / 0 |

共 5 份 harness、30 个 replay 输入通过，启用 ASan leak detection 和 UBSan halt；没有运行长时间 fuzz 或 coverage 实验。源事实保持不变，原始失败出版物保留。数据在 `artifacts/context_semantics_final_audit_20260928_v3/summary.json`；后续精确 userdata owner 规则的加载复核也通过。

## 复现入口与尚未解决的问题

离线测试使用 `.venv/bin/python -m pytest -q`。真实调用入口：`scripts/smoke_context_pipeline.py`、`scripts/smoke_context_retry.py`、`scripts/smoke_plan_translation.py`、`scripts/smoke_context_schema.py`，均通过 `--env-file .env` 读取 provider 配置。使用 `--help` 查看具体 case/output 参数；新实验应使用新的输出目录，避免覆盖原始 trace。

`scripts/smoke_context_reproject.py --input <已保存 phase1> --output <新目录>` 默认不调用模型，重建派生 Context 和 Gate；增加 `--harness <已有源码>` 才检查现有模型 harness 的编译/runtime。只有显式 `--generate` 才请求新的代码模型。零模型复核结果必须单列，不能算作新增 native Context 调查。

汇总指标在 `artifacts/context_semantics_final_summary_20260928.json`。artifact 目录保持 git ignored，报告保存指标与路径，凭证不进入 git。

当前仍未解决：shared-context 多 CORE/wrapper 导致的义务规模及部分 unresolved typed lifecycle；模型将外部 callback context 声称为 input 却未给 harness 构造；复杂 interprocedural alias、branch、escape、宏展开 ABI，以及超出目前一层 callback table 的嵌套。源码事实的语义判定仍部分依赖模型和现有 validator。

下一步应围绕已保存的 shared/callback 失败，改善参数构造和局部依赖调查，并重复预算匹配的基本 API 实验。当前证据不足以宣称真实模型在五类 API 上稳定全部冻结，暂不开展大规模跨项目 benchmark，也不报告 Candidate recall、coverage 或泛化优势。
