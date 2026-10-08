# DeepSeek Harness Context 后端接入说明

更新日期：2026-10-08；首次接入日期：2026-10-07。

本项目增加了可选的 `deepseek-harness` Context 调查后端。它使用官方 DeepSeek Harness 的 Agent 循环推进一次调查，通过桥接调用本项目已有模型和源码工具，再向原有证明、修订事务及完整性检查提交结构化候选。默认仍为 `native`。

2026-10-08 后续验证：已安装固定版本 SDK/runtime，307 项离线回归和 3 项真实 SDK fixture smoke 通过；cJSON native / DSH 同版本对照各完成 3 次 parse，Context 均 0/3。23 个完成 parse 的真实 DSH 会话正常结束，但仍有静态 cleanup 缺口、schema/JSON 纠错失败和一次 prompt 容量停止。已再次按用户要求暂停，2 次结构试验中断、2 次未启动，详细记录见 [cJSON 静态缺口与 DSH 对照分析](CJSON_AGENT_BACKEND_GAP_ANALYSIS.md)。这不构成稳定性通过。

以下静态接入阶段与 v1/v2/v3 manifest 的范围保持不变：当时用户要求暂停测试，没有安装可选 SDK、启动 DSH runtime 或执行模型请求、pytest、fresh run、Gate、Plan、build/runtime 验证。后续运行证据保存在独立复测目录，没有覆盖历史零调用记录。

## 接入位置与数据流

```text
Minimal FT + 已签发源码证据 + 缺失证明反馈
  → HarnessContextAgent 准备调查提示词、terminal schema 和剩余预算
  → DeepSeek Harness 官方 Agent 循环
  → 本项目 BudgetedModel / 原源码工具 / 原结构化提交校验器
  → 原 Context 修订事务、证明图和 completeness 检查
  → 闭合并冻结的 Context
  → 后续 context-generate 的 Gate、Plan、代码生成与验证
```

DSH 的接入单位是一次 Context requirement 调查，可以包含同一函数的多个 grouped requirements。外层 `HarnessContextMiningLoop` 继续负责调度、补充调查、反馈路由、提交事务和完整性判断。

模型调用由已有 `BudgetedModel` 执行；源码查询由已有 `HarnessContextTools` 执行，继续限制函数范围、证据签发、读源码字数和工具额度。结构化提交继续使用本项目的动态 terminal schema 与校验函数。DSH 产生的结论必须通过这些校验，随后才能进入 Context 事务。

DSH runtime 使用本项目生成的专用内部 profile，只装载调查必需的官方循环、模型/工具注册、会话和桥接组件。该 profile 不开放 shell、文件系统写入、直接 provider 请求、自动模型重试、会话标题生成、自动 compaction 或子 Agent。源码读取通过本项目授权工具完成。后续若引入 compaction 或子 Agent，需要另外实现证据保真和统一账本，不能通过用户 profile 自动开启。

桥接采用仅监听 `127.0.0.1` 的临时 HTTP 服务，每次调查使用独立认证 token、严格递增请求序号和串行执行。临时 DSH home 包含完整内部 profile，插件复制到 profile 下以使用发布版 runtime 的模块 fallback；无需 npm 安装插件。子进程环境只保留路径、home、locale、临时目录等必要系统变量，凭据、外部 `DSH_*`、`NODE_OPTIONS`、`NODE_PATH` 等变量被实际移除。SDK 不接收 provider 的 `api_key` 或 `base_url`；实际 provider 连接由 Python 模型适配器持有。

发布版 SDK 的 `env=` 会与父进程环境合并，空字符串也可能触发“变量存在”的入口选择。因此本项目在固定版本 client 的 `_default_launch_args` 处清理 SDK 刚创建的子进程环境字典，再交回原启动方法写入独立 `DSH_HOME`；不修改父进程 `os.environ` 或已安装 SDK 文件。runtime 路径通过官方公开 `bundled_runtime_path()` 定位并显式传入 `dsh_bin`，固定为 `bundled-exe`，避免父环境改变 carrier。这处私有启动 hook 与 `0.1.5rc1` 的源码合约绑定，升级 SDK 时必须重新核对。

发布版 SDK 不能直接接收本项目已有的 assistant/tool 历史，因此完整初始对话作为会话中的 JSON seed 记录。实际模型请求使用 Python policy 保存的规范对话，包含原 system、framework 准备的证据、真实模型响应和源码工具结果。DSH 会话记录运行过程；它与 provider 对话通过 `python-authoritative-context-history-v1` 明确区分。拒绝的纯文本响应、provider 失败或修复反馈通过内部 `__harness_context_feedback` 调用推进官方循环；该调用不进入模型工具列表，不读源码、不签发证据，也不算 model/tool calls。

每次模型请求前刷新 terminal schema；最后普通轮和修复轮只提供 terminal。混合 terminal/tool 批次在执行任何调用前拒绝，调用 ID、名称、参数和顺序须与原模型提交一致。参数同时保留原始 JSON 字节，防止 JavaScript 数值转换改变大整数或浮点类型。畸形 JSON 使用原校验器反馈，在已有普通轮或明确允许的一次额外提交内请求新的完整答案。语义拒绝也必须重新显式提交；不自动改写模型结论。全局调用、源工具预算和原严格验证始终有效。

普通调查轮调用未知源码工具时，Python policy 会在 SDK 调度前拒绝整个批次，包括其中合法的兄弟调用。原调用 ID 得到明确的协议反馈，证据列表为空，源码工具计费为零；模型响应的真实调用与 tokens 仍保留。若还有普通轮和原有 protocol recovery 额度，Agent 可以修正工具选择，继续读取源码；最后预约的 terminal-only 轮仍生效。非法 ID、重复 ID、超长或非法原 JSON 不获得这条恢复通道，混合 terminal 批次及截断响应也继续遵守各自原有拒绝策略。

官方循环的 `concludeTurn()` 要等同批工具全部处理后才结束。当 Python 因工具或源码预算停止调查时，桥插件对同批余项继续核对原身份与参数，然后仅在本地返回“已停止”；不再发送 HTTP 请求、执行工具或发模型请求。这样不会把原预算停止原因覆写成 pending-call 协议错误。

结构化 terminal 校验会先把 native 提案和 group partial fallback 捕获到 Python 闭包，SDK 完成或关闭失败可能发生在其后。现在 DSH `abort` 会显式设置 `submission_revoked` 和原因；agent 撤销本次 native proposals、partial fallback 与 local repair audits，候选原文只保留为 trace 中的 `submission_revocation` 历史。外层首次提交同时拦截失败的 `native_submission` 和 `run.result`，缓存读取也拒绝撤销标记。真实 model/tool calls、tokens、provider events 和已签发的源码证据仍保留。已恢复并最终 answered 的历史错误不会触发这条撤销防线。

## 锁定版本

| 项目 | 固定值 |
|---|---|
| Python SDK | `deepseek-harness-sdk==0.1.5rc1` |
| Python runtime binary 包 | `deepseek-harness-runtime-bin==0.1.5rc1` |
| 上游发布 tag | `dsh-v0.1.5-rc.1` |
| 上游源码 commit | `183f08e9c6dde7e36cd2318eaee70b0da08fb35e` |
| 本项目桥接策略 | `dsh-context-bridge-v3` |
| 有界 Context policy | `dsh-bounded-context-policy-v3` |
| Context 提交 policy | `source-grounded-harness-context-v18` |
| runtime carrier | `bundled-exe` |
| 用户 profile 规范 | `dsh-context-profile-v1` |

选择发布版而非上游 master，是因为两者的消息表示和部分扩展接口不同。本桥接依照上述发布版本实现；升级 SDK/runtime 时应同步审查协议、工具批次行为和事件结构。只读源码记录位于 [upstream_contract.json](../artifacts/dsh_integration_20261007/upstream_contract.json)，上游源码见 [固定发布 commit](https://github.com/deepseek-ai/deepseek-harness/tree/183f08e9c6dde7e36cd2318eaee70b0da08fb35e)。

## 安装与调用

在项目根目录按需安装可选依赖：

```bash
pip install -e '.[dsh]'
```

原有 native 用户无需安装这些可选依赖。CLI 的 `--help` 在解析参数后立即退出，既不导入可选 SDK，也不启动 runtime。

先通过现有上游阶段准备有效的 SFG、Slice 和 Minimal FT artifacts，再运行独立 Context 阶段。例如，使用已有 DeepSeek 环境配置：

```bash
python -m harness_generation harness-context \
  --artifacts /absolute/path/to/artifacts \
  --agent-backend deepseek-harness \
  --provider deepseek \
  --env-file /absolute/path/to/provider.env
```

模型/provider 参数沿用本项目原有配置。DeepSeek 使用 `DEEPSEEK_API_KEY`；兼容 provider 使用 `LLM_API_KEY`、`LLM_BASE_URL` 与 `LLM_MODEL`。也可以通过 `--model` 指定模型、`--thinking` 指定 thinking 配置、`--agent-timeout 60` 或 `120` 指定单次 provider 请求的 transport timeout。凭据不写入 DSH 用户 profile 或持久化配置描述符。

已安装 console entry 时，可以将 `python -m harness_generation` 替换为 `harness-generation`。也可使用 `python -m harness_generation.harness_context.cli` 直接启动该阶段。`--ft` 与 `--candidate` 仍接受精确 artifacts ID。

`harness-context` 命令产出 Context 及完整性报告。生成 C harness 仍由后续 `context-generate` 阶段负责。

## 用户 profile

`--dsh-profile` 接受 UTF-8 JSON 文件，最多 32768 字节。缺省字段自动补齐；未知字段、重复 key、无穷大、NaN 和越界数值会被拒绝。以下是完整默认值：

```json
{
  "max_prompt_chars": 400000,
  "max_response_chars": 64000,
  "max_session_events": 4096,
  "max_event_chars": 1000000,
  "request_timeout_seconds": 180
}
```

保存为 `dsh-profile.json` 后调用：

```bash
python -m harness_generation harness-context \
  --artifacts /absolute/path/to/artifacts \
  --agent-backend deepseek-harness \
  --dsh-profile /absolute/path/to/dsh-profile.json \
  --provider deepseek
```

| 字段 | 用途 | 允许范围 |
|---|---|---|
| `max_prompt_chars` | 桥接模型输入的字符上限 | 整数 1–2000000 |
| `max_response_chars` | 桥接模型响应的字符上限 | 整数 1–1000000 |
| `max_session_events` | 一次调查的会话事件数量上限 | 整数 1–65536 |
| `max_event_chars` | 单个 DSH 会话事件的字符上限 | 整数 1–16000000 |
| `request_timeout_seconds` | 一次 DSH 调查的 watchdog 时间上限 | 大于 0 且不超过 3600 的有限数值 |

字符限制与 token 额度是不同约束。`request_timeout_seconds` 控制整次调查/IPC 等待，`--agent-timeout` 控制单次真实 provider 请求；调整前者不会增加模型调用次数。用户 profile 不能配置 provider 凭据、Cordis 插件路径、工具、shell、子 Agent 或额外调用预算。

watchdog 超时停止接收新调用并关闭 SDK runtime，返回前排空已开始的 provider 请求，以保留准确账本。provider 的收尾继续依赖原 OpenAI/httpx transport timeout，本后端没有新增中断 Python provider socket 的机制，也没有执行证据证明严格总墙钟上限。完成与超时通过独立锁原子判定，普通 SDK 失败保留自身停止原因；已完成调查不会被迟到的 timer callback 改判。HTTP socket timeout 从建立 handler 起覆盖请求行、headers 和 body；停止时还会主动关闭已接收的 socket，解除持续零碎数据造成的等待。主动关闭引发的读写异常不会覆写原停止原因。

固定 SDK 的请求 timeout 在写入 stdin 后才开始计时，`close()` 又先发送 shutdown 请求，可能被同一写锁阻塞。独立进程监督不取得 SDK、写入、policy 或关闭锁，持续观察 `client._proc`，覆盖 deadline 早于进程赋值的情况。正常关闭给予 2 秒 grace；watchdog 超时时立即监督终止。终止后先等 0.25 秒，再 kill 并最多等待 1 秒回收，解除通常可终止进程的阻塞管道。回收异常归档为 `dsh_runtime_reap_error`。这也是固定版本私有接口适配，源码合约见 [追加核对](../artifacts/dsh_integration_20261007/upstream_contract_v3.md)。

监督成功或失败都通过 `dsh_runtime_supervision` 记录触发原因、terminate/kill 请求及回收结果。诊断队列在所有 owner 线程收尾后才写入 trace，不增加模型、工具或 provider 调用。正常关闭成功的强制终止不会单独撤销已接受的提交；明确的 SDK 关闭或回收失败仍撤销。回收失败后保留已观察的进程引用，即使 SDK 清空 `_proc` 也继续等待 OS 确认退出，不反复发送 terminate/kill。

临时目录建立/清理、bridge 服务及其他收尾异常也归档为明确的执行失败，撤销本次候选后返回调查结果。各项清理独立尝试，一项失败不能跳过后续资源关闭；错误记录保留类别与异常类型，不写入 SDK 原始异常文本。

因此收尾时间可能超过 watchdog 值，还需等待正在执行的 provider 请求及进程清理。如果 OS 无法终止或回收进程，框架保留等待与失败记录，不分离仍可能活动的 SDK/账本线程来提前宣告完成；目前不能保证这类极端状态下的严格返回期限。默认 180 秒短于四轮请求加额外修复都用满 60 秒的最坏耗时；需要完整等待这类慢请求时可调高该字段，例如 360 秒，原调用预算不会增加。

监督线程创建失败时会记录 `dsh_runtime_supervision_error`，并尝试直接回收当时已赋值的进程。这条 fallback 仍不能覆盖进程尚未赋值、随后启动又阻塞的情况；这种资源故障下的返回期限也尚无保证。

`--dsh-profile` 只能与 `--agent-backend deepseek-harness` 一起使用。Python 测试/调用方通过 `main(..., model=...)` 注入模型时，也不能同时选择 DSH CLI 后端，避免绕开真实 provider 和执行方式的配置绑定。

## 预算、记录与 resume

原 `ContextBudget` 的全部字段继续生效，包括总模型调用、每次调查轮次、工具调用、源码字数、发现函数、完整性修订轮次、terminal 修复、准备读源码和保留预算。CLI 的对应参数仍为 `--max-total-model-calls`、`--max-tool-calls` 等。

框架 bootstrap 和自动准备读取在进入 DSH 循环前已真实扣费，作为调查初始事件传入。模型请求继续进入全局 `MiningState` 账本；grouped 结果继续只给一个 cost owner 记费。DSH 会话事件不能替代真实 provider 请求、工具执行和证据签发记录，也不能当成额外免费调用。

DSH configuration 的 `agent_backend` 描述符绑定 SDK/runtime 版本、runtime carrier、桥接策略、桥插件和 kernel 摘要、原生提示/终态/工具/有界 policy 摘要、有效用户 profile 摘要与完整 `ContextBudget`。它通过原 `configuration_fingerprint` 进入 requirement attempts、修订事务和最终 Context 的持久化兼容检查。更换后端或上述配置将导致原缓存不兼容。直接 Python API 在持久化前也检查所传 configuration 与 backend、MiningState 预算是否匹配。

`native` 的原配置形状保持不变，既有 native resume 规则继续使用。首次提交防线属于 Context policy 的语义变更，因此版本从 v17 升至 v18，旧 Context 缓存不能直接作为新版有效结果复用。`--resume` 可复用的前提仍包括源码指纹、上游 FT、配置、证据、提交 marker 与活跃 resolution 的一致性；闭合 Context 还会按原规则重新检查后才复用。依赖版本识别应在启动 runtime 前完成，真正调查才启动可选后端。

CLI 选择 DSH 时先只读检查两个可选包的版本，缺失或不匹配会清晰报错；完整缓存复用不启动 runtime。Python backend 的 runtime/桥接错误返回含 `execution_error` 的调查结果，保留之前的真实请求和工具账本；超时、会话异常结束或关闭失败不会保留该轮的有效 decision。DSH 事件以 `dsh_session_event` 归档，认证 token 和私有 endpoint 被脱敏；计费仍取原 `model_response`、`model_error` 和 `tool_call` 记录。

下一次使用重复实验 runner 冻结当前代码时，生产清单同时包含 `.mjs` 桥插件和 `dsh_kernel.json`，避免只冻结 Python 而丢失运行资产。本轮没有重新冻结或执行历史 cohort；原 fresh artifacts 保持原有版本和结果。

## 重复实验接线

`scripts/repeat_fresh_stability.py` 已接受 `--agent-backend` 和 `--dsh-profile`。选择 DSH 必须使用 `--freeze-current`，以新生产 fingerprint 登记完整后端描述符、规范化的有效 profile 副本及哈希。只有 `harness-context` 阶段采用 DSH；Candidate、Slice 和代码生成继续使用各自原执行方式。缺省选择 native，旧 native 登记仍按原规则读取。

登记阶段只构造描述符，不导入 SDK 或启动 runtime。实际执行前，supervisor 和 worker 都使用标准库读取包元数据与平台载荷，检查固定 SDK/runtime 版本、Python 入口、runtime marker、平台 executable、ripgrep 及必要 macOS helper，并检查执行权限。结果记录为静态能力条件，不表示 runtime 已启动；缺包、错版本或载荷缺失会在任何 worker 上游模型请求前停止。Context CLI 原有版本检查继续生效。

执行前还检查 profile、完整预算、固定后端元数据和运行资产与冻结源码一致，防止登记声明与实际配置错位。`--register-only` 仅生成可审查的注册与冻结配置，不执行依赖 probe、SDK 或模型；使用 `--run-registered` 才执行同一注册，先重新核对完整性与依赖条件。

恢复测试后，可按以下命令创建独立 DSH cohort。该命令会登记并立即启动实验，本轮未执行：

```bash
python scripts/repeat_fresh_stability.py \
  --output /absolute/path/to/new-dsh-cohort \
  --freeze-current \
  --agent-backend deepseek-harness \
  --dsh-profile /absolute/path/to/dsh-profile.json \
  --json-repetitions 5 \
  --sample-repetitions 3 \
  --workers 1
```

默认样例包括 `json_parse`，以及 callback construction source、shared context lifecycle、owned-return cleanup、out-parameter creator、memory stream abstraction 五个开发样例。可通过 `--cases json_parse` 单独登记同目标重复，或选择已有结构样例；这些样例仍属于已知开发回归，不能作为盲测泛化证据。

如果先审查配置，在上面的命令增加 `--register-only`。后续执行同一登记使用：

```bash
python scripts/repeat_fresh_stability.py \
  --run-registered /absolute/path/to/new-dsh-cohort
```

`--run-registered` 不重写登记，不接受新的后端或预算覆盖；源码或登记资产已变化时拒绝执行。本轮没有执行这些命令，也没有重新冻结生产 cohort。

collector 保存登记与真实 Context 后端描述符、fingerprint、hard gaps、model/tool calls、tokens 和 provider events。`dsh_*` 诊断事件单独统计，并排除 grouped 成本副本，不重复累计 provider 成本。独立 auditor 不导入生产源码，核对冻结资产、包版本、profile、完整预算、Context 顶层与主调查配置，以及主 trace 的 `dsh_backend_start` receipt。Context 已进入并结束而 publication、配置、metrics 或付费 trace 缺失时明确判为观察缺口；合法 attempt 不能掩盖缺失的顶层配置。未开始或被上游阻塞的阶段保留未知/跳过状态，不提供 DSH 成功证据。

预检观察归档保留历史；审计只用当前 receipt 判断本次执行条件。当前 worker 或 supervisor 预检失败不能与随后阶段进入、模型/工具/provider 调用、付费产物或成功 trial 并存。为兼容历史登记，缺失 supervisor receipt 目前仍不单独判错，因此缺少该观察时不能把审计通过解释为已经证明执行前零付费。

worker 和 auditor 分别从冻结 Python AST 恢复固定后端描述符，检查 carrier、SDK/upstream/policy/history、字段集合及完整资产名单，避免“改声明后重算 fingerprint”被接受。恢复器只支持当前描述符使用的 literal 与已知常量 Name，不执行生产源码；将来改变描述符的表达式结构，需要同步调整恢复器。

## 当前能力边界

接入为更换调查运行层提供了受限入口；尚无 fresh-run 证据证明其提高了成功率、成本或稳定性。

静态释放证明覆盖不足、资源身份迁移、修订事务状态同步、分支路径 cleanup 校验及缺失的反馈路由，仍由本项目对应模块处理。DSH 循环也可能选错查询、遗漏 helper、产生错误条件或耗尽预算；这些情况需要完整性反馈和后续修订逻辑处理。

目前 schema/语义 terminal 修正轮只允许用已有证据重新提交，不能重新开放源码调查。工具或源码额度耗尽也会停止该次调查，不会自动使用预约终端轮总结已有证据。这两点继承现有有界策略，未知工具反馈恢复并不等于任意错误都能回滚、重新取证并闭合 Context。

上游 runtime 会增加 IPC、消息转换、会话事件和进程生命周期等故障面。后续恢复测试时，需要同时核对发布版 API、请求/工具计费、失败事件归类、进程清理、native 回归、缓存隔离和固定 fingerprint 的重复结果。当前仅完成代码接线、版本接口调查与静态检查，不能将它报告为稳定性验证通过。

## 静态核对与未执行的验证

初次接入的 12 个相关 Python 文件通过 `ast.parse`，桥插件通过 `node --check`，内部 kernel JSON、`pyproject.toml`、可选依赖固定版本及 wheel 资产声明已静态核对，相关已跟踪文件的 `git diff --check` 无格式错误。该阶段记录保留在 [static_integration_manifest.json](../artifacts/dsh_integration_20261007/static_integration_manifest.json)，其中源码摘要属于初次接入版本。

第二阶段补充环境隔离、同批工具停止、未知工具协议反馈、watchdog 完成竞态、不完整 HTTP headers 收尾及 cohort 登记/观察定义。源码合约见 [upstream_contract_v2.md](../artifacts/dsh_integration_20261007/upstream_contract_v2.md)，当时的摘要和检查结果见 [static_integration_manifest_v2.json](../artifacts/dsh_integration_20261007/static_integration_manifest_v2.json)。

本次第三阶段继续补齐中止后的候选撤销、首次提交与缓存防线、主动停止 HTTP IO、独立进程监督与资源清理、依赖前置检查和只登记/执行既有登记入口。**没有执行回归定义**，包括使用 fake SDK 或 fake JS host 的离线回归也未执行。当前源码摘要、定义数量及静态解析结果另记入 [static_integration_manifest_v3.json](../artifacts/dsh_integration_20261007/static_integration_manifest_v3.json)，没有覆盖历史记录。

本轮框架模型调用、源码工具调用、provider 请求均为 0，没有启动 SDK runtime。runner 的 DSH 选择与登记链已经接通，但运行正确性、进程生命周期和重复稳定性仍没有执行证据；默认 runner 的 native 结果不计作 DSH 验证。
