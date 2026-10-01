# 参数构造、局部依赖闭合与固定预算重复实验

本报告的五类 fixture 已正式归为 **Development / Regression Set**。所有历史实测与配对重放均是开发证据，禁止计入 Blind Generalization 的成功率。

本轮基于本地 `v0.2` 实现，集中处理 shared-context 与 external callback context 的 harness construction。**固定预算真实实验的端到端成功为 13/25；证据配对重放为 17/25，仍不能宣称稳定或跨项目泛化。**没有增加 Agent 工具或流水线阶段。实验源码是五种小型 API 模型，不能据此评估项目级 Candidate recall 或宣称跨项目泛化。

## 实现与证明边界

新增 `harness_generation/harness_context/construction.py`。`construction_contract` 是框架根据已签发、完整的源码和已校验声明生成的对象，带有 construction ID、evidence IDs、资源源头、构造方式、初始化步骤及有效期。Context validator 重新推导整个对象；修改证书 JSON 不能通过验证。

shared-context 的 `creator_return` 证书连接一个具体调用位置的 creator 返回值、局部 alias、consumer 参数和唯一 cleanup 参数。当前确定性闭合限定为：无参数 creator 明确返回一个 `calloc(1,sizeof(T))` 对象；cleanup 明确释放同一参数；consumer 只访问该对象的字段且对象不逃逸；调用者值流为直线且消费在创建之后、释放之前；同一 API 端点不能对应多个源或重复调用。相同类型、相似名字、相同模型 resource 字符串均不是证明。

字段写入只接受来自声明参数的直接赋值，拒绝条件写入、重复覆盖、复杂 cast/调用。writer 与 reader 共享精确值源、实际字段交集和调用顺序，才形成局部 state transition。框架将源证据投影到缺失的 consumer lifecycle 和 cleanup argument，建立 creator/cleanup API closure 依赖，再由现有 hard ordering graph 表达必须顺序。

对于已经完全被上述证书证明的 consumer lifecycle/call-order requirement，Gate 记录独立的 `framework_satisfied_requirements`，避免要求模型重复证明。原始模型 requirement 状态和 facts 不改写。其余 input、ownership、return、callback 等未知义务仍按原有 Gate 阻塞；并非将所有 unresolved 都视作通过。模型状态与框架证明覆盖应分别查看。

external callback context 使用 `public_callback_object` 证书，要求完整且唯一的公开 layout、精确 callback field、已验证 userdata 关联、已知 callback lifetime、borrowed/during-call ownership，以及对象仅通过声明字段进行同步 callback 调用。整个 layout 必须都能被显式字段初始化覆盖，连未读取的额外字段也不能凭空略过；数组/bitfield、不可解析 layout、对象逃逸、额外调用/写入保持未证明。

通过验证时，证书明确指定每次 fuzz input 的 stack storage、zero-init 后的 callback stub 字段赋值、配合不解引用 userdata 的 stub 使用 null userdata，以及 call-return 终点。这是特定公开结构的可验证构造方案；不是根据 `ctx` 名称、`input` 标签或“找不到 creator”自动选 stack。原始模型的 `input` lifecycle/argument 保存在 facts 中，派生的可执行契约引用 construction ID。

Agent 调查前通过已有 `find_resource_flows`、`find_callees`、`get_function` 查询补齐相关局部证据，不扩大 registry，也不越过 scope、discovery/depth 或源码预算。缓存复用有独立 trace 事件，实际新增查询才计入工具成本。Plan 保存 construction sources，代码模型按明确 recipe 构造和复用对象。初始冻结实验使用 construction v1、Plan/code prompt v3、Context prompt v5；配对修复使用 construction v2、Plan/code prompt v4；最后的独立调度复测使用 Plan/code prompt v5。construction version 纳入配置，改变规则后旧 Context 必须重新验证。

新增反例覆盖额外 callback 状态、对象 escape、证书篡改和条件 feed。初始离线回归 **275 passed**，最终 **284 passed**；依赖检查与 `git diff --check` 通过。保存的 callback 原始模型事实在零模型重投影下达到 complete，原始 facts 不变。旧 shared publication 因新的 source-derived closure 改变了必要 requirement universe 而被标为 stale/invalid，不能把它计入当前完整链成功；下面重复实验全部从新的静态输入开始。

## 实验设计

运行 `scripts/repeat_context_pipeline.py`，五类各 5 次，共 25 次。每次建立新项目/artifact，执行真实 Candidate Validation → Slice → Minimal FT → Context → Plan → code → compile → ASan/UBSan replay。显式指定 parse anchor；静态分析 parser-only；没有 hand-selected FT、Fake 模型语义或失败后追加重试。两个独立进程并发，结果逐次保存，失败也计入分母。

所有类别使用相同预算：Candidate Validation 与 Slice 各最多 6 exploration rounds、24 个 repository tool calls、48,000 source chars、每次最多 10 个 references/callers/callees；保留既有单次 terminal schema repair。Context 的全局模型预算 24 calls、64 tools、96,000 source chars、最多 16 个 discovered functions、依赖深度 2、3 个 completeness rounds，每组调查最多 4 rounds 和一次既有 terminal repair。框架预查询也计入 Context 工具预算，terminal 预留不增加调用预算。

Agent 输出上限 Candidate/Slice 为 4,096 tokens，grouped Context 为 8,192；code translation 为 8,192。Agent temperature 未指定，使用 provider 默认值；没有设置或声称独立随机 seed。code model 使用现有 temperature 0.2。输入源码摘要、预算文件、provider 配置、实际 served model、实现 fingerprint 与全部 trace 保存于实验目录。

runner 在开始和结束验证实现源码 fingerprint 一致。实验期间不修改生成逻辑，也不因某类失败增加其预算。这里“预算匹配”指相同阶段上限，而不是实际 tokens 一样：不同 FT、动态 closure 和模型工具选择会产生不同消耗。

## 结果

### A：完整链真实调用，五类各 5 次

请求模型为 `ark-code-latest`，实际响应模型均为 `deepseek-v4-flash-ga-260731`；provider 为 `openai-compatible`，thinking disabled。运行时间为 2026-09-28 23:46 至 2026-09-29 00:09（北京时间）。25 次全部执行，没有 runner error；源码 fingerprint 前后一致。

| API 模型 | Slice success | Context completion | Compile | Runtime | hard gaps：均值 / 中位数 / 范围 |
| --- | ---: | ---: | ---: | ---: | --- |
| direct | 5/5 | 5/5 | 5/5 | 5/5 | 0.00 / 0 / 0–0（n=5） |
| nul_string | 5/5 | 5/5 | 5/5 | 5/5 | 0.00 / 0 / 0–0（n=5） |
| shared_context | 4/5 | 0/5 | 0/5 | 0/5 | 2.75 / 1 / 1–8（n=4） |
| owned_return | 5/5 | 3/5 | 2/5 | 2/5 | 0.60 / 0 / 0–2（n=5） |
| callback | 5/5 | 1/5 | 1/5 | 1/5 | 1.00 / 1 / 0–2（n=5） |

总计 Slice **24/25**、Context **14/25**、compile/runtime **13/25**。compile/runtime 以所有 25 个 trial 为分母；未进入生成的 trial 没有编译或运行，记为未成功，不能称为编译器失败。shared-context 第 5 次在 Slice 阶段失败，hard gaps 为 N/A，不计入 gap 均值；其余 24 次都产出了 Context。

下面是整个 Candidate → Slice → Context → code 的实际消耗，格式为「均值（最小–最大）」；中位数和分阶段计量保存在 summary。model calls 包括尝试但失败的调用，tokens 是响应中实际收到的 usage，不推算无 usage 的服务端费用。repository tools 不包含本地 compiler/runtime。

| API 模型 | Model calls | Tool calls | Tokens |
| --- | ---: | ---: | ---: |
| direct | 9.8（9–12） | 12.2（10–16） | 52,468.6（48,645–62,494） |
| nul_string | 10.8（10–12） | 13.8（11–18） | 64,008.0（58,943–73,202） |
| shared_context | 21.6（9–31） | 46.6（20–66） | 206,064.4（47,068–307,591） |
| owned_return | 15.8（15–18） | 23.0（19–27） | 119,183.0（101,221–142,779） |
| callback | 20.8（19–23） | 36.2（28–39） | 174,463.8（152,319–185,216） |

总消耗 **394 model-call attempts、659 repository tool calls、3,080,939 tokens**。Context 的 24-call 上限只约束 Context 阶段，因此 shared-context 全链最多 31 calls 不表示超出 Context 预算。

| API 模型 | 已运行 Context 的数量 | Context calls 均值 | Context tools 均值 | Context tokens 均值 |
| --- | ---: | ---: | ---: | ---: |
| direct | 5 | 2.00 | 3.40 | 18,912.8 |
| nul_string | 5 | 3.00 | 4.60 | 31,008.8 |
| shared_context | 4 | 15.50 | 37.00 | 193,403.8 |
| owned_return | 5 | 7.00 | 10.40 | 75,005.6 |
| callback | 5 | 12.20 | 23.40 | 134,645.0 |

shared-context 的 CORE 大小为 3、3、2、2，第五次没有有效 FT；前两次把 example caller wrapper 纳入 CORE，扩大了义务。其他类别 CORE 均为 1。source construction 在已产出的四个 shared-context 中都能建立局部资源链；callback 中 4/5 建立公开结构构造证书，但这不等于整个 Context 完成。

### A 的失败定位

| Trial | 实际阻塞 |
| --- | --- |
| shared 1 | 8 hard gaps，包括 wrapper 参数缺失、ctx 错标 fuzz buffer、未知 ownership/state、wrapper support ordering；另有 `conflicting_resource_identity` |
| shared 2 | cleanup 参数被标成 owned，却没有 release API |
| shared 3 | cleanup ownership 缺口，另有 parse 的 feed-init 与 creator lifecycle 冲突 |
| shared 4 | parse state requirement 未解决，另有同一资源的初始化投影冲突 |
| shared 5 | Slice `invalid_output`：support wrapper 只给出 wrapper delegation，缺少具体 setup/lifecycle reason；保守 fallback 不被当作成功 Slice |
| owned 2 | cleanup 参数 owned/release 缺口 |
| owned 3 | cleanup argument requirement unresolved，参数未构造 |
| owned 4 | Context complete，但生成代码在声明 parse 前未定义 `size_t`，编译失败 |
| callback 1/3/4 | construction 已证明；标量 return success 仍为 unknown |
| callback 2 | 字段初始化被表示成 mandatory init/unknown API，另有 unknown return success |

### B：同一批原始模型证据的配对重放

完成 A 后冻结第二版实现，执行 `scripts/repeat_context_reproject.py`。不调用 Candidate、Slice 或 Context 模型，不补源、不改原始 facts、requirements 状态或 resolutions。模型 requirement 仍 unresolved 的部分，通过独立、可重算的 framework proof coverage 满足；不把未知返回语义改成 always。

此次修复包括：

- 完整的 public callback field recipe 可以满足 mandatory initialization/API null；明确指定的 init API 仍不能被 recipe 消除。
- 唯一已有 owned producer/lifecycle，加上完整源码中精确的单参数 `free(parameter)` cleanup，可生成 `cleanup_consumption`，绑定遗漏的 cleanup argument，并将派生 ownership 表示成 consumed/transferred。显式其他 release、多个来源、其他资源的实际 cleanup、非精确 wrapper、CORE cleanup 均不采用此规则。
- 同一资源的 parse「feed 初始化」在 source writer→reader 和 input_fed precondition 都吻合时表示为已排程的 state transition，避免误作重复的全局 resource initializer。原始 lifecycle fact 保留。
- 全部 context 参数的字段读取都由一个已证明 writer 满足时，框架可覆盖相应局部 state requirement；条件 writer、部分字段和其他参数不据此获得全量覆盖。局部链遇到不可识别的资源使用或字段自增时不发证书。
- code prompt 要求在目标声明之前包含标准类型头文件，保留编译失败原件。

| API 模型 | A Context → B Context | A Runtime → B Runtime |
| --- | ---: | ---: |
| direct | 5/5 → 5/5 | 5/5 → 5/5 |
| nul_string | 5/5 → 5/5 | 5/5 → 5/5 |
| shared_context | 0/5 → 3/5 | 0/5 → 1/5 |
| owned_return | 3/5 → 5/5 | 2/5 → 5/5 |
| callback | 1/5 → 1/5 | 1/5 → 1/5 |

B 总计 Context **19/25**、compile/runtime **17/25**。新增 5 次真实 Plan→code translation，usage **47,130 tokens**；13 个已有成功 harness 使用 `--harness` 重新验证，没有再次模型生成。没有有效 Context 的 shared 5 没有重放。B 的源码 fingerprint 前后一致。

仍保留以下失败：callback 1–4 均因 unknown return success 阻塞（callback 2 的 init 缺口已消除，构造证书成为 5/5）；shared 1 仍 invalid 且有 6 hard gaps；shared 2 Context complete，但 Plan 的独立 wrapper 排在 cleanup 之后而阻塞；shared 4 Context complete，但 code 中两处 destroy 和一个宏定义违反精确 Plan，被代码 validator 拒绝；shared 5 为原有上游失败。

B 是对相同模型事实的框架消融式比较，**不是第二批 25 次完整原生模型实验，也不证明修复后的模型调查轨迹稳定**。A 与 B 没有相同 tokens 的目标：B 的 Context 成本为零，额外 code 成本单列，不能把它合并到 A 的预算统计。

### C：Plan 调度的独立针对性复测

B 结束后修复 Plan 拓扑排序：多个调用同时满足硬依赖时优先执行 active CORE，再 cleanup；不添加虚构的语义边。若硬依赖要求 cleanup 在后续 active use 之前，仍拒绝，需要显式 lifetime schedule。增加正反回归。同时 code prompt 明确拒绝宏，要求所有错误路径进入唯一的 cleanup call site。

对原始 shared 2 的相同证据做独立重放：0 Context calls、1 code call、20,899 tokens，**Plan → compile → ASan/UBSan runtime 通过**。对 shared 4 同样追加 1 code call、15,491 tokens，模型仍把 destroy 写在两个分支，被 validator 拒绝；没有放松调用次数或排序检查。两个 follow-up 共 36,390 tokens，均保存在独立目录，没有覆盖 B 的失败或修改其统计。

### 每次原生实验计量

| 类别 / 次数 | 状态 | hard gaps | Model calls | Tool calls | Tokens |
| --- | --- | ---: | ---: | ---: | ---: |
| direct / 1 | passed | 0 | 9 | 10 | 48,645 |
| direct / 2 | passed | 0 | 12 | 16 | 62,494 |
| direct / 3 | passed | 0 | 10 | 12 | 50,384 |
| direct / 4 | passed | 0 | 9 | 13 | 50,700 |
| direct / 5 | passed | 0 | 9 | 10 | 50,120 |
| nul_string / 1 | passed | 0 | 10 | 11 | 63,828 |
| nul_string / 2 | passed | 0 | 11 | 14 | 63,903 |
| nul_string / 3 | passed | 0 | 11 | 14 | 60,164 |
| nul_string / 4 | passed | 0 | 12 | 18 | 73,202 |
| nul_string / 5 | passed | 0 | 10 | 12 | 58,943 |
| shared_context / 1 | blocked | 8 | 18 | 42 | 181,873 |
| shared_context / 2 | blocked | 1 | 31 | 58 | 307,591 |
| shared_context / 3 | blocked | 1 | 20 | 47 | 191,687 |
| shared_context / 4 | blocked | 1 | 30 | 66 | 302,103 |
| shared_context / 5 | semantic-slice_failed | N/A | 9 | 20 | 47,068 |
| owned_return / 1 | passed | 0 | 15 | 21 | 101,221 |
| owned_return / 2 | blocked | 1 | 18 | 27 | 142,779 |
| owned_return / 3 | blocked | 2 | 16 | 26 | 131,125 |
| owned_return / 4 | compile_failed | 0 | 15 | 22 | 112,512 |
| owned_return / 5 | passed | 0 | 15 | 19 | 108,278 |
| callback / 1 | blocked | 1 | 20 | 39 | 173,262 |
| callback / 2 | blocked | 2 | 21 | 39 | 179,947 |
| callback / 3 | blocked | 1 | 19 | 28 | 152,319 |
| callback / 4 | blocked | 1 | 21 | 38 | 181,575 |
| callback / 5 | passed | 0 | 23 | 37 | 185,216 |

### 结论与边界

确定性 construction source 已能表达公开 callback stack/field initialization，以及具体 creator-return→consumer→cleanup 资源链；原始模型的泛化 input/context 标签不会直接成为生成许可。重复样本证明 cleanup 与 init/state 的某些波动可以由源码证据补全，但 unknown return semantics、wrapper CORE 膨胀和代码模型多 cleanup call site 仍是实际瓶颈。

五种 fixture 每类只有 5 次，且使用显式 anchor，没有项目级 Candidate recall、真实项目复杂度、跨提供商对照或 coverage 实验。即使 5/5，Wilson 95% 成功率下界也只有约 56.6%；无法据此保证稳定。Runtime 仅包含六个固定输入的 ASan/UBSan/leak replay，不代表 fuzzing coverage 或穷尽验证。

源码证书是一个受限 C 子集的可复算规则；没有实现全局宏重定义/跨编译单元条件分析、C++ 构造规则或任意隐藏状态不变量的形式化证明。opaque creator、复杂 initializer、异步/逃逸 callback、多来源/多实例、循环调度仍需已有 Agent 获取具体证据，缺口不能由类型或函数名补齐。

后续应首先解决标量结果消费策略与 unknown success Gate、消除 wrapper 的非必要 CORE 扩张，并让 Plan 的错误路径明确约束唯一 cleanup。再对当前实现重跑新的完整固定预算样本；本轮配对结果不能代替这个稳定性评估。

本地机器记录：`artifacts/context_budget_repeats_20260928/summary.json`（A）、`artifacts/context_paired_replay_20260929/summary.json`（B）、`artifacts/context_plan_followup_20260929/`（C）。每次 source、trace、evidence、原始失败 publication、Plan、harness、compiler 与 runtime 结果均独立保存。artifact ignored，不进入 git。

## 可复现命令

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/repeat_context_pipeline.py \
  --output artifacts/<new-directory> --repetitions 5 --workers 2 --env-file .env
```

配对重放命令：

```bash
.venv/bin/python scripts/repeat_context_reproject.py \
  --input artifacts/context_budget_repeats_20260928 \
  --output artifacts/<new-paired-directory> --env-file .env
```

此命令使用运行时的当前实现；A/B 各自的 fingerprint 已保留，但没有将整个源码快照归档，因此仅有 artifact 不能复建旧版本二进制。本地源码有原有未提交改动，当前报告不声称与远端分支完全一致。

真实 API 测试不进入 pytest。`.env` 和实验 artifact 保持 ignored，凭证不进入报告或 git。
