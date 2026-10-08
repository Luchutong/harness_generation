# cJSON 静态证明缺口与 DSH 能力对照

日期：2026-10-08（Asia/Shanghai）。本轮测试已按用户要求暂停，后续仅只读分析源码和已保存产物，未修复生产代码、重跑模型、重建 Gate 或执行 build/runtime。

**目前没有证据证明接入 DSH 提高了 cJSON 的 Context 闭合率或端到端稳定性。** 真实 DSH 载体、桥接、预算和反馈链可以运行；主要瓶颈仍是静态证明覆盖、资源契约表达、查询调度和模型纠错。正常结束的 SDK 会话不等于成功闭合的 Context。

## 实验与暂停边界

新生产 fingerprint：`165099c636259b0fbd4fdaedab4c5316f97e0ec5608491eee5cd11a26028bd6c`，177 个生产文件。目标只包含 `/home/luchitong/work/cjson_recon/project/cJSON.c`、`cJSON.h`；目标与历史基线的两文件 hash、构建配方一致。固定入口来自自动候选目录，不使用父目录历史 harness 或手填 Context 事实。

登记 native、DSH 各五次：同目标 parse 各三次、PrintUnformatted 各一次、PrintPreallocated 各一次。暂停时 **6 次 parse 完成，2 次打印试验中断，2 次未启动**。监督进程接收 SIGTERM，退出 130；两个活动 worker 退出 -15，相关进程已确认退出。[暂停记录](../artifacts/cjson_agent_retest_20261008/testing_paused.json) 与原始 supervisor 记录保留，不把中断试验计作能力失败或成功。

原始 `completion_audit.json` 记录六条已收集结果，`all_scheduled_observed=false`。独立分析另外核对八个实际 supervisor 终态，其中两个为中断；没有伪造完整十次审计。六个完成样本的身份、有效配置、primary cost owner、响应/tokens、Gate 零代码请求审计均通过，完整 cohort 审计仍为 false。见 [只读暂停汇总](../artifacts/cjson_agent_retest_20261008/paused_analysis/summary.json) 与 [完成样本审计](../artifacts/cjson_agent_retest_20261008/paused_analysis/completed_trial_audits.json)。

测试前 238 项 DSH/后端回归和 69 项 Context/事务/恢复回归通过。一次测试夹具把内部 requirement 响应数当作外部模型请求数，修正的是测试计数，原失败及复现记录保留；未修改生产行为。三个真实 SDK/runtime fixture smoke 通过，实际 provider 请求为零。它们验证执行合约，不能代替 cJSON fresh 成功。

## 同目标结果

| 组 | Slice 有效 | Context 闭合 | hard gaps（逐次） | Plan / build / runtime 到达 | 全链 model / tool | 已知 tokens | provider 响应 / 失败 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 历史 native，11c9ce… | 3/3 | 0/3 | 3 / 20 / 2 | 0 / 0 / 0 | 66 / 161 | 2,829,588 | 66 / 0 |
| 当前 native，165099… | 3/3 | 0/3 | 4 / 3 / 9 | 0 / 0 / 0 | 70 / 159 | ≥2,672,982 | 69 / 1 timeout |
| 当前 DSH，165099… | 3/3 | 0/3 | 9 / 2 / 2 | 0 / 0 / 0 | 59 / 114 | 2,437,315 | 59 / 0 |

表中 model/tool/tokens 含 Candidate、Slice、Context 和预算内修复。工具数采用持久化阶段预算口径，包含框架源码操作，不能直接替换成模型发出的 tool calls 或原始 trace 事件数。六次 Gate 全部拒绝生成，代码模型请求为零；build/runtime **未到达**，没有观测到编译或运行失败。

当前 DSH 三次终态依次为 `max_total_model_calls`、`execution_failure`、`execution_failure`；native 为 `completeness_budget_exhausted`、`max_total_model_calls`、`completeness_budget_exhausted`。hard gap 是必需证明节点的缺失/矛盾，数量变化不是等量独立缺陷，也不能单凭较少缺口认定能力更强。

所有八条已开始轨迹合计 146 model、299 tool、145 个已保存 provider 响应、1 次 timeout，已知 **5,453,210 tokens**。timeout 用量及中断时未完整出版的调用未知，整批成本是下界。六个完成 parse 的 provider events 为 128 个成功响应、1 个失败请求、22 个 execution_error、11 次 extra_terminal_repair、6 次 protocol_recovery、3 次 history_normalization；这些事件可以描述同一次请求的不同阶段，不能相加作为额外付费请求。

Slice 六次都保持 ParseWithLengthOpts 为唯一 CORE、SUPPORT 为空并交付 FT，但完整角色、EXCLUDE 与 frontier 仍有方差。去随机 ID/证据噪音后，六次 Slice partition 有三种、role projection 五种、FT partition 三种。frontier 保留问题文本，等义改写也可能造成不同签名。见 [可重算 Slice/FT 投影](../artifacts/cjson_agent_retest_20261008/paused_analysis/slice_ft_stability.json)。这证明入口 CORE 和有效终态一致，不能证明全部 Slice 语义稳定；DSH 仅作用 Context，上游方差不能归因于 DSH。

## 静态分析 gap 的具体局限

### 1. 识别函数不等于证明函数效果

`cJSON_Delete` 的完整函数体在调查中已签发。DSH r01 还真实执行了 `find_cleanup_candidates`；查询返回 signature hints，`structural_hint_only=true`、88 个匹配、结果被截断，最终 signed cleanup 候选仍为空。框架获得了证据 ID，却没有得到可提交的释放 effect。

因此该缺口不能统一解释为“agent 没读到源码”。需要区分：函数存在、源码已读取、效果被静态证明、效果与确切资源主体绑定、被正确提交。这几个阶段目前并未全部打通。

### 2. 间接 allocator/free hook 与全局状态缺乏完整效果摘要

[support_effects.releases](../harness_generation/semantic_slicing/support_effects.py#L12) 只处理 identifier 形式的直接调用、精确参数与最多两层直接 callee；成员调用被跳过。[proof_grounding](../harness_generation/harness_context/proof_grounding.py) 能处理部分 callback 身份和直接调用，但未知调用或无法确定的路径会标为 uncertain，不自动获得正向释放证明。

cJSON 使用 `global_hooks.deallocate(item)`、`hooks->allocate(...)`，默认 hook 初始化又可被 `cJSON_InitHooks` 修改。源码显示的释放意图不能直接转成“本调用必定释放同一个对象”的机器证明。需要联结全局初始化、可变 hook 的目标集合、allocator 配对及实际调用状态；当前签名/局部 body 分析不足以完成此联结。上述源码形态与 signed 候选为空相符，属于原因分析，尚未通过修复实验验证。

### 3. 循环、递归树和条件所有权只覆盖有限结构

`proof_grounding.analyze` 的调用深度上限为两层、路径展开有界；专用 owned traversal 规则要求特定循环/分支结构。cJSON_Delete 的 sibling while、child 递归及 `cJSON_IsReference`、`cJSON_StringIsConst` 条件组合不能仅依赖函数名或一次 `free` 出现来证明完整对象清理。需要同时描述 incoming root、借用成员、owned descendants、别名及不同成功/失败路径。

这是一类保守证明规则覆盖不足：拒绝可避免接受错误 cleanup，但会造成真实可用接口无法闭合。增加模型推理无法自动扩展静态规则支持的程序结构。

### 4. 构建宏与 callback ABI 的恢复不足

当前 parser 能恢复 115 个函数记录；历史只读编译审计表明 Linux 实际定义均包含，但另有未求值 Windows 分支 overapproximation。原始声明中的 `CJSON_CDECL` 产生 parser ERROR；[callback_declarations](../harness_generation/harness_context/callbacks.py#L65) 遇到有错误的 struct 声明直接跳过，历史 cJSON hook callback 声明签发为零。

因此宏 warning 不能一概视作无害。需要依据构建配置恢复 calling convention、typedef/field ABI 和条件编译身份，同时保留原始源码 provenance；“函数 body 完整”并不保证 callback 类型信息完整。本轮 parser/callback 底层并未因 DSH 接入而增强。

### 5. 返回值、out storage 和 pointee 的身份/生命周期表达仍易冲突

Parse 返回 owned cJSON 树；`return_parse_end` 则是 caller 提供的指针 cell，成功/失败时可写入借用输入 buffer 的不同位置。cell、pointee、输入 owner 和函数返回对象需要独立身份，并保留分支 origin/生命周期关系。

本轮出现 `resource_identity_multiple_origins`、`construction_contract_conflict`、`owned_return_contract_mismatch` 等。它们可能来自分析不能表达合法的分支来源，也可能来自模型提交互相矛盾的构造/ownership；必须检查拒因对应的具体事实，不能把全部 identity 拒绝直接归为静态 bug。native r01 收到明确修改字段反馈后，仍提交 `construction=constant, constant=null`，事务判为 no_progress，属于 agent 纠错失败的直接例子。

### 6. 信息发现和签发都受范围/预算约束

Context discovery 上限 16、深度两层、最多 24 model / 64 tool，修订与准备额度另受约束。DSH r01 和 native r02/r03 均出现 discovery16、大量 optional deferrals；有的查询只返回线索，无法签发被预算或范围阻挡的 helper。

这同时涉及静态工具能力和 agent 查询策略。重复扩大相同类型的查询会耗尽预算，继续读源码也不一定增加可用证明。缺口反馈应明确区分未检索、范围阻挡、预算阻挡、分析不支持和提案矛盾，让后续调度选择有产出的调查。

## DSH 相对 baseline 的实际提升与边界

本项目接入的是官方 DSH 的**受限 Context 调查循环**。provider、源码工具、证明签发、预算、外层事务和 Gate 都继续由 Python 原链负责；shell、文件写入、直接 provider、自动 compaction 和子 agent 未开放。模型也没有更换：历史与当前响应均报告 `deepseek-v4-flash-ga-260731`。因此它不是完整官方 agent 配置的能力评估，也没有给静态层增加新的证明种类。

可确认的执行层能力：三个完成 parse 共有 **23 个实际 DSH 会话，23 个 finish 都是 completed**，378 个诊断事件与 35 次 Context 模型桥接调用对齐；没有观测到 carrier/adapter 崩溃。回滚保留成本和已签发证据；恢复反馈确实能推进后续显式提交，SDK 事件没有产生隐藏 provider 计费。DSH r01 的 cleanup 查询相比某些历史“提出查询但未执行”多推进一步，但还不足以证明重复能力提升。native baseline 本身也有有界恢复/事务能力，不能把它描述为所有错误都直接退出。

尚未提升的任务能力：Context/native/DSH 均 0/3，无可执行 Plan 或 harness。DSH r01 的两次 malformed terminal 参数 SHA 完全相同，provider finish_reason 为 tool_calls，反馈后模型仍未修复；其他组重复 signed-alternative schema 错误。错误在 Python 权威 provider 历史中已存在，不能归因于 SDK 参数投影。schema 反馈有时只说“一种 signed subject/candidate alternative”，没有给具体字段与可接受候选差异；这限制模型纠错。

新增容量边界：DSH r02 在畸形 JSON 反馈后触发 `dsh_prompt_limit`，下一 provider 请求前本地撤销候选，实际 SDK 仍正常 completed。冻结上限为 400,000 prompt 字符，超限确切值未持久化；不能声称具体超出多少。调查 metadata 中已出现十万字符量级 proof agenda、重复 obligation/closure feedback，权威 history 曾有 235,144 字符 assistant 内容。容量停止保护了边界，却提前终止调查，较少 calls/tokens 不能解释为效率提升。

当前 native/DSH 共享生产 fingerprint、provider 和有效预算，但每次独立执行上游 Slice，因此进入 Context 的 frontier 不完全相同。历史 fingerprint 11c9ce… 与当前版本又有多项执行/恢复变化；每组仅三个已知目标重复、seed 未固定、provider alias 不锁定实际权重。这些结果可支持“本轮未观察到成功率提升”，不能证明 DSH 在任何任务上都无收益，也不能给出纯后端因果效果。

## 后续优先级（本轮未实施）

1. 补齐构建宏/ABI 与全局 hook points-to，签发确切 allocator/free effect，并保留分支、调用状态和主体证明。
2. 为 sibling/child cleanup 和 borrowed out-pointee 建立可重放、有限的条件效果摘要，避免混淆 cell 与 pointee。
3. 将 schema 拒因变为字段级差异和确切 signed alternatives；校验修改是否实际生效，对相同错误提交返回 no_progress。
4. 对重复 proof/feedback 使用引用和增量投影，既保留 Python 完整审计历史，又减少每次 provider 请求的重复内容；对字符停止持久化实际大小与阈值。
5. 当已有证据确实不足时，通过显式、预算内的回到调查调度重新取证；不把 terminal-only 纠错误当作具有新调查能力。

优先解决证明能力和反馈可执行性，再评估扩大 DSH 自主能力。仅换调度器或提高预算，无法绕过 signed proof 缺口。本轮保留所有失败、中断和成本，不继续测试或修改这些生产规则。
