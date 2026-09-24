# SynapseFlow 论文最小路径核对

依据：[SynapseFlow, arXiv:2607.07007v1](https://arxiv.org/html/2607.07007v1)，重点核对 §3.2、§3.3、算法 1、算法 2 和 §3.4。本页只判断方法路径是否保留论文的必要步骤；仓库中的评分、HarnessPlan、protocol IR、usage mining 和长期 fuzz 评测属于额外研究实现。

## 最小路径

`scripts/run_minimal_demo.sh` 依次执行：C 项目解析 → **真实 LLM** 语义标注 → SFG → `triplets --paper-minimal` → 选取一个 FT → Stage 1–4 → 中间检查、编译、链接、empty/minimal input 运行检查和 fuzz smoke。脚本要求 `LLM_BASE_URL`、`LLM_API_KEY`、`LLM_MODEL`，Phase 1 与生成阶段使用同一模型和 API 地址。Phase 1 的标注请求若没有产生成功的决策，脚本会停止，不把 Mock 或失败后的保守降级结果作为真实论文路径的成功运行。脚本还限定所选 FT 只有一至两个局部 snippet，使 Stage 3 最多需要一次相邻合并。

`--paper-minimal` 每个唯一 ISF 仅提取一个 FT，不按 usage pattern 拆分。同一函数可以同时有 ISF、PRF、HPF 标签；FT 中仍只有一个外部输入入口。普通 `triplets` 命令保留按 usage pattern 产生 variant 的扩展行为。

Phase 1 也提供 `sfg_builder --paper-minimal`：它只执行论文要求的 LLM 字节流投票、结构函数角色和模糊指针方向判断，跳过仓库扩展的 usage pattern LLM 复审。已由 AST 读写或 `const` 确定的结构指针方向直接使用静态证据。完全删除 LLM 语义判断会改变论文 §3.2.1–3.2.2 的方法。

当前论文模式还做一个保守的静态可表示性筛选：签名没有结构输入或输出的函数不会进入语义投票，因为当前 SFG 无法为它们构建结构流。论文明确要求 ISF 把原始数据引入内部结构，但没有规定必须以此精确语法规则筛选；这里可能漏掉通过全局状态隐式传递结构的函数。模型将文件名/路径名判为连续字节时，类别否决优先于布尔票；URI/URL 参数名也保守视为语义字符串。

大型项目的 CLI 安全上限：`sfg_builder --semantic-analyzer llm` 默认至多 300 次实际语义请求；`triplets` 默认跳过超过 20 个函数的 FT，并把原因写入 `triplet_exclusions.json`；`triplets rank` 默认最多选 20 个 FT、300 次基线生成调用，每个 FT 至多 20 个函数和 20 个 Stage 2 单元；`generate`/`generate-all`/`run` 在调用模型前重新核对相同规模，并以 300 次实际请求作为整个运行的硬上限。读取既有 `triplets.json` 的命令默认拒绝超过 128 MiB 的目录，避免旧的大目录先耗尽内存。各参数可显式提高。过大 FT 被排除，而不是从原 FT 中截断函数，因此保留的 FT 仍按原有图算法生成。这些上限是成本控制，不是论文设定的常数。

旧产物需要重新执行 Phase 1 和 FT 抽取才会体现声明去重、mock 判断和 FT 规模上限。真实生成默认要求 `annotations.json` 证明 Phase 1 使用 LLM 且语义决策成功；旧产物若无法证明来源，可用 `--allow-unverified-semantic-artifacts` 显式承担该限制。

## 方法对照

| 论文必要步骤 | 仓库最小路径 | 判断 |
| --- | --- | --- |
| §3.2.1：tree-sitter 预筛选，LLM 判断字节流和函数角色，三种提示投票识别 ISF | `sfg_builder` 使用 tree-sitter、LLM semantic analyzer 和三种 stream prompt 投票 | 对应；脚本已强制使用真实语义后端 |
| §3.2.2：以结构类型为节点、函数数据流为有向边，保留 `(null)` | `sfg_builder` 产出 `flows.json` 与 `sfg.json` | 对应；复杂多输入/输出边是标记为 inferred 的工程推断 |
| 算法 1：排除其他 ISF，取输入祖先与输出后代，每个 ISF 一个 FT | `triplets --paper-minimal` 关闭 usage variants；图提取器带有所有权边界保护 | 保留一个 ISF 一个 FT 的核心约束；边界保护见下方 |
| §3.3.1：文档 → 局部结构 snippet → 粗代码 → fuzz harness | `Stage1Generator`、`Stage2Generator`、`Stage3Assembler`、`Stage4Generator` | 四阶段存在；Stage 3 的细节见下方差异 |
| §3.4：中间输出检查，最终编译并以空输入运行 | `PipelineStageValidator`、build/runtime validator | 对应；额外的链接、最小输入和 fuzz smoke 属于工程验证 |
| §3.3.2：失败后逐层回退到更早 checkpoint | `PipelineOrchestrator` / `StagedRollbackStrategy` | 对应逐层回退机制；首次回退的论文表述有歧义 |

## 尚不能声称逐项等同之处

1. **Stage 3 合并粒度**：论文 §3.3.1 说沿 SFG 顺序迭代合并相邻 snippet。当前 `Stage3Assembler.run()` 排序后把所有 snippet 放进一次 LLM 请求，生成一个粗代码。对于一个 snippet 无需合并，两个 snippet 只需合并一次，因此最小 demo 限定在这个范围；三个及以上 snippet 的一般路径还不是论文描述的逐次合并。
2. **首次回退目标**：论文 §3.3.2 正文说最终代码失败时返回 Stage 3，算法 2 却把初始 `cycState` 写成 Stage 4。当前策略先保留 Stage 3 checkpoint 并重新执行 Stage 4；这与算法 2 的初始状态一致，也符合正文中“保留 Stage 3 输出”的解释。论文没有给出完全一致的唯一实现。
3. **FT 边界补全与裁剪**：仓库可依据所有权和源码用法补充创建/释放函数；对已知拥有返回对象的 `(null) → Resource` 入口，还会限制普通图可达性，避免把其他资源消费者并入同一个 FT。这是为 C API 生命周期做的工程扩展，不能称为论文算法 1 的逐行实现。`--paper-minimal` 关闭 usage pattern 的 FT 拆分，但仍保留这些所有权处理。对 opaque handle 等目标，需人工检查结果是否仍是论文定义的最小自洽函数组。
4. **可复现性**：最小 demo 只证明一个小项目的端到端执行。它不复现论文 25 个目标、24 小时 × 5 次试验、覆盖率或漏洞发现结论；真实模型输出也会随服务版本变化。

因此，当前脚本可作为**论文核心工作流的最小演示**；在完成一般 FT 的 Stage 3 逐次合并并对更多目标核验 FT 之前，不应称为完整算法及实验结果的复现。

2026-09-24 的真实 API 运行记录位于 `/tmp/harness_paper_minimal_20260924_verified/`：24 个 Phase 1 语义决策均成功，得到 `json_parse` 与 `json_parse_ex` 两个 FT；选择含两个局部 snippet 的 `json_parse`。Stage 1–4、Intermediate、Compiler、Linker、Runtime 与 fuzz smoke 全部通过。第一次 Stage 4 违反资源清理顺序，触发一次回退，第二次通过。这是单目标执行证据，不是论文覆盖率或漏洞检测结果的复现。

大型项目的无网络回归：旧 `artifacts/libxml2_20260923` 有 4,030 个候选、1,450 个 mock ISF、1.2 GiB 的 FT 目录，原选择清单估计 361,922 次基线生成调用。用当前 `/home/luchitong/work/libxml2` 源码和修复后的代码重跑，得到 3,598 个函数记录、2,996 个有定义的候选、349 个 mock ISF；按 20 函数上限保留 256 个 FT、记录 93 个排除，目录为 10.38 MiB；默认排序选择 20 个 FT、估计 300 次基线调用。两次扫描的源码与解析范围未证明完全相同，不能把数量差直接解释为单项修复的效果；mock 数量也不能替代真实 LLM 语义结果。

2026-09-24 的 libxml2 真实 Phase 1 小范围验证只扫描 `xmlIO.c` 与 `include/libxml/*.h`，并非全项目。初次运行在论文模式下发出 161 次真实语义请求，174 条语义决策全部成功；审计发现模型把文件名和路径名标作连续字节，旧计票因此得到 33 个 ISF。修正类别否决、URI/URL 语义名过滤及无结构流预筛后，严格复用原响应、零新增网络请求，最终得到 10 个 ISF、10 个 FT（均未超过 20 函数上限，均有结构节点）。同范围按新预筛重新运行预计需 92 次论文必需的语义请求。真实原始产物在 `artifacts/libxml2_xmlio_real_phase1_paper_20260924_0930`，最终重放产物在 `artifacts/libxml2_xmlio_real_replayed_final_20260924_1000`；未执行任何 FT 的 Stage 1–4 生成。
