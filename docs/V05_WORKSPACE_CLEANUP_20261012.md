# v0.5 工作区清理与发布记录

日期：2026-10-12（Asia/Shanghai）。本次按用户要求，仅保留 `/home/luchitong/work/HG` 的 v0.5 生成优先链，删除指定七个旧工作区及历史测试数据。当前分支为 `v0.5-generation-first`，包版本为 `0.5.0`。

## 删除范围

以下七个目录已经实际删除，包括各自未提交文件、缓存、测试数据及嵌套工作区：

- `/home/luchitong/work/harness_generation_code_feedback_20261005H`
- `/home/luchitong/work/harness_generation_context_projection_20261005I`
- `/home/luchitong/work/harness_generation_stability_candidate_20261004`
- `/home/luchitong/work/harness_generation_stability_scheduler_20261005E`
- `/home/luchitong/work/harness_generation_stability_scope_20261005F`
- `/home/luchitong/work/harness_generation_stability_validation_20261005D`
- `/home/luchitong/work/harness_generation`

HG 内的 `artifacts/`、`benchmarks/`、`scripts/`、`.tools/`、`native/`、旧 `compile_commands.json` 链接、历史报告和旧测试模块也已删除。没有保存历史源码副本、原始模型响应、运行快照、语料、coverage、二进制或旧测试项目。

## 独立仓库与环境

HG 原来是依赖旧主目录 `.git/worktrees/HG` 的 linked worktree。删除主目录前，已将共用 Git 对象、配置及 HG 自身 HEAD/index/日志迁到 HG 的独立 `.git/`，验证当前 branch、HEAD 和项目变更完全一致。当前 `git worktree list` 仅显示 HG。

HG 的 `.venv` 已重新创建，并安装本目录的 editable `0.5.0` 包；不复用指向旧目录的安装映射。原模型配置迁到被 Git 忽略的本地 `.env`，不进入发布内容。

本次以正常新提交更新当前远端分支；Git 历史继续保留，本次文件删除不声称已经擦除历史提交。

## 保留的运行链

```text
parse：源码与真实 Clang 构建索引
  → 精确 target 的 Lightweight API Context，或已有合法 FT
  → 一次有预算的 Strategy Planning / 保存 Strategy 重验
  → Execution Preflight → ExecutablePlan
  → 确定性翻译 → 真实 build → sanitizer 固定输入运行
  → 保存独立质量轴、诊断与成本，结束
```

公开命令只剩 `parse` 和 `harness-run`，后者仅接受 `generate` 模式。旧 Candidate/Slice/Context/Strict/SVF CLI、恢复控制器和自由代码模型生成入口已删除。

为了彻底去掉旧执行链依赖，本次新增 `generation_base.py`、`execution_controller.py`、`executable_helpers.py`：分别承载单次规划/身份/账本、持久化动作与失败边界、候选 Plan 的共享翻译辅助逻辑。NativeGenerationServices 和 SingleGenerationController 不再继承旧恢复链；旧 services、controller、DraftPlan、正式 publication、DSH 和 SVF 独立模块已经移除。

保留的共享源码检查、类型/资源/回调工具及 FT 认证辅助模块仍由 v0.5 调用，因此按依赖保留。它们没有旧流程公开入口。已有 FT 仅作为兼容输入，仓库不再提供旧 FT 创建流水线。

执行前仍检查 source/build/scope、ABI、资源来源、已知契约违反及 Plan/代码一致性。未知复杂语义保留 unknown；`semantic_verified` 和正式 `generation_allowed` 为 false。完成动作恢复仍认证原始请求、策略、代码、编译/运行观察和成本，不重复 provider 或执行动作；未确认外部动作需要明确核对。

## 本次验证

| 检查 | 结果 | 实测边界 |
| --- | --- | --- |
| 剪裁后 v0.5 主回归 | **157/157，通过，33.41 s** | 含小型 C fixture 的真实 Clang、harness 编译/运行、预检反例、Plan 身份、Native 观测认证和完成恢复 |
| 新抽出 FT/Strategy 认证回归 | **12/12，通过，0.44 s** | Fake planner 保存与真实 Transcript 回放；精确策略/证据/scope；candidate 与已保存数据篡改、扩权及源漂移拒绝 |
| 公开命令 / 模式 | 通过 | 仅 parse / harness-run(generate)，旧命令和 verify/recover 拒绝 |
| 安装与依赖 | 通过 | 本地 editable 0.5.0；pip check 无冲突；console script 可执行 |
| 当前源码 AST、文档链接、diff 空白检查 | 通过 | 当前文件，不借用旧快照成绩 |

两组互不重叠，共 **169/169**。保留 **12 个测试模块及 1 个独立 fixture 模块**，它们在临时目录创建小样例；测试数据与运行产物在检查后清除。没有真实 provider 请求或真实 LLM fresh run。

新增认证测试中的 FT-shaped 输入是明确的组件夹具，不构成完整旧 FT loader 或旧流水线端到端验收。真实 json_parse / Expat 的历史产物已删除，本次未重新运行这些项目；历史 176/176 和此前 sanitizer 成绩不用于认证清理版。

首次主回归是 156/157，失败来自测试中遗留的已删除 helper 名称；修正为新的旧模块导入阻断 helper 后，完整主回归 157/157。它没有发现本次目标 runtime 崩溃。

## 当前源码身份

[源文件清单](V05_SOURCE_MANIFEST.json)包含 **126** 个生产/打包文件：125 个 Python 文件（包括 project_catalog.py），另加 pyproject.toml。测试、文档、凭据、环境和运行数据不在该 fingerprint inventory 内。

```text
f1116a7db91c9a5496274d1b31ae10fe2885405bb5889e28de73ac0be11dcae5
```

这是剪裁后的新身份，不能沿用 2026-10-11 的 203 文件 fingerprint。算法及逐文件 SHA-256 已登记，便于后续固定版本 fresh 验证。

运行说明见 [README](../README.md)，当前机制见 [v0.5 设计](V05_GENERATION_FIRST_DESIGN.md)。[旧验收摘要](V05_GENERATION_FIRST_ACCEPTANCE_20261011.md)明确记录历史原始证据已经删除。
