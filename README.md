# HG v0.3

HG 是从原 `harness_generation` 开发工作区抽取的 C 项目 libFuzzer harness 生成框架，输出 harness 支持 C/C++。此工作区只保留当前新链及其依赖；代码模型消费已冻结的 HarnessPlan，静态分析、源码证据、契约修订和生成门禁由框架维护。

```text
源码解析 → Candidate → Candidate Validation → Semantic Slice → Minimal FT
  → Harness Context / API Closure → Semantic Obligation Graph → Closure Gate
  → HarnessPlan → C/C++ → build → runtime
```

**当前测试保持暂停，本次只整理工作区和分支。** 抽取不是能力修复，也没有在 HG 中重新执行 pytest、真实模型、Gate、build 或 runtime。`v0.3` 表示新链独立工作区的版本，不表示稳定性已经通过。

## 已知验证状态

2026-10-08 原工作区的 cJSON 复测中，native、DSH 各完成 3 次 parse：两组 Slice 均为 3/3，Context 均为 0/3，Plan、build/runtime 均未到达。整批保留 6 次完成、2 次中断、2 次未启动；目前没有证据表明接入 DSH 提高端到端稳定性。详见 [cJSON 缺口与后端对照](docs/CJSON_AGENT_BACKEND_GAP_ANALYSIS.md)。

报告中的 307 项离线回归、3 项 SDK fixture smoke、历史 JSON parser 成功及其他实验成绩，均属于原工作区当时的冻结版本。旧 fingerprint 不代表此次抽取的 HG 源码，也不能作为迁移后的通过证明。原始运行产物没有随本次整理迁移。

## 安装与模型配置

需要 Python 3.10 或更新版本；执行构建和 sanitizer runtime 时还需可用的 Clang/Clang++ 与目标项目构建依赖。以下命令供之后使用，本次整理未执行安装或运行：

```bash
python -m venv .venv
.venv/bin/python -m pip install -e .
```

按需选择官方 DeepSeek Harness Context 后端时，安装固定可选依赖：

```bash
.venv/bin/python -m pip install -e '.[dsh]'
```

本项目固定 `deepseek-harness-sdk==0.1.5rc1` 和 `deepseek-harness-runtime-bin==0.1.5rc1`。native 无需这两个依赖。DSH 的桥接合约和边界见 [接入说明](docs/DEEPSEEK_HARNESS_INTEGRATION.md)。

复制仓库的空配置模板为本地 `.env`，自行填入 provider 配置。凭据文件受 Git 忽略，不能提交实际凭据：

```dotenv
LLM_API_KEY=
LLM_BASE_URL=
LLM_MODEL=
LLM_THINKING=disabled
DEEPSEEK_API_KEY=
```

兼容 provider 使用 `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL`；官方 DeepSeek provider 使用 `DEEPSEEK_API_KEY`。配置通过 `--env-file` 作为数据读取。

## CLI 七步

以下展示一次新的执行目录如何贯穿新链。先填写目标源码目录、构建配方和候选 identity；第 3、4、6、7 步可能发起真实模型请求。测试恢复应另行登记版本、预算与重复次数，这些示例没有在本次整理中执行。

```bash
HG_PROJECT=/absolute/path/to/project
HG_ARTIFACTS=artifacts/my_project_fresh
HG_CANDIDATE='<目录中的精确 function_id 或 candidate_id>'
HG_BUILD_CONFIG=/absolute/path/to/target_build.json

# 1. 解析源码，准备 parser-only 静态产物
.venv/bin/python -m harness_generation parse \
  --project "$HG_PROJECT" --output "$HG_ARTIFACTS"

# 2. 保存候选目录，保留未选择候选
.venv/bin/python -m harness_generation candidates \
  --artifacts "$HG_ARTIFACTS" --policy broad

# 从 candidate_discovery/candidates.json 确定 HG_CANDIDATE 后执行后续步骤。
# 3. 用受限源码工具验证入口语义
.venv/bin/python -m harness_generation candidate-validate \
  --artifacts "$HG_ARTIFACTS" --candidate "$HG_CANDIDATE" \
  --provider openai-compatible --env-file .env

# 4. 划分 CORE / SUPPORT / EXCLUDE / UNRESOLVED
.venv/bin/python -m harness_generation semantic-slice \
  --artifacts "$HG_ARTIFACTS" --candidate "$HG_CANDIDATE" \
  --provider openai-compatible --env-file .env

# 5. 确定性投影 Minimal FT
.venv/bin/python -m harness_generation minimal-ft \
  --artifacts "$HG_ARTIFACTS" --candidate "$HG_CANDIDATE"

# 6. 调查 Context，执行修订事务并重新计算 Closure Gate
.venv/bin/python -m harness_generation harness-context \
  --artifacts "$HG_ARTIFACTS" \
  --provider openai-compatible --env-file .env --agent-backend native

# 7. 重新核验冻结输入，构建 Plan，翻译、构建并运行 harness
.venv/bin/python -m harness_generation context-generate \
  --artifacts "$HG_ARTIFACTS" --provider openai-compatible --env-file .env \
  --target-build "$HG_BUILD_CONFIG" --build --runtime
```

`context-generate` 只有在 Context 闭合并冻结、输入 identity 与证据重新核验通过后才会调用代码模型。必需义务缺失时保存拒因，不因 agent 写 `resolved` 而生成。框架已有有界补证据、反馈和候选回滚；分析不支持、修改无进展或预算耗尽仍可能阻止生成。

第 6 步可将 `--agent-backend native` 改为 `--agent-backend deepseek-harness`。DSH 只替换一次 Context 调查的执行循环，使用相同源码工具、Python 模型账本、预算、事务与 Gate；它不自动扩展静态证明能力，也没有开放 shell、文件写入或子 agent。Candidate、Slice 和代码翻译的执行方式不随此选项改变。

## 工作区与阅读入口

- [抽取范围与历史证据边界](docs/WORKSPACE_EXTRACTION.md)：原工作区、Git worktree、排除的旧执行链及迁移限制。
- [逐文件抽取清单](docs/WORKSPACE_EXTRACTION_MANIFEST.json)：来源摘要、HG 源码身份与静态整理检查。
- [新链架构导航](docs/FRAMEWORK_ARCHITECTURE_AND_LIMITATIONS.md)：各阶段职责与当前缺口。
- [执行机制与数据流](docs/FRAMEWORK_EXECUTION_AND_DATA_FLOW.md)：源码、证据、Context、Gate 与 Plan 的详细流动。
- [Canonical Construction](docs/CANONICAL_CONSTRUCTION_REPORT.md)、[Agent 补证据](docs/AGENT_PROOF_INVESTIGATION_REPORT.md)、[Semantic Closure](docs/SEMANTIC_CLOSURE_FRAMEWORK_REPORT.md)：当前机制的演进记录。
- [Context 修订事务](docs/CONTEXT_REPAIR_TRANSACTION_REPORT.md)、[Agent 能力与提示改进](docs/AGENT_CAPABILITY_AND_PROMPT_IMPROVEMENT_REPORT.md)：反馈、回滚、调查和预算边界。

`harness_generation/` 保留新链，`sfg_builder/` 保留共享解析与结构依赖；目录名称不意味着仍提供旧 SFG workflow。`scripts/`、`tests/` 和 `benchmarks/` 包含选定的新链评测工具、回归用例及样例。部分历史脚本仍要求外部历史输入，不能直接视为从空目录可复现实验。旧 `scripts/blind_eval/freeze.py` 的冻结范围未包含 DSH runtime 资产，不能用于完整 DSH 身份登记；保留此历史工具不代表完成了新的 DSH 盲测支持。

历史报告中的 `../artifacts/` 链接指向原运行目录；HG 未复制这些产物，需要回到 `/home/luchitong/work/harness_generation/artifacts/` 查阅。原脏工作区及未提交改动保持原状。
