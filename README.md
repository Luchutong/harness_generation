# HG v0.5

HG 为 C 项目生成 C/C++ libFuzzer harness。LLM 调查目标 API 并提交类型化调用策略，框架检查当前源码、Clang ABI、API 范围和已知调用错误，再确定性生成代码，执行真实编译及固定输入 sanitizer smoke。

```text
源码解析与 Clang 构建索引
  → Lightweight API Context（或已有合法 Minimal FT）
  → 一次有预算的 Strategy Planning
  → Execution Preflight → ExecutablePlan
  → 确定性 C/C++ → 编译与固定输入运行 → 保存结果并结束
```

当前公开命令只有 `parse` 和 `harness-run`。`harness-run` 仅提供 `generate` 模式，兼容已有 `--ft` 输入。执行观察不会触发第二次规划、自动代码修复或再次生成。

## 安装

需要 Python 3.10+、Clang、`ar` 和可用的 ASan/UBSan 工具链。源码索引当前接受 C 翻译单元，harness 可通过 `--language c++` 输出 C++。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m harness_generation --help
```

规划使用原生 OpenAI 兼容客户端。可以复制 `.env.example` 为 `.env` 并配置 `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL`，运行时指定 `--provider openai-compatible --env-file .env`。凭据及本地环境不进入源码库。

## 使用

先准备项目真实的 `compile_commands.json`，在新目录保存索引：

```bash
.venv/bin/python -m harness_generation parse \
  --project <project> --output <new-index-directory> \
  --compile-commands <project>/compile_commands.json
```

从生成的 `functions.json` 选择精确目标函数 ID。构建配置 `target_build.json` 描述同一个项目，例如：

```json
{
  "schema_version": 1,
  "project_root": "./my-project",
  "source_files": ["src/parser.c"],
  "header_files": ["include/parser.h"],
  "include_paths": ["include"],
  "compiler": "clang",
  "compiler_flags": ["-std=c11"],
  "archiver": "ar",
  "timeout": 30
}
```

`project_root` 相对于命令的工作目录解析，源码、头文件及 include 路径相对于项目根目录解析。构建文件须列出目标所需翻译单元及真实编译选项。

```bash
.venv/bin/python -m harness_generation harness-run \
  --artifacts <index-directory> --target <exact-function-id> \
  --target-build <target_build.json> --headers <public_header.h> \
  --provider openai-compatible --env-file .env
```

`--support-api <exact-function-id>` 可重复指定相关构造或清理 API；框架仍会用当前 Clang 索引验证调用范围。`--target` 和 `--ft` 互斥。已有合法 FT/Strategy 可以沿用以下输入形式；本仓库不提供旧 FT 的生产流水线或历史数据：

```bash
.venv/bin/python -m harness_generation harness-run \
  --artifacts <index-and-ft-directory> --ft <ft-id> \
  --strategy-run <saved-strategy-run> \
  --target-build <target_build.json> --headers <public_header.h>
```

generate 自动编译和运行。完成后可用原输入和 `--resume-run <run-id>` 认证已保存结果；有未确认外部动作时保存诊断并停止。恢复已完成结果不会重新请求规划模型、编译 harness 或运行目标。

## 结果含义

Plan、代码、编译、runtime 和有效性分别记录。预检可信的明确违反会拒绝；复杂 ownership、循环和递归等未知命题保存在 `unknown_contracts`。

生成结果属于候选：`execution_allowed=true` 表示允许执行，`semantic_verified=false`、`generation_allowed=false`。编译和固定输入运行通过不能建立完整语义证明、目标漏洞结论或 fuzz 有效性。动态有效性缺少当前可信观察时为 unknown。

## 测试与文档

```bash
.venv/bin/python -m pytest
```

保留的测试代码使用运行时临时 fixture，不依赖旧工作区、历史 benchmark 或 provider 请求。2026-10-12 清理删除了历史测试数据、产物、样例项目和旧流程；2026-10-11 的测试成绩只作为历史摘要，不绑定本次清理后的代码。

- [v0.5 设计与运行边界](docs/V05_GENERATION_FIRST_DESIGN.md)
- [2026-10-11 历史验收摘要及证据删除说明](docs/V05_GENERATION_FIRST_ACCEPTANCE_20261011.md)
- [原 v0.5 重构要求](docs/fix2_plan.md)

当前清理与验证记录见 [2026-10-12 清理报告](docs/V05_WORKSPACE_CLEANUP_20261012.md)。
