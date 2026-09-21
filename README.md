# Harness Generation

为 C 项目生成 libFuzzer harness 的实验框架。v0.1 提供两条可运行的路径：项目级的
**SFG → Function Triplet (FT) → Stage 1–4** 流水线（可接入 ProtocolIR），以及单文件的
**候选生成 → 执行反馈** 实验路径。两条路径共用部分构建、运行和评测组件，产物与入口分别管理。

## 快速开始

需要 Python 3.10+。建议先创建虚拟环境，再安装本地项目：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

先在不调用模型的情况下构建 SFG 并提取 FT。示例项目在 `tests/fixtures/simple_project`，
输出写入被 Git 忽略的 `runs/`：

```bash
python -m sfg_builder \
  --project tests/fixtures/simple_project \
  --output runs/simple
python -m harness_generation triplets --artifacts runs/simple
```

`runs/simple/triplets.json` 给出 FT ID；当前示例项目的 ID 是
`ft_parser_from_memory_a5265df23ba0`。分阶段生成需要模型配置；
`.env.example` 列出变量，但 CLI **不会自动加载 `.env`**。在当前 shell 导出
`LLM_BASE_URL`、`LLM_API_KEY`、`LLM_MODEL` 后运行：

```bash
python -m harness_generation run \
  --artifacts runs/simple \
  --ft ft_parser_from_memory_a5265df23ba0 \
  --real-llm --build
```

`--build` 会执行中间校验、编译、链接和运行时 smoke；加上 `--smoke-fuzz`
可做限时 fuzz。实际构建还需要可用的 Clang/libFuzzer 工具链。若只想检查解析与
FT 抽取，前两条命令即可。完整选项、离线 mock/recorded response 和阶段产物见
[流水线使用说明](docs/HARNESS_PIPELINE.md)。

协议格式挖掘是独立入口；静态 A/B 块无需 API key，C 块需显式开启模型推断：

```bash
python -m harness_generation protocol-mine \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --output runs/mini_parser
```

## 命令与职责

| 入口 | 职责 | 主要产物 |
| --- | --- | --- |
| `sfg-builder` | 解析项目并构建 SFG | `functions.json`、`annotations.json`、`flows.json`、`sfg.json` |
| `harness-generation triplets` | 从 SFG 提取 FT | `triplets.json` |
| `harness-generation protocol-mine` | 静态抽取协议事实，可选推断惯用法 | `protocol_candidates.json`、`protocol_conventions.json`、`protocol_ir.json` |
| `harness-generation generate` / `run` | 分阶段生成与校验单个 FT | `generation/<ft_id>/`、`harnesses/<ft_id>.c` |
| `harness-generation generate-all` | 对目录内所有 FT 执行生成 | 各 FT 的独立产物 |
| `harness-generation --source ...` | 单文件候选实验 | 独立的候选目录、执行与反馈记录 |
| `harness-generation feedback-loop` | 在候选实验上执行有界反馈循环 | 轮次记录与候选评估 |
| `harness-generation measure-target` / `coverage-arms` / `generation-variance` | 目标覆盖与对照测量 | 覆盖记录、报告和生成间方差 |

`generate` 和 `run` 消费已有的 FT 目录；它们不会自动运行 SFG 或协议挖掘。
`protocol_ir.json` 是可选输入，若存在则在 Stage 4 进入 prompt 前做项目函数对账。
单文件候选实验使用 `--source`、`--function`、`--output`，其协议规范入口与分阶段
流水线不同；详细行为见[候选与反馈实验](docs/CANDIDATE_WORKFLOW.md)。

## 仓库结构

```text
harness_generation/   FT、协议模型、Stage 1–4、校验、构建、评测与 CLI
sfg_builder/          项目解析、语义标注与 SFG 构建
benchmarks/           可复现目标及参考 harness
tests/                单元、集成测试与固定录制 fixture
docs/                 使用说明、设计依据与实验报告
artifacts/            两份受测试/文档引用的录制示例；其他运行输出不跟踪
runs/                 本地运行输出（Git 忽略）
```

模块关系和数据边界见[架构说明](docs/ARCHITECTURE.md)，文档分类见[文档索引](docs/README.md)。
`artifacts/` 的保留规则见[目录说明](artifacts/README.md)。

## 验证与版本

```bash
python -m pip install -e '.[test]'
python -m pytest -q
```

版本由 `pyproject.toml` 管理，当前为 **0.1.0**；本版范围和已知限制见
[CHANGELOG](CHANGELOG.md)。覆盖率报告来自固定测量，不把单次运行或重复 seed
解释为独立生成的效果。
