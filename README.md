# 函数源码 → libFuzzer Harness

使用 DeepSeek 生成独立 C 函数的 libFuzzer Harness，并通过真实 Clang 编译和链接检查。第一版不执行生成的二进制，不进行自动修复。

## 环境与配置

- Python 3.10+；运行和测试仅使用标准库，无第三方运行依赖。
- Clang 及 libFuzzer、AddressSanitizer、UndefinedBehaviorSanitizer 运行库。
- DeepSeek API 密钥及可用余额。

在项目目录直接运行即可，无须安装包：

```bash
cd ~/work/harness_generation
read -rsp "请输入 DeepSeek API Key: " DEEPSEEK_API_KEY
echo
export DEEPSEEK_API_KEY
python3 -c 'import os; print("已配置" if os.getenv("DEEPSEEK_API_KEY") else "未配置")'
```

密钥只对当前终端和其子进程生效。程序仅从环境变量读取，不自动加载 `.env`；`.env.example` 仅用于说明变量名。不要将密钥写入源码或提交到版本库。

可选安装命令为 `python3 -m pip install -e .`，安装后也可使用 `harness-generation` 入口。

## 生成一次 Harness

```bash
python3 -m harness_generation \
  --source examples/parse_u16.c \
  --function parse_u16 \
  --output runs/parse_u16
```

输入必须是自包含的 UTF-8 `.c` 文件，包含所需标准库头文件、类型和辅助函数；不包含 `main`，不依赖其他本地文件或外部库。明确指定目标函数名，支持 `static` 函数。第一版不使用 AST 验证输入条件或自动提取函数。

默认模型为 `deepseek-v4-flash`，可通过 `--model deepseek-v4-pro` 更换。请求发送到官方 `https://api.deepseek.com/chat/completions`，使用非流式、关闭思考模式、temperature=0.2、max_tokens=4096。请求超时参数为 120 秒，无自动重试或重定向；底层 HTTP 超时是 socket 等待超时，不是整个请求的硬性总时限。接口和模型参数见 [DeepSeek 官方文档](https://api-docs.deepseek.com/api/create-chat-completion/)。完整输入源码会发送给 DeepSeek。

每次使用**尚不存在的输出目录**，包括重试失败实验时，以免覆盖记录。无论编译是否成功，每次命令最多调用一次 API，可能产生费用。

## 复查与改进已有 Harness

`--harness` 使用本地代码，跳过 API 和密钥检查，执行同样的格式检查、审阅提示与编译。新产物写入独立目录，原实验不变：

```bash
python3 -m harness_generation \
  --source runs/parse_u16/target.c \
  --function parse_u16 \
  --harness runs/parse_u16/harness.c \
  --output runs/parse_u16_review
```

针对纯计算函数，如果调用结果未使用，`-O1` 可能删除关键计算。提示词 v2 要求将非 void 标量返回值和有效、已初始化的输出保存到类型匹配的局部 `volatile` 变量；仅写 `(void)result` 不能保护普通变量的计算。不要通过修改目标实现或给目标指针参数添加 `volatile` 来解决。

`examples/reference_harnesses/` 提供三个手写参考 Harness，可用于比较模型输出；它们不是模型生成结果。用下面命令验证修正后的示例：

```bash
python3 -m harness_generation \
  --source examples/parse_u16.c \
  --function parse_u16 \
  --harness examples/reference_harnesses/parse_u16.c \
  --output runs/parse_u16_reference
```

每次编译前保存 `review.json`，提示是否缺少直接目标调用或 `volatile`。检查忽略注释和字符串中的关键词，但只是词法启发式，可能误报或漏报（例如函数指针调用、无关 volatile、不可达调用）。始终标记为 `needs_review`；没有提示也不代表语义正确。审阅提示不改变编译成功的退出码。

## 实验产物

| 文件 | 内容 |
| --- | --- |
| `target.c` | 输入源码的原样副本 |
| `prompt.json` | 完整请求参数和提示词，不含密钥 |
| `response.txt` | API 响应正文，若意外回显密钥则脱敏 |
| `harness.c` | 提取后的 C Harness |
| `input_harness.txt` | 离线复查时的输入 Harness，即使验证失败也保留 |
| `review.json` | 自动审阅提示及人工检查清单 |
| `compile_command.json` | 编译参数列表，相对于实验目录执行 |
| `compile_stdout.txt` / `compile_stderr.txt` | 编译诊断 |
| `fuzz_target` | 成功编译的可执行文件，不自动运行 |
| `result.json` | 状态、失败阶段、模型、耗时、token 用量、提示词版本和源码/Harness SHA-256 |

尚未进行的阶段不会产生对应文件。缺少密钥时仍保存源码、提示词及失败结果；输入路径错误或输出目录已存在时，直接报告错误，不改变已有目录。

Harness 应包含一次 `#include "target.c"`，并定义 `int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)`。只编译 Harness 一个翻译单元：

```bash
clang -std=c11 -g -O1 -Wall -Wextra -Wpedantic -fsanitize=fuzzer,address,undefined harness.c -o fuzz_target
```

编译限时 30 秒，保存超时前的诊断。命令成功返回 0，生成或编译失败返回 1，参数错误返回 2。`result.json` 分别记录 `generation` 与 `compilation.status`，编译失败不会被误记成生成失败。原始响应会在解析之前保存，便于检查空输出、截断、格式错误及 HTTP 错误。

离线模式记录 `mode=offline`、`generation=skipped`，不记录模型或 token 消耗；不要将离线编译算入模型首次生成成功率。新结果使用 `schema_version=2`，原有状态字段保留，增加审阅与来源信息。JSON 文件通过临时文件替换写入；Ctrl+C 返回 130 并尽量保留中断阶段。编译器警告保留在诊断中，不统一视为错误。

代码检查仅包括输出格式、包含文件和入口等基本结构；不是语义验证。模型仍可能生成错误参数、无效调用或重复实现，需要人工审阅。编译成功不等于 Harness 正确，更不等于发现漏洞。

## 离线验证

```bash
python3 -m unittest discover -s tests -v
```

测试不联网、不使用真实密钥。覆盖代码提取、截断和异常响应、单次 API 请求、密钥脱敏、缺失密钥、已有目录保护、编译超时，以及使用固定 Harness 的真实 Clang 编译成功与失败。Clang 存在但运行库缺失时，编译测试会失败，便于发现环境问题。

另外覆盖三个参考 Harness 的离线编译、审阅提示、字符串与注释处理、中断记录，并检查 Clang `-O1` 生成的 LLVM IR，验证参考 `parse_u16` Harness 保留输入字节读取。此回归只针对该示例，不构成任意模型输出的优化保留证明。

## 三个示例的真实 API 实验

在已配置密钥的同一个终端中执行。以下命令仅用于复现三个示例，不额外实现批量评测功能：

```bash
experiment_dir="runs/$(date +%Y%m%d-%H%M%S)"
for target in parse_u16 classify_string mix_scalars; do
  python3 -m harness_generation \
    --source "examples/$target.c" \
    --function "$target" \
    --output "$experiment_dir/$target"
done
python3 - "$experiment_dir" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
passed = 0
for name in ("parse_u16", "classify_string", "mix_scalars"):
    path = root / name / "result.json"
    result = json.loads(path.read_text()) if path.exists() else {}
    status = result.get("compilation", {}).get("status", "missing")
    passed += status == "passed"
    print(f"{name}: {status}")
print(f"首次编译成功率: {passed}/3 = {passed / 3:.1%}")
PY
```

人工检查每份 `harness.c`：确实调用了指定函数，参数来自 fuzz 输入；`parse_u16` 的输出指针可写；`classify_string` 的缓冲区有 NUL 终止且被释放；`mix_scalars` 的标量读取不会越界或产生未对齐访问。检查是否有提前返回导致目标调用不可达。将检查结论写入各实验目录的 `review.md`，与编译结果分开记录。

首次成功率以三个示例各一次请求为分母；保留网络和 API 失败，不通过反复生成挑选成功结果。离线模拟结果不算真实 API 实验结果。当前范围不包括覆盖率统计、实际 fuzz、自动修复、项目构建依赖解析或 AST 提取。
