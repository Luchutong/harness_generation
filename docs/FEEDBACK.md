# Feedback → Prompt → 下一轮 Harness

已实现显式的单轮再生成，使用现有 `FeedbackPacket` 作为输入。反馈可以来自人工
审阅、`AutomaticFeedbackBuilder`，或其他工具，但必须关联到准确的父候选和证据。
正常候选执行会把多维质量信号落为 `evaluation.json`，并在 Harness 已保存时写入
`automatic_feedback.json`；它是下一轮反馈文件的可审计起点，不覆盖 revision child
保存的父级 `feedback.json`。

```text
父候选目录 + feedback.json + 原始目标源码
  → 校验候选 ID、轮次、函数名与源码/Harness 哈希
  → 读取证据并保存文本快照
  → StructuredFeedbackPromptBuilder 构造请求
  → N 次独立 LLM 请求
  → 各子候选审阅、可选编译/fuzz、评估报告
  → 下一轮 experiment.json（不自动继续）
```

## 准备反馈

从父候选 `result.json` 复制 `candidate_id`、`source_sha256`、`harness_sha256` 和 `round_index`；旧记录缺少轮次时按 0。下面是格式示意，哈希占位内容必须替换成父记录实际值：

```json
{
  "schema_version": 1,
  "candidate_id": "candidate_0005",
  "round_index": 0,
  "source_sha256": "父记录的源码SHA256",
  "harness_sha256": "父记录的Harness SHA256",
  "items": [
    {
      "metric_id": "reachability",
      "observation": "Harness 在 Size < 2 时提前返回，但目标函数已实现短输入返回 -1 的处理。",
      "hypothesis": "提前返回使目标的短输入错误路径无法被测试。",
      "suggestion": "保留可写输出参数，将短输入也传给目标；不要用固定数据替换。",
      "evidence": [
        {"artifact": "harness.c", "description": "前置长度检查", "locator": "包含 Size < 2 的条件"},
        {"artifact": "source_summary.json", "description": "tree-sitter 提取的目标 API 与条件摘要"}
      ]
    }
  ]
}
```

`metric_id` 使用十项指标 ID，编译等非评分反馈可设为 `null`。观测与证据必填，假设和建议可为 `null`。不要求提供分数，也不会把未知指标转换为改进目标。

反馈文件可放在父目录之外；`evidence.artifact` 必须指向父目录内的 `.c/.json/.txt/.log/.md` 文本文件，不能指向外部文件。框架校验文件和身份匹配，不证明观测内容真实。父候选即使编译失败也可修复，但必须已保存 `harness.c` 和对应哈希；没有提取出 Harness 的生成失败暂不支持作为父候选。

默认质量信号产生的反馈可直接作为上述文件使用，例如：

```bash
python3 -m harness_generation \
  --source runs/round0/candidates/candidate_0005/target.c \
  --function mp_parse \
  --parent-candidate runs/round0/candidates/candidate_0005 \
  --feedback runs/round0/candidates/candidate_0005/automatic_feedback.json \
  --output runs/round1 \
  --candidates 3
```

该文件在生成子候选时会被复制为子目录中的 `feedback.json`；子候选自身的
`automatic_feedback.json` 则保留给再下一轮，二者不会相互覆盖。

## 运行一轮

在已配置 `DEEPSEEK_API_KEY` 的终端执行：

```bash
python3 -m harness_generation \
  --source runs/round0/candidates/candidate_0005/target.c \
  --function mp_parse \
  --parent-candidate runs/round0/candidates/candidate_0005 \
  --feedback runs/reachability_feedback.json \
  --output runs/round1 \
  --candidates 3
```

这是路径示例，请替换成实际实验目录。两个反馈选项必须一起使用，不能与离线 `--harness` 合用。原有 `--model`、`--temperature`、`--generate-only`、`--fuzz-seconds` 和 `--corpus` 仍适用。默认生成并编译，N 个候选最多请求 N 次，不自动重试或补齐。

新实验 `strategy=feedback_revision`，子候选 `parent_id` 指向父候选，轮次加一。ID 形如 `candidate_0005.r1.candidate_0001`，物理目录仍为 `candidates/candidate_0001/`（N=1 保留平铺布局）。不同实验间用父目录和代码哈希共同定位来源，ID 不是全局 UUID。

若继续下一轮，应先评估子候选，再使用该子候选的记录准备新的反馈。旧反馈不能直接套到新 Harness 上。一次命令不会自行挑选最佳候选或消耗预算运行多轮。

## Prompt 构造与审计

`RevisionPromptBuilder` 定义扩展协议，默认实现为 `StructuredFeedbackPromptBuilder`：

1. 保留初始生成的系统规则和 tree-sitter 语法摘要。
2. 追加反馈修订规则，要求返回完整 C Harness，而非补丁。
3. 将父 Harness、结构化反馈和证据片段作为独立上下文传给模型。

规则要求模型区分事实与假设，核对建议是否符合接口契约，不修改目标、不吞掉错误、不把仅更换变量名当作改进，也不能声称未经执行验证的质量提升。它是提示约束，不是质量保证。

每个子目录保存实际请求 `prompt.json`、`feedback.json`、`feedback_evidence.json`、`parent_harness.c`，结果保存 `feedback_prompt_version` 和 `parent_directory`。证据按文件读取前 4096 个字符，标记是否截断，并记录完整文件 SHA-256；`locator` 作为定位说明保留，当前不解析为切片规则。超过 1 MiB 的文件要求提供较小的派生报告。每包最多 20 条反馈、10 个证据文件，文本字段各最多 8000 字符。

`iteration.py` 已提供默认的 `AutomaticFeedbackBuilder`、`WeightedAggregationPolicy`、`ScoreCandidateSelector` 和 `FeedbackDrivenIterationPlanner`，可在 Python 调度层中从候选执行结果与 `evaluation.json` 生成反馈、排序候选并规划下一轮子候选数。自动反馈会优先保留 stage failure 和低分/错误的多维 metric，按弱项稳定排序；未知指标不会被写成 0 分。显式 `--parent-candidate/--feedback` 保留为人工控制的一轮再生成方式；下节的 `feedback-loop` 提供有界的自动迭代。实际质量提升仍需后续评估验证。

## 有界自动闭环

`feedback-loop` 将已有的单轮部件串成一个明确有界的闭环：

```text
round 0 parent Harness
  → evaluation.json + automatic_feedback.json
  → 哈希/源码/证据快照校验
  → revision prompt（父 Harness + feedback + evidence）
  → N 个 LLM 子候选
  → 各子候选验证、执行、评估
  → 仅从通过阶段门槛的子候选中稳定选择 1 个
  → 下一轮，直到 --rounds 用尽
```

示例（mini_parser）：

```bash
export DEEPSEEK_API_KEY='...'
python3 -m harness_generation feedback-loop \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --parent-harness benchmarks/mini_parser/harnesses/pass_through.c \
  --output runs/mini_parser_feedback_loop \
  --rounds 2 \
  --children-per-round 2 \
  --feedback-threshold 0.9 \
  --fuzz-seconds 10 \
  --corpus benchmarks/mini_parser/corpus/structured
```

也可从已有候选继续（该目录必须拥有匹配的 `result.json`、`harness.c` 与
`automatic_feedback.json`）：

```bash
python3 -m harness_generation feedback-loop \
  --source benchmarks/mini_parser/target.c \
  --function mp_parse \
  --parent-candidate runs/mini_parser_feedback_loop/round_001 \
  --output runs/mini_parser_feedback_loop_resume \
  --rounds 1
```

闭环根目录保存 `feedback_loop.json`，逐轮记录父候选、实际使用的 feedback SHA-256、
子实验目录、被拒绝候选原因、评分选择结果和最终选中的候选。失败 child 会保留产物但
不会成为下一轮父候选。选择只比较有 Harness、没有 failure stage 且阶段状态已接受的
children；这仍只是按已测质量信号的选择，不能把 Smoke 成功或未知指标描述为质量提升。
