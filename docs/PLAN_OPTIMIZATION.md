# HarnessPlan 优化闭环

`plan-optimize` 从一份已生成的 Stage 4 HarnessPlan 和 harness 开始。它先在隔离目录中重新执行正式验证，然后按轮次生成子计划；每个子计划都会重新生成 harness、编译链接、运行验证，并在相同构建配方、语料、执行次数和 seed 下测量目标代码分支覆盖率。未通过验证或缺少目标覆盖率的候选不会获得分数。父候选参与每轮选择，较差的子候选不会替换它。

```bash
harness-generation plan-optimize \
  --artifacts ARTIFACTS --ft FT_ID \
  --project-root PROJECT --target-build BUILD_RECIPE.json \
  --output NEW_OUTPUT --rounds 2 --children-per-round 3 \
  --runs 1000 --seeds 1 2 3 --holdout-seeds 101 102 103 \
  --corpus CORPUS
```

`ARTIFACTS` 必须包含 `functions.json`、`triplets.json`、Stage 3 rough、已发布的 harness 和 HarnessPlan。构建配方明确列出目标源文件、编译器、头文件目录与链接参数。`NEW_OUTPUT` 必须尚不存在。每个候选位于自己的 `candidates/` 目录；`plan_optimization.json` 保存谱系、验证和评分，并分别报告生成间方差与每个生成结果的 seed 间方差。无测量时方差为 `null`。

Stage 4 的 `optimization_feedback` 包含父候选的实测分数和原始测量值。修订只允许修改 HarnessPlan 的 `input_strategy` 和 `notes`。候选 harness 由 Stage 4 写入暂存位置，只有 intermediate、compiler、linker、runtime 四项正式验证全部通过，promotion 才发布稳定的 harness 与 plan。`passed_with_limitations` 不满足发布门槛。

## 非帧输入

当项目提供经过证实的递归文法时，可以将它写成 `TargetContract` 的 `grammar` 输入模式，并通过 `generate --target-contract CONTRACT.json` 交给 Stage 4。文法需有 `start` 和非空 `rules`；计划需声明相同的 `start_symbol`、正数 `max_depth` 与 `max_output_bytes`。Stage 4 会核对输入缓冲区确实受到 fuzzer 字节影响，并通过真实编译链接验证生成代码。

```json
{
  "schema_version": 1,
  "entry_function": "parse_value",
  "input": {
    "id": "project_documented_value_grammar",
    "mode": "grammar",
    "status": "known",
    "source": "project_documentation",
    "evidence": ["The project's documented input grammar"],
    "grammar": {
      "start": "value",
      "rules": {"value": "object | string", "object": "'{' value? '}'", "string": "quoted characters"}
    }
  },
  "resources": [],
  "facts": []
}
```

静态协议挖掘仍以定长帧事实为主；它不会从任意 C 解析器自动恢复递归文法。文法契约必须有可信的项目来源，运行期覆盖率与崩溃复现仍是生成结果的独立证据。优化实验的多个 seed 衡量同一生成结果的运行波动，多个独立子计划衡量生成波动。
