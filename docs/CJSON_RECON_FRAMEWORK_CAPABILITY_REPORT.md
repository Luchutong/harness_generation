# cjson_recon 框架能力检验

日期：2026-10-06（Asia/Shanghai）。本轮由用户明确指定 `/home/luchitong/work/cjson_recon` 为测试项目，恢复本任务所需的定向检查和 fresh 执行。

## 登记边界

固定生产 fingerprint：`1da0159676fef323ce5be1fb51aceb9d8f9bacf348a5e7e344418e2d82eaae2c`，170 文件。算法为所有 `harness_generation/**/*.py`、`sfg_builder/**/*.py` 和 `pyproject.toml` 的 SHA256 清单按路径排序、紧凑 JSON 序列化后再次 SHA256。

目标只索引 `/home/luchitong/work/cjson_recon/project/cJSON.c` 和 `cJSON.h`（cJSON 1.7.15）。目标没有 Git 元数据，用完整两文件清单验证源身份。父目录的历史 framework、手写 harness、corpus 和构建结果不进入新模型输入。

| 入口 | 次数 | 检查内容 |
| --- | --- | --- |
| `cJSON_ParseWithLengthOpts` | 3 | input buffer/extent、owned tree 返回及清理、借用输入的 parse-end 输出 |
| `cJSON_PrintUnformatted` | 1 | cJSON 对象构造、打印字符串 owned 返回及 `cJSON_free` 清理 |
| `cJSON_PrintPreallocated` | 1 | caller-owned 输出 storage/capacity、对象构造、format 标量 |

每个 trial 从源码解析重新开始，执行 candidates → candidate validation → Slice → minimal FT → Context → Plan/code/build/runtime。无 resume、无失败 trial 重跑、无旧语义产物输入。Context 失败后仍调用生成门禁，检查其是否阻止代码调用。登记原预算与有界修复额度，拒绝尝试的真实调用和 tokens 不回退。构建用 C11、clang、libm；直接单文件编译，`ENABLE_LOCALES` 未定义（关闭）。

这三个入口不能代表 callback construction source、shared context lifecycle、owned out-parameter creator、stream/file abstraction 的全部覆盖。`return_parse_end` 是 borrowed input alias，不是 owned out-parameter creator。

## 执行与证据

测试已按用户要求暂停，登记和原始产物保存在 [实验目录](../artifacts/cjson_capability_20261006/)，状态见 [testing_paused.json](../artifacts/cjson_capability_20261006/testing_paused.json)。暂停核对时已无注册 runner/worker 进程；5 个 worker 均已保存最终状态，包含 3 个 Context 未闭合、1 个 Slice 原生终态无效，以及 1 个候选 unresolved 后 Slice selector 拒绝。未生成通过的 harness。cohort 缺少 supervisor completion_audit.json，不能虚构完整结束审计，也不追加重跑、重放、Gate 重建或 build/runtime。最终成本汇总尚未定稿。

本轮后续工作转为 [框架机制与数据流说明](FRAMEWORK_EXECUTION_AND_DATA_FLOW.md)，以源码和已有产物解释当前实现。上述 worker 状态与此前回归是暂停前的历史记录，不是恢复测试。

随后已按用户要求修改 Agent 提交、查询、反馈、证明记忆和调度，见 [Agent 能力与提示改进报告](AGENT_CAPABILITY_AND_PROMPT_IMPROVEMENT_REPORT.md)。Main 现为新的 171 文件版本，本报告的 cJSON cohort 继续绑定原冻结 fingerprint；没有对新版重跑或补算成功。

预检首轮为 81 passed、14 failed（37.84 秒）。12 项在候选 evaluator 调用之前尝试 deepcopy `mappingproxy`，另 2 项从不含原生依赖的夹具选择依赖而触发 `StopIteration`。保留 [初始结果](../artifacts/cjson_capability_20261006/test_preflight/initial_result.json)；只修正两份测试文件，增加两项单模式联动及持久化正例，指定八文件最终 **97 passed（42.34 秒）**，生产 fingerprint 未变。见 [修正摘要与备份](../artifacts/cjson_capability_20261006/test_preflight/fixture_fix_summary.md)、[完整回归日志](../artifacts/cjson_capability_20261006/test_preflight/fixture_fixed_full.log)。首轮失败不能直接视作候选事务校验失败，也不能删除后补算首轮成功。

离线 parser 审计核验全部 115 个 function body 与源码 span 相符；实际 Linux C11 编译的 112 个定义全部包含，额外 3 个定义是未求值 Windows 分支的静态 overapproximation。三个入口及 `cJSON_Delete`、`cJSON_free`、`cJSON_InitHooks`、`cJSON_New_Item` 和 17 个 Create* 都有完整定义。两条文件级 warning 汇总了 8 个 parser ERROR 节点，全部对应 `CJSON_CDECL` token：hook struct 字段及 Windows wrapper。**Hook struct 的 parse error 会使 callback declaration 查询跳过字段，实际签发数为 0**；raw struct 声明仍保留，不能把这些 warning 全部认作无害。见 [离线 parser 审计](../artifacts/cjson_capability_20261006/offline_parser_review.json)。

## 自动发现与本轮手动选点的区别

框架的 `discover_candidates` 自动保留全部解析函数，按 byte pointer、length-like parameter、parser-like name、resource return 等信号排序。`candidate-validate` 不给 `--candidate` 时会遍历 catalog 选中候选；`semantic-slice` 不给 selector 时处理全部 accepted 候选。Minimal FT 和 Context 也能批处理已有产物。新链各阶段能批量执行，但完整项目的源码/构建边界、全局成本及阶段调度目前由外部实验脚本组织；现有 `run`/`generate-all` 面向旧 triplet 生成链，不能据其名称声称已有新 Context 链的一键项目调度。

本轮每次 `candidates` 均自动登记、选中 115 个函数，其中 37 个标为 static；`cJSON_ParseWithLengthOpts` 排名 1、`cJSON_PrintPreallocated` 排名 3、`cJSON_PrintUnformatted` 排名 61。排序分数是启发式信号，不是可调用性证明或成功概率。手动固定三个 anchor 是本实验设计：控制重复目标并覆盖结构差异；后续 `--candidate` 明确只验证这些目标。**这些结果不证明全项目自动入口筛选的召回率、排序质量或总成本可控**。完整自动流程仍需要结合构建配置、公开可调用范围、数据入口证据及预算来调度，而不是默认让 115 个函数全部消耗独立模型预算。
