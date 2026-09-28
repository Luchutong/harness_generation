# Candidate Discovery 与 FT Construction 的边界

本次重构把“提出可能的 fuzz entry”从 FT 构造中独立出来。输入仍为现有 Phase 1 的 functions、annotations、flows、SFG 与可选 ownership/usage artifacts；输出仍为 schema version 5 的 `triplets.json`。Stage 1–4、Protocol Mining、反馈循环及 FT 排序规则没有修改。

## 调用链

```text
Phase 1: functions / annotations / flows / sfg / ownership / usage
    ↓
discover_candidates(artifacts, policy, max_candidates)
    ↓
candidate_discovery/candidates.json
    ↓
FunctionTripletExtractor.extract(artifacts, candidates=catalog)
    ↓ 每个 selected candidate
extract_for_anchor(artifacts, candidate 或 function_id)
    ↓
可替换的 StructuralRelationPolicy + 现有生命周期闭包
    ↓
triplets.json + triplet_exclusions.json + candidate construction metadata
    ↓
现有 rank / generate / generate-all
```

`extract_for_anchor` 处理一个 anchor 的所有 usage-pattern 变体，返回 `tuple[FunctionTriplet, ...]`。它不根据字节参数、长度名称或已有 ISF 标注拒绝该 anchor。未来的语义验证层可以向它提交选定的函数 ID；未来的 semantic slice 可以替换结构策略。本次没有实现 Agent 或新的剪枝算法。

## 两种候选 artifact

现有 SFG 把供语义分析使用的静态池写在根目录 `candidates.json`，其 schema 包含 `isf/prf/hpf` 等字段。这个文件继续保留，原有 SFG 预算、投票和 `paper_minimal` 行为没有变化。

新 artifact 为 **`candidate_discovery/candidates.json`**，由 `ArtifactStore.entry_candidates`、`write_candidate_catalog` 与 `load_candidate_catalog` 管理。它有独立的 `artifact_kind=entry_candidate_catalog`、`schema_version=1` 和 `policy_version=entry-discovery-v1`。两种 schema 不会互相覆盖或自动误读。

新增命令在完整的 Phase 1 输出上独立执行，不调用模型，也不构造 FT。它读取 **所有 `functions.json` 记录**，包括未进入旧静态候选池、没有 annotation、没有 flow 及仅声明的函数，因此不会继承旧 ISF 过滤造成的永久缺失。没有被 parser 解析到的函数不在本次覆盖范围；本次没有扩展语言前端。

## 数据契约

- `CandidateSignal`：`kind`、可选 `[0,1]` score、结构化 evidence。记录参数位置、类型、声明、名称提示、AST writes、现有 ISF annotation、使用模式 ID 等；不保存 prompt、response 或自由格式模型解释。
- `EntryCandidate`：函数 ID、名称、签名、文件、行号、signals、priority、status、metadata。所有 discovery candidate 的 **status 始终为 `unresolved`**。
- `CandidateCatalog`：完整 candidate 集合、来源 fingerprint、策略、按优先级选出的 IDs、预算，以及每个未选候选的明确 deferred reason。

priority 是 signal score 的最大值，用于确定处理顺序，不能解释为 entry 有效性或生成成功概率。参数启发式只能增加 signal；没有 signal 的函数仍在 catalog 中。`buffer_length_relation_candidate` 明确携带 `relation_proven=false`，不会把任意 pointer/length 组合当成已证实的输入绑定。

序列化不包含时间戳，候选和 signal 使用稳定顺序。fingerprint 覆盖函数源码记录及 Phase 1 的 annotations、flows、graph、ownership 和 usage evidence。消费时检查 fingerprint、全部函数是否保留及每个 identity；输入变化时要求重新 discovery，不会静默回退。catalog 的 construction metadata 不改变来源 fingerprint。

### 处理策略

| 策略 | 下一步处理的集合 | catalog 中未处理的记录 |
| --- | --- | --- |
| `broad`，新 discovery CLI 的默认值 | 所有有定义的函数，按 priority / function ID 排序 | 仅声明记录延期为 `declaration_only`；预算外记录为 `candidate_budget` |
| `legacy` | 有旧 ISF annotation 的函数，保持原抽取入口集合 | 其余记录为 `not_selected_by_legacy_isf_policy` |
| `explicit` | 用户通过 `--anchor-id` 或 Python API 明确选择的 ID | 其余记录为 `not_requested` |

`--max-candidates 0` 会保留整个候选集并延期全部处理。legacy 是兼容选择策略，不是候选存在性的事实来源。没有持久 catalog 的旧 `triplets` 调用会创建完整的 legacy catalog，再进行构造；已有但错误或过期的 catalog 会报错。

## 结构传播与 oversized 诊断

旧的 type-reachable closure 已封装在 `LegacyStructuralClosure`，实现 `StructuralRelationPolicy.select(...)`。它保留原先的 null 哨兵、opaque boundary、owned-return producer 特判和其他 ISF masking。默认 FT 成员集合保持兼容。

FT 的 `metadata.relation_evidence` 区分：

- `strong`：已有 ownership、lifecycle closure、explicit usage pattern 的关系记录；strong 相对于共享类型证据而言，并不表示本次新增了独立的语义验证。
- `weak_structural_function_ids`：由结构边关联的函数；`weak_only_function_ids` 表示缺少上述强证据的非 anchor 成员。
- `shared_type_is_semantic_evidence=false`：共享类型本身不等价于语义上必需。默认策略仍使用旧闭包，未来可以替换该策略而无需重写 discovery。

本次没有新增 direct-call 分析；后续关系策略可引入该证据。原 FT 的结构边、bypass input binding、ownership 表达与 wire schema 不变。

超过 `max_functions_per_ft` 时，继续跳过该 FT 变体以兼容 downstream，但在 `triplet_exclusions.json` 和对应 candidate 的 `metadata.construction.diagnostics` 中记录：

```text
anchor_function_id / function / usage_pattern_id
reason = too_many_functions
function_count / max_functions_per_ft / candidate_retained = true
frontier.function_ids
frontier.structure_nodes
frontier.relation_evidence
```

catalog 中该函数继续存在。`metadata.construction.status` 为 `oversized`；若部分变体成功则为 `partial`，全部构造成功则为 `constructed`。这些是工程处理状态，candidate 的语义状态仍为 `unresolved`。从未处理的延期候选有 `deferred` 状态及 reason；已经处理过但本次没有被请求的候选保留原 construction 结果，防止另一个 anchor 的运行抹掉已有 oversized frontier。本次工作集合以 catalog 的 selection 为准。

为了兼容 `FunctionTriplet` 必须恰好有一个 ISF 的契约，显式 anchor 在 **本次 FT 的角色视图中**带 ISF role；不会修改 `annotations.json`。`metadata.anchor_candidate` 标明 `unresolved`、是否已有 ISF annotation 以及 `explicit_construction_request`。构造成功不等于目标已被证明是 ISF；现有 rank 对正向 byte-stream evidence 的要求仍保留。

## CLI

以下命令假设 `artifacts/demo` 已包含 Phase 1 的四个基础文件。

兼容现有目标集合，两个阶段独立执行：

```bash
python -m harness_generation candidates --artifacts artifacts/demo --policy legacy
python -m harness_generation triplets --artifacts artifacts/demo --individual --paper-minimal
python -m harness_generation triplets rank --artifacts artifacts/demo --max-ft 1
```

记录更宽的候选集合，并限制进一步构造数量：

```bash
python -m harness_generation candidates --artifacts artifacts/demo --max-candidates 10
python -m harness_generation triplets --artifacts artifacts/demo --max-functions-per-ft 20
```

指定目录中某个函数 ID 构造 FT（可重复 `--anchor-id`，不要使用可能重名的函数名称）：

```bash
python -m harness_generation triplets --artifacts artifacts/demo --anchor-id 'api.c:7:parse_wrapped'
```

也可用 `triplets --candidates /path/to/candidate_catalog.json` 消费外部 catalog；结果及更新后的候选诊断写入当前 `ArtifactStore` 的标准路径，输入文件不被覆盖。ID 需要与当前 `functions.json` 匹配。重生成 triplets 后需要重新运行 rank，旧 selection fingerprint 不会被绕过。

最小真实模型 demo 脚本已显式增加 legacy Candidate Discovery 步骤。Python 旧调用 `FunctionTripletExtractor().extract(artifacts)` 仍走兼容策略；新调用可传 `candidates=catalog`，或直接使用 `extract_for_anchor`。

## 验证

```bash
.venv/bin/python -m pytest tests/test_entry_discovery.py -q
```

测试覆盖 unusual buffer、context-only、path 命名、无 annotation/flow、paper-minimal 下的候选保留；预算延期和 schema/fingerprint 校验；显式 anchor、强弱关系、oversized frontier、生命周期和替代 relation policy；两个独立 CLI 及 unchanged rank / generation_cli / Stage 1 消费。验证使用本地 mock，没有新模型请求。

JSON 与 libxml2 xmlIO 的原抽取器对照另外检查 FT ID、成员、结构边、usage/lifecycle 与旧 metadata 的一致性，只允许新增 `anchor_candidate` / `relation_evidence` metadata。当前目录没有旧测试源码，本次测试是新增的边界回归集。
