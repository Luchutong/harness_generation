"""Render preserved native results; no annotation, model or pipeline mutation."""
import argparse
from collections import Counter,defaultdict
import csv
import json
from pathlib import Path
import statistics


def average(values):
    values=[v for v in values if v is not None]
    return f'{statistics.mean(values):,.1f}' if values else 'N/A'


def render(directory,output):
    summary=json.loads((directory/'summary.json').read_text());reg=summary['registration'];rows=summary['trials']
    benchmark=Path(reg.get('benchmark_directory',Path(__file__).resolve().parents[2]/'benchmarks/blind'))
    manifest=json.loads((benchmark/'real_manifest.json').read_text())
    synthetic=json.loads((benchmark/'synthetic_manifest.json').read_text())
    freeze=json.loads((directory/'freeze/manifest.json').read_text());groups=defaultdict(list)
    for r in rows:groups[(r['set'],r['case'],r['configuration'])].append(r)
    complete=summary.get('completed_trials')==reg['planned_trials'] and summary.get('implementation_unchanged')
    text=f'''# Blind Generalization Evaluation

本轮使用固定语义实现，以新的 API semantic patterns 和实测前选定的真实项目评价泛化。旧五类 fixture 仅是 Development / Regression Set，不进入盲测分母。本实验显式指定 target anchor，属于 **semantic pipeline evaluation**，不评价 project-level Candidate recall。

当前记录 **{len(rows)}/{reg['planned_trials']}** 个 native trials；状态：**{'completed, frozen' if complete else 'in progress / not finalized'}**。没有 paired replay、失败后修代码、追加预算或挑选最佳一次。

## 1. Frozen implementation identity

- git commit：`{freeze['git_commit']}`，branch `{freeze['branch']}`，dirty files {len(freeze['dirty_status'])}；本地未提交代码属于冻结身份。
- production fingerprint：`{freeze['source_fingerprint']}`。
- 135 个生产 Python 源文件和 root runtime dependencies 有摘要；原始源码和 tracked patch 归档于 `freeze/`。
- requested model：`{freeze['provider']['model']}`；provider `{freeze['provider']['provider']}`，thinking `{freeze['provider']['thinking']}`。
- served models：{', '.join(sorted({m for r in rows for m in r.get('served_models',[])})) or 'not yet observed'}。
- 开始时间：`{reg['started_at']}`；结束时间：`{summary.get('completed_at','pending')}`。
- production/evaluation/benchmarks unchanged：`{summary.get('implementation_unchanged')}/{summary.get('evaluation_unchanged')}/{summary.get('benchmarks_unchanged')}`。

| Component | Frozen version |
| --- | --- |
'''
    for component,versions in freeze['versions'].items():
        text+=f"| {component} | "+', '.join(f'`{k}={v}`' for k,v in versions.items())+' |\n'
    text+='''
## 2. Development set

direct buffer、NUL string、shared context、owned return、callback 只用于 unit/regression/negative tests 与 implementation validation。此前 25-run 和 paired cohort 均为开发数据，已在对应 runner、报告中标记。它们不证明跨项目泛化。

## 3. Blind synthetic set

十二种新结构维度：creator with arguments、out-parameter initialization、malloc/memset/helper initialization、custom allocator、refcount、opaque public context、setter callback registration、nested callback table、callback pull input、multiple feeds、simultaneous same-type resources、memory stream。

每个 case 的源文件仅在 preregistration benchmark directory 下的 `synthetic/<id>/source/`，expected contract 位于同级 `ground_truth.json`。独立 reference harness 在 source 外，用于验证样例自身可执行，未向 Agent 提供。它们不是旧 fixture 改名，也不用于新增生产规则。

## 4. Blind real-project set

在 production freeze 后、native run 前选定 target APIs。源码为原始库实现和 header slice；统一排除 examples、tests 和上游 fuzzer，选择不基于框架成功。此范围限制不能当作全仓库入口发现。

| Target | Upstream / commit | Language / build | Model / selection rationale |
| --- | --- | --- | --- |
'''
    for case in manifest['cases']:
        repo=case['repo'].removesuffix('.git');text+=f"| `{case['target_api']}` | [{case['project']}]({repo}/tree/{case['commit_sha']}) / `{case['commit_sha']}` | {case['language']} / {case['build_system']} | {case['rationale']} |\n"
    text+='''
一个 API 可以覆盖多个模型类别；项目数与入口数分别记录。构建系统及原始 source hashes 位于 real selection/manifest；构建布局准备在任何 native call 前完成，没有修改目标库算法。

## 5. Ground truth and semantic adjudication

`ground_truth.schema.json` 与人工独立 contract annotation 包含 CORE、required support、resource origin/consumers/cleanup、input binding、ownership、callback、ordering、invocation multiplicity 和必要约束。Pipeline worker 不导入 evaluator 或 fixtures；仅得到 source/、target API 与纯 build options。Agent 工具只能索引 trial project；注释目录不在可读取范围。

Supervisor 在 worker 退出后才加载 truth。CORE/support precision/recall 按预注册 API sets 计算，资源比较明确的 origin 与消费身份，生命周期检查明确 creator/output 和 cleanup，ownership 检查返回/参数和 release，callback 检查精确 field/registration/ABI，ordering 检查 hard-edge reachability，multiplicity 检查独立预期调用次数。

这些是必要契约检查，不是任意 C/C++ 语义的形式化证明。未产出契约为 unverified；pull reader/custom allocator 行为不能只由 ABI 判断，仍需 code audit。Runtime 通过也不会把 unknown 自动改成 correct。

自动 `false_complete` 为 Gate complete 且 checker 判断必要-contract mismatch；最终还须独立确认其不是合法替代构造路线。单纯 compile/static failure 不自动证明 Gate semantic unsoundness；另列 complete_but_invalid、unverified dimensions、sanitizer failures。未检出的错误不等于不存在；确认后的人工 audit 应作为独立追加结果，不能覆盖原始 trial。

## 6. Budgets and native design

每 case / configuration 至少五个独立 trials，fresh source copy、Candidate、Slice、FT、Context、Plan 与 code；没有 resume。A/B/C 不是同证据重投影。schedule 固定 seed 20260929，仅用于作业交错，不是模型随机 seed。Agent temperature/provider seed 未指定，code temperature 0.2，最多 8192 output tokens；四种 library adapters 只有原始 build flags/header paths，没有语义适配。

'''
    text+='```json\n'+json.dumps(freeze['budgets'],indent=2)+'\n```\n'
    text+='''
所有类别、A/B/C 使用相同阶段 ceiling。Terminal schema repair 是冻结实现既有行为，非失败后外部 retry。实际调用/tokens 可不同；并发数量在 preregistration 中固定，不改变每个 trial 预算。

## 7. Native repeated-run results

Development、blind synthetic、blind real 分开统计。所有失败进入分母，未到达的 compile/runtime 计为未成功，但不称为编译错误。

| Set / case | Config | Trials | Candidate accepted | Slice success | Context complete | Plan | Compile | Runtime | False complete |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
'''
    for key,selected in sorted(groups.items()):
        metrics=[sum(bool(r.get(field,False)) for r in selected) for field in ('slice_success','context_complete','plan_success','compile_success','runtime_success','false_complete')]
        accepted=sum(r.get('candidate_status')=='accepted' for r in selected)
        text+=f'| {key[0]} / {key[1]} | {key[2]} | {len(selected)} | {accepted} | '+' | '.join(str(v) for v in metrics)+' |\n'
    text+='''
## 8. Semantic correctness

Each dimension is correct / incorrect / unverified / not applicable. Precision/recall and per-check evidence are in per-trial evaluation.json. Missing data remains unverified; zero denominator is N/A.

| Set / Config | Dimension | Correct | Incorrect | Unverified | N/A |
| --- | --- | ---: | ---: | ---: | ---: |
'''
    for dataset in ('blind_synthetic','blind_real'):
        for cfg in ('A','B','C'):
            selected=[r for r in rows if r['set']==dataset and r['configuration']==cfg]
            for dimension in ('resource_identity','lifecycle','ownership','callback','ordering','input_binding','multiplicity'):
                counts=Counter(r.get('semantic_correctness',{}).get(dimension,{}).get('status','unverified') for r in selected)
                text+=f'| {dataset} / {cfg} | {dimension} | '+ ' | '.join(str(counts[v]) for v in ('correct','incorrect','unverified','not_applicable'))+' |\n'
    text+='''
## 9. False-complete and conservative failures

| Set / Config | complete_and_runtime_valid | complete_but_invalid | blocked_conservatively | semantic_verified + runtime | confirmed false_complete |
| --- | ---: | ---: | ---: | ---: | ---: |
'''
    for dataset in ('blind_synthetic','blind_real'):
        for cfg in ('A','B','C'):
            selected=[r for r in rows if r['set']==dataset and r['configuration']==cfg];counts=Counter(r['outcome'] for r in selected)
            text+=f'| {dataset} / {cfg} | '+ ' | '.join(str(counts[v]) for v in ('complete_and_runtime_valid','complete_but_invalid','blocked_conservatively'))+f" | {sum(r.get('semantic_verified',False) and r.get('runtime_success',False) for r in selected)} | {sum(r.get('false_complete') is True for r in selected)} |\n"
    positives=[r for r in rows if r.get('false_complete') is True]
    if positives:
        text+='\nAutomatically flagged mandatory contract mismatch candidates (independent audit required):\n\n'
        for r in positives:text+=f"- `{r['case']}/{r['configuration']}/{r['trial']}`: {', '.join(r['false_complete_reasons'])}。见该 trial evaluation.json 中的 checks。\n"
    else:text+='\n本批尚未确认 false complete；这不表示不存在未审计的 callback、input transport 或其他语义缺陷。\n'
    text+='''
## 10. Certificate / rule applicability

下表 C 为完整未干预实现；A/B 的 disabled 原因单独保存，不能误当成规则自然失败。每 trial 记录 fired / did_not_fire / blocked / produced_unresolved。未命中原因属于 evaluation-side diagnosis，没有改动生产规则来追求命中。

| Set / Config | Rule | Applied trials | Cases with a hit | Blocked | Produced unresolved |
| --- | --- | ---: | ---: | ---: | ---: |
'''
    for dataset in ('blind_synthetic','blind_real'):
        for cfg in ('A','B','C'):
            selected=[r for r in rows if r['set']==dataset and r['configuration']==cfg]
            for rule in ('resource_identity','creator_return','cleanup_consumption','public_callback_object','nul_contract','local_state_transition','ordering_projection'):
                applied=[r for r in selected if r.get('certificates',{}).get(rule,{}).get('applied')]
                text+=f'| {dataset} / {cfg} | {rule} | {len(applied)} | {len({r["case"] for r in applied})} | '+str(sum(r.get('certificates',{}).get(rule,{}).get('status')=='blocked' for r in selected))+' | '+str(sum(r.get('certificates',{}).get(rule,{}).get('status')=='produced_unresolved' for r in selected))+' |\n'
    text+='''
## 11. Failure taxonomy

Failures are multi-label. Early upstream failure keeps downstream metrics N/A/false, not zero hard gaps. Operational/programming errors are retained as observed failures; no code was repaired using their results.

| Failure | Trials |
| --- | ---: |
'''
    failures=Counter(f for r in rows for f in r.get('failure_reasons',[]))
    for reason,count in failures.most_common():text+=f'| {reason} | {count} |\n'
    text+='''
## 12. Native A/B/C ablation

A keeps Agent-grounded model IDs but removes framework resource projection and construction certificates. B adds generic resource identity/flow, disables allocation/free ownership shortcut and reuse normalization, and still removes high-level creator/public callback/cleanup/state certificates. C is the original frozen implementation.

Gate, prompts, registry, callback ABI enrichment, NUL projection, bounded evidence preflight and existing ordering validators are held constant. Generic flow tool evidence is still available to the Agent in every config; this experiment isolates deterministic projection, not removal of an Agent tool. This is a subtractive intervention, not an exact historical baseline. Independent native model trajectories mean A→B→C differences require repeated sampling, not paired causal token claims.

## 13. Cost

tokens are reported provider usage, not price or uncached billed tokens. Failed provider attempts without usage cannot be priced. Context grouped traces are deduplicated; global Context metrics govern call/tool counts. Actual output size, FT/core/support/unresolved/gaps/closure/source chars, elapsed time and all raw stages are retained per trial.

| Set / Config | Model calls | Tools | Prompt tokens | Completion tokens | Total tokens | Mean hard gaps (observed Context only) | Mean source chars | Mean seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
'''
    for dataset in ('blind_synthetic','blind_real'):
        for cfg in ('A','B','C'):
            selected=[r for r in rows if r['set']==dataset and r['configuration']==cfg]
            text+=f'| {dataset} / {cfg} | '+ ' | '.join(f"{sum(r.get(k,0) for r in selected):,}" for k in ('model_calls','tool_calls'))+' | '+ ' | '.join(f"{sum(r.get('tokens',{}).get(k,0) for r in selected):,}" for k in ('prompt_tokens','completion_tokens','total_tokens'))+f" | {average([r.get('hard_gaps') for r in selected])} | {average([r.get('source_chars') for r in selected])} | {average([r.get('elapsed_seconds') for r in selected])} |\n"
    text+='''
## 14. Limitations

只有五个重复样本/配置/模式，非独立第三方持有的盲集；由实现者在 freeze 后创建，仍有 pattern selection bias。真实项目均为 C，没有 C++ 项目效度；显式 target 和原始 source slice 不支持 entry discovery recall。六个固定 ASan/UBSan replay 输入不证明 coverage 或穷尽正确性。

人工 annotation 及自动 necessary-contract checker 可能遗漏不变量；unverified 的 reader/allocator/field values 不能当作成功。A/B 是 evaluation-side projection intervention，预算相同不代表调查/evidence 相同。指标未控制 provider 时间变化和硬件噪声。若这一批失败以后参与规则修改，必须换新的 blind set，保留本批。

## 15. Which capabilities generalized?

'''
    successful=[r for r in rows if r['configuration']=='C' and r.get('semantic_verified') and r.get('runtime_success')]
    patterns=sorted({r['case'] for r in successful})
    text+='完整配置 C 中具有已检查必要契约且 runtime 通过的模式：'+(', '.join('`'+x+'`' for x in patterns) if patterns else '尚无已充分验证的 positive pattern')+'。\n\n'
    text+='这些是 observed capability，只有在重复成功和独立语义证据都足够时才支持对应模式泛化；不能推广成 framework generalizes across C/C++ projects。\n'
    text+='''
## 16. Narrow deterministic proof subset

creator_return 仍要求无参数精确 calloc creator、单来源、非逃逸字段 consumer 和唯一 cleanup；public_callback_object 仍要求完整公开 layout、可显式初始化所有字段和同步非逃逸；cleanup_consumption 仍要求精确单参数 free wrapper及已有独立 owned producer。它们的 zero hit 或少量 hit 应如实解释为 recognized subset，而非修改规则提高 benchmark。

最终原始 summary、preregistration、源码归档、每次日志/annotation digest/evaluation.json 均在本地 artifact 目录。报告没有替换失败，也没有把 development 数据混进成功率。

复现（需先创建新的 freeze/output 和新盲集；禁止对已反馈到算法的本集继续称 blind）：

```bash
.venv/bin/python -m scripts.blind_eval.freeze --output artifacts/<new-frozen-output>
.venv/bin/python -m scripts.blind_eval.runner --benchmark-dir benchmarks/blind/<new-cohort> --output artifacts/<new-frozen-output> --repetitions 5 --workers 4
.venv/bin/python -m scripts.blind_eval.report --input artifacts/<output> --output docs/BLIND_GENERALIZATION_EVALUATION.md
```
'''
    text+='\n本轮 synthetic patterns：\n\n'+''.join('- `'+c['id']+'`: '+c.get('semantic_dimension','pattern')+'\n' for c in synthetic['cases'])
    text+=f'\n真实入口数 {len(manifest["cases"])}；独立项目数 {len({c["project"] for c in manifest["cases"]})}。\n'
    output.write_text(text)
    flat=[{k:r.get(k) for k in ('set','case','configuration','trial','candidate_status','slice_status','slice_core_size','slice_support_size','slice_unresolved_size','minimal_ft_core_size','minimal_ft_support_size','context_status','hard_gaps','soft_unknowns','api_closure_size','context_complete','plan_success','code_success','compile_success','runtime_success','sanitizer_status','false_complete','model_calls','tool_calls','source_chars','elapsed_seconds')}|r.get('tokens',{}) for r in rows]
    if flat:
        with (directory/'trials.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(flat[0]));writer.writeheader();writer.writerows(flat)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();render(args.input,args.output)
