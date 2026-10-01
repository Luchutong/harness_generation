"""Separate post-hoc observations; never repair or rerun a native blind trial.

For supervisor adjudication exceptions, recover stage and cost observations
using the frozen extractor with semantic adjudication disabled in an isolated
function namespace. Keep those semantic dimensions unverified. Original native
summary/trials and the frozen evaluator remain unchanged.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import statistics
import types

from scripts.blind_eval import evaluate
from scripts.blind_eval.identity import assert_frozen, file_digest
from scripts.blind_eval.report import render


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unverified_semantics(*args):
    return {dimension: {'status': 'unverified', 'checks': [],
        'reason': 'original supervisor adjudication exception; no semantic repair'}
        for dimension in evaluate.SEMANTIC_DIMENSIONS}


def observational_extractor():
    # Do not monkeypatch even the evaluator module. This second function shares
    # the frozen metric extractor's bytecode and receives separate globals.
    namespace = dict(vars(evaluate))
    namespace['semantic_checks'] = unverified_semantics
    return types.FunctionType(evaluate.evaluate_trial.__code__, namespace,
                              'posthoc_observational_extractor')


def aggregate(rows):
    result = {'trials': len(rows),
        'candidate_statuses': dict(Counter(row.get('candidate_status', 'unverified') for row in rows)),
        'candidate_invalid_output': sum('candidate_invalid_output' in row.get('failure_reasons', []) for row in rows),
        'slice_statuses': dict(Counter(row.get('slice_status', 'not_run') for row in rows)),
        'context_statuses': dict(Counter(row.get('context_status', 'not_run') for row in rows)),
        'outcomes': dict(Counter(row.get('outcome', 'unverified') for row in rows)),
        'failure_reasons': dict(Counter(reason for row in rows for reason in row.get('failure_reasons', []))),
        'totals': {key: sum(bool(row.get(key)) for row in rows) for key in
            ('slice_success', 'context_complete', 'plan_success', 'code_success',
             'compile_success', 'runtime_success', 'sanitizer_failed')},
        'costs': {key: sum(row.get(key, 0) for row in rows) for key in ('model_calls', 'tool_calls', 'source_chars')},
        'tokens': {key: sum(row.get('tokens', {}).get(key, 0) for row in rows) for key in
                  ('prompt_tokens', 'completion_tokens', 'total_tokens')},
        'sizes': {}, 'api_set_overlap': {}, 'certificates': {},
        'semantic_correctness': {dimension: dict(Counter(row.get('semantic_correctness', {})
            .get(dimension, {}).get('status', 'unverified') for row in rows))
            for dimension in evaluate.SEMANTIC_DIMENSIONS}}
    for key in ('slice_core_size', 'slice_support_size', 'slice_unresolved_size',
                'minimal_ft_core_size', 'minimal_ft_support_size', 'hard_gaps',
                'soft_unknowns', 'api_closure_size', 'elapsed_seconds'):
        values = [row[key] for row in rows if row.get(key) is not None]
        result['sizes'][key] = {'observations': len(values),
            'mean': statistics.mean(values) if values else None,
            'median': statistics.median(values) if values else None,
            'maximum': max(values) if values else None}
    for key in ('core_precision_recall', 'support_precision_recall'):
        scores = [row[key] for row in rows if row.get(key) is not None]
        counts = {name: sum(score[name] for score in scores) for name in ('tp', 'fp', 'fn')}
        result['api_set_overlap'][key] = dict(counts, observations=len(scores),
            micro_precision=counts['tp'] / (counts['tp'] + counts['fp']) if counts['tp'] + counts['fp'] else None,
            micro_recall=counts['tp'] / (counts['tp'] + counts['fn']) if counts['tp'] + counts['fn'] else None)
    rules = {rule for row in rows for rule in row.get('certificates', {})}
    for rule in sorted(rules):
        applied = [row for row in rows if row.get('certificates', {}).get(rule, {}).get('applied')]
        result['certificates'][rule] = {'applied_trials': len(applied),
            'cases': sorted({row['case'] for row in applied}),
            'statuses': dict(Counter(row.get('certificates', {}).get(rule, {}).get('status', 'unverified') for row in rows))}
    return result


def provider_observations(rows):
    observations = []
    patterns = ('candidate_discovery/agent_runs/*/trace.json', 'semantic_slices/*/trace.json',
                'harness_contexts/*/agent_runs/*/attempt_*/trace.json')
    for row in rows:
        statuses, phases, responses = set(), set(), set()
        root = Path(row['artifact_root']) / 'artifacts'
        for pattern in patterns:
            for path in root.glob(pattern):
                for index, event in enumerate(json.loads(path.read_text()).get('events', [])):
                    if event['kind'] == 'model_response':
                        responses.add(event.get('metadata', {}).get('response_id', str(path) + ':' + str(index)))
                    elif event['kind'] == 'model_error':
                        statuses.add(event.get('http_status') or 'unknown')
                        phases.add(event.get('phase', 'unknown'))
        observations.append({'case': row['case'], 'configuration': row['configuration'],
            'trial': row['trial'], 'set': row['set'], 'http_statuses': sorted(statuses, key=str),
            'error_phases': sorted(phases), 'model_responses': len(responses),
            'context_reached': row['context_status'] != 'not_run', 'context_status': row['context_status']})
    return observations


def enrich_report(path, result, aggregates):
    """Add aggregate denominators and an explicit audit boundary to raw rendering."""
    path = Path(path)
    text = path.read_text()
    rows = result['trials']
    groups = aggregates['by_set_and_configuration']
    fmt = lambda value: 'N/A' if value is None else f'{value:,.2f}'
    def insert_before(section, content):
        nonlocal text
        heading = f'## {section}. '
        at = text.index(heading)
        text = text[:at] + content + '\n\n' + text[at:]
    intro = (f"\n**正式 cohort：{len(rows)} 个 fresh native trials。** "
        f"Context complete {sum(row['context_complete'] for row in rows)}/{len(rows)}，"
        f"runtime success {sum(row['runtime_success'] for row in rows)}/{len(rows)}。"
        '以下结果使用原始 native 记录，另以独立 observational audit 恢复 supervisor 判读异常行的已保存阶段/成本；'
        '这些行的语义仍为 unverified。没有新增模型调用或重跑。\n')
    text = text.replace('## 1. Frozen implementation identity', intro + '\n## 1. Frozen implementation identity', 1)
    candidate = '\n补充按配置统计的阶段状态（invalid output 单列，可能与 verdict 重叠）：\n\n'
    candidate += '| Set / Config | Trials | Accepted | Unresolved | Rejected | Invalid output | Slice success | Context incomplete | Context invalid | Context not run |\n'
    candidate += '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n'
    for group, data in groups.items():
        counts = data['candidate_statuses']; context = data['context_statuses']
        candidate += f'| {group} | {data["trials"]} | ' + ' | '.join(str(counts.get(k, 0)) for k in ('accepted', 'unresolved', 'rejected'))
        candidate += f' | {data["candidate_invalid_output"]} | {data["totals"]["slice_success"]} | ' + ' | '.join(str(context.get(k, 0)) for k in ('incomplete', 'invalid', 'not_run')) + ' |\n'
    candidate += '\nSlice success 包含冻结实现的 completed_with_unresolved；不自动等于 CORE 完整。CORE/support 的空产物和未到达阶段单独记录。'
    candidate += 'Plan/code/compile/runtime 未执行的 trial 都进入端到端分母；条件编译成功率的分母只有实际编译尝试。\n'
    insert_before(8, candidate)
    availability = aggregates['provider_observations']
    provider = '\n提供商可用性（受影响 trial 数，多标签，可重叠）：\n\n'
    provider += '| Config | Native attempts | 有模型响应 | 无模型响应 | HTTP 400 | HTTP 429 | 无 provider error | 无 provider error 且进入 Context |\n'
    provider += '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n'
    for configuration in ('A', 'B', 'C'):
        selected = [item for item in availability if item['configuration'] == configuration]
        provider += f'| {configuration} | {len(selected)} | ' + ' | '.join(str(value) for value in (
            sum(item['model_responses'] > 0 for item in selected),
            sum(item['model_responses'] == 0 for item in selected),
            sum(400 in item['http_statuses'] for item in selected),
            sum(429 in item['http_statuses'] for item in selected),
            sum(not item['http_statuses'] for item in selected),
            sum(not item['http_statuses'] and item['context_reached'] for item in selected))) + ' |\n'
    provider += ('\nHTTP 429 在后段集中出现；已知只能确认服务端拒绝，原始 trace 没有足够信息区分具体限流/额度原因。'
        'HTTP 400 多见于冻结实现的 terminal repair。另有少量无 HTTP status 的请求错误。'
        '所有失败留在正式分母，未更换模型、凭证或重试。5 trials 指独立尝试数，不能解释为每个 case/config 有 5 次完整模型轨迹。'
        '无 provider error 的子集仅用于诊断，不能替代预注册成功率；该子集也没有 Context complete。\n')
    insert_before(8, provider)
    semantic = '\nAPI set overlap：仅对该阶段已保存产物计算 micro precision/recall，分母列明。未到达阶段不伪装成已验证契约。\n\n'
    semantic += '| Set / Config | API set | Observations | TP | FP | FN | Micro precision | Micro recall |\n| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |\n'
    for group, data in groups.items():
        for key, score in data['api_set_overlap'].items():
            semantic += f'| {group} | {key} | {score["observations"]} | {score["tp"]} | {score["fp"]} | {score["fn"]} | {fmt(score["micro_precision"])} | {fmt(score["micro_recall"])} |\n'
    semantic += '\nrequired support precision 是与预注册 required API 集合的重合度；额外合法 helper 并不因此成为语义错误。表中 incorrect 包含部分 Context 缺少必要事实，须结合 Gate 状态解读，不能直接视为 unsound success。\n'
    semantic += 'MPack 的合法 initializer_alternatives 由生命周期检查单独判断；原始 support-set overlap 未归一化这些替代 initializer，可能产生路线差异的 FP/FN。\n'
    insert_before(9, semantic)
    errors = result['posthoc']['recovered_trials']
    boundary = ('\n判读边界：原始 supervisor 有 ' + str(len(errors)) +
        ' 个 adjudication_error，原始记录及异常类型原样保留。独立 audit 只恢复阶段、成本、API 集合和规则命中；'
        '没有修复 callback checker，该行语义一律 unverified。恢复结果见 posthoc/summary.json 和 analysis_code.py；'
        '其 native_summary_sha256 可核对原始记录未被覆盖。\n\n'
        'blocked_conservatively 在汇总中指没有生成许可，包含前段退出和 provider failure，不能解释成每次都完成了语义证明。'
        'confirmed false_complete 需要 Gate 放行且独立审计证明 mandatory contract 错误；自动旗标本身不足以确认。'
        '若 complete 为零，条件 false-complete rate 为 N/A，没有检验 Gate 放行后的 soundness。\n')
    text = text.replace('confirmed false_complete |', '自动 false-complete flags（需审计） |')
    insert_before(10, boundary)
    costs = '\n大小指标：均值仅使用 observed artifacts，括号为观测数，未到达阶段为 N/A。\n\n'
    costs += '| Set / Config | Slice CORE | Slice SUPPORT | Slice unresolved | FT CORE | FT support candidates | Hard gaps | Soft unknowns | API closure |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n'
    for group, data in groups.items():
        costs += f'| {group} | ' + ' | '.join(
            f'{fmt(data["sizes"][key]["mean"])} ({data["sizes"][key]["observations"]})'
            for key in ('slice_core_size', 'slice_support_size', 'slice_unresolved_size',
                        'minimal_ft_core_size', 'minimal_ft_support_size', 'hard_gaps',
                        'soft_unknowns', 'api_closure_size')) + ' |\n'
    total = aggregates['all']
    costs += '\n全 cohort 已记录成本：model calls ' + str(total['costs']['model_calls'])
    costs += '，tool calls ' + str(total['costs']['tool_calls'])
    costs += '，prompt / completion / total tokens ' + ' / '.join(f'{total["tokens"][key]:,}'
        for key in ('prompt_tokens', 'completion_tokens', 'total_tokens')) + '。\n'
    costs += '\n完整尺寸分布、均值/中位数/最大值、分组状态与 micro 分母保存在 posthoc/aggregates.json。usage 缺失的失败请求不算零成本，实际账单无法从本实验推断。\n'
    insert_before(14, costs)
    pilot = ('\n基础设施限制：V1 pilot 因 build recipe 漏写 schema_version 而终止，20 个完成和 4 个中断 trial 全部保留并排除正式分母；'
        '修复评测接线后重新冻结并选用完全不同的 V2 集合。V1 callback-setter false-complete 自动旗标存在合法公开字段初始化替代路线，未经确认，不作为 Gate 缺陷证据。'
        'V2 evaluator 的 callback field=null 异常保持冻结，只追加上述独立观察审计。详见 [observed failures](BLIND_GENERALIZATION_OBSERVED_FAILURES.md)。\n')
    insert_before(15, pilot)
    limitations = (f'\n{sum(item["model_responses"] == 0 for item in availability)} 个 trial 未取得模型响应，'
        f'{sum(bool(item["http_statuses"]) for item in availability)} 个 trial 至少出现一次 provider error；'
        'A/B/C 取得响应的机会不同。因而本轮完成了预注册采样与保存，但没有完成每模式/配置 5 次无服务错误的语义稳定性验证。'
        '三组 completion 均为零，不能估计 construction certificates 的成功率增益，也不能把服务端错误归因于规则不覆盖。\n')
    insert_before(15, limitations)
    identity = [row for row in rows if row['configuration'] == 'C' and
                row['semantic_correctness']['resource_identity']['status'] == 'correct']
    callbacks = [row for row in rows if row['configuration'] == 'C' and
                 row['semantic_correctness']['callback']['status'] == 'correct']
    partial = ('\n局部必要-contract 检查：C 中 resource identity correct ' + str(len(identity)) +
        ' 个 trial，涉及 ' + ', '.join(sorted({row['case'] for row in identity})) + '；callback ABI/registration correct ' +
        str(len(callbacks)) + ' 个 trial，涉及 ' + ', '.join(sorted({row['case'] for row in callbacks})) + '。'
        '这些 Context 仍被 Gate 拦截，不能当作完整 API pattern 成功。规则命中只说明证据投影被应用，不自动等于整份语义契约正确。\n')
    insert_before(16, partial)
    text += '''

源码边界核对（静态设计分析，不能替代本轮未执行的 Plan/runtime）：

- `construction.zero_creator` 只接受无参数、单指针返回、函数体精确为 `return calloc(1, sizeof(T));`；其局部链还要求单 origin、单 cleanup、可证明的字段 consumer。带参数 creator、out initialization、helper allocation、refcount 和重复调用不会仅凭相近类型成为同一证书。
- `construction.public_callback_object` 明确拒绝嵌套 `field_path` 和非空 `setup_api`，并要求完整字段初始化及同步非逃逸。准确 callback ABI 与可构造 callback object 是两个独立判断；nested table、setter、pull reader 的 ABI 证据不能自动完成其构造或行为契约。
- `resource_identity.endpoint` 以 function/parameter/return 为键；多候选 creator identity 留为 unresolved。它不是任意调用实例与引用计数单位的模型。
- Plan 的 SUPPORT 能按显式 resource 重复，但 CORE 仍按 API 调度一次；多个 return resource 会触发明确的 alias 限制。三次 feed 和两个对象上的 CORE feed，需要比函数级 ordering 更细的调用实例证据。本轮未到达 Plan，因此这属于表示边界，不是已观察到的运行崩溃。
- NUL projection 要求已发布的 fuzz binding、明确 nul_terminate transform 与源码中限定的 libc/循环证据；不能由 char-pointer 类型或项目名直接完成。手写 lexer、间接输入和跨 helper string contract 可能停在 recognized proof subset 之外。

本轮 worker 的静态准备是函数/签名/body 解析；legacy SFG edges、annotations 和文档为空。现有 scoped source/value-flow 工具仍运行。所有配置相同，但这些结果不能解释成完整 legacy-SFG 分析或全仓库 Candidate discovery 的评价。
'''
    analysis_name = Path(result['posthoc']['analysis_directory']).name
    text = text.replace('posthoc/summary.json', analysis_name + '/summary.json')
    text = text.replace('posthoc/aggregates.json', analysis_name + '/aggregates.json')
    path.write_text(text)


def audit(native, output, report=None):
    native = Path(native).resolve()
    output = Path(output).resolve()
    summary_path = native / 'summary.json'
    before = digest(summary_path)
    raw = json.loads(summary_path.read_text())
    registration = raw['registration']
    if raw['completed_trials'] != registration['planned_trials'] or not raw.get('completed_at'):
        raise ValueError('native sampling must finish before post-hoc analysis')
    if not all(raw.get(key) is True for key in
               ('implementation_unchanged', 'evaluation_unchanged', 'benchmarks_unchanged')):
        raise ValueError('native cohort did not pass its final freeze checks')
    assert_frozen(native / 'freeze/manifest.json')
    benchmark = Path(registration['benchmark_directory'])
    if file_digest(benchmark) != registration['benchmark_digests']:
        raise ValueError('benchmarks differ from native registration')
    evaluation_dir = Path(evaluate.__file__).parent
    if file_digest(evaluation_dir) != registration['evaluation_code_digests']:
        raise ValueError('frozen evaluator differs from registration')
    cases = {}
    for name in ('synthetic_manifest.json', 'real_manifest.json'):
        cases.update({case['id']: case for case in
                      json.loads((benchmark / name).read_text())['cases']})
    extract = observational_extractor()
    rows, recovered = [], []
    for original in raw['trials']:
        if original.get('evaluation_status') != 'adjudication_error':
            rows.append(original)
            continue
        case = cases[original['case']]
        trial = native / 'trials' / (
            f"{original['case']}_{original['configuration']}_{original['trial']:02d}")
        truth = benchmark / Path(case['source_dir']).parent / 'ground_truth.json'
        row = extract(trial, truth, case, original['configuration'], original['trial'], None)
        row.update(evaluation_status='posthoc_observations_only',
                   original_evaluation_status='adjudication_error',
                   original_error_type=original['error_type'],
                   semantic_verified=False, false_complete=None,
                   false_complete_reasons=[], worker_exit_unavailable=True,
                   adjudication='stage/cost recovery only; semantic adjudication remains unverified')
        row['failure_reasons'] = sorted(set(row['failure_reasons']) | {'evaluation_error'})
        if row['context_complete']:
            row['outcome'] = 'unverified_evaluation_failure'
        recovered.append({'case': row['case'], 'configuration': row['configuration'],
                          'trial': row['trial'], 'pipeline_status': row['pipeline_status'],
                          'context_complete': row['context_complete'],
                          'original_error_type': original['error_type']})
        rows.append(row)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'freeze').mkdir()
    shutil.copyfile(native / 'freeze/manifest.json', output / 'freeze/manifest.json')
    result = dict(raw, trials=rows, posthoc={
        'version': 'blind-observational-audit-v2',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'native_summary_sha256': before, 'native_directory': str(native), 'analysis_directory': str(output),
        'analysis_code_sha256': digest(__file__), 'recovered_trials': recovered,
        'new_model_calls': 0, 'pipeline_retry': False, 'semantic_checker_repaired': False,
        'original_native_results_overwritten': False})
    (output / 'summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    aggregates = {'all': aggregate(rows), 'provider_observations': provider_observations(rows), 'by_set_and_configuration': {
        f'{dataset}/{configuration}': aggregate([row for row in rows
            if row['set'] == dataset and row['configuration'] == configuration])
        for dataset in ('blind_synthetic', 'blind_real') for configuration in ('A', 'B', 'C')}}
    (output / 'aggregates.json').write_text(json.dumps(aggregates, ensure_ascii=False, indent=2) + '\n')
    shutil.copyfile(__file__, output / 'analysis_code.py')
    if report:
        render(output, Path(report))
        enrich_report(report, result, aggregates)
    if digest(summary_path) != before:
        raise RuntimeError('native summary changed during analysis')
    assert_frozen(native / 'freeze/manifest.json')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    arguments = parser.parse_args()
    result = audit(arguments.native, arguments.output, arguments.report)
    print(json.dumps({'native_trials': result['completed_trials'],
                      'recovered_observations': len(result['posthoc']['recovered_trials']),
                      'new_model_calls': 0}, ensure_ascii=False))
