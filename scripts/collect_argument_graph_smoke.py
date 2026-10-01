#!/usr/bin/env python3
"""Collect immutable native development smoke results without model calls."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def collect(directory):
    path = directory / 'summary.json'
    summary = json.loads(path.read_text())
    if not summary['completed'] or not summary['implementation_unchanged']:
        raise ValueError('collect only completed, internally frozen smoke batches')
    rows = []
    for trial in summary['trials']:
        graph = next((g for g in summary['graphs'] if Path(g['artifact']).is_relative_to(Path(trial['artifacts']))),None)
        completeness=trial.get('context',{})
        metrics=trial.get('context_metrics',{'model_calls':0,'tool_calls':0})
        responses, failures, protocol, malformed = {}, {}, {}, {}
        validation_records=[]
        traces = Path(trial['artifacts']).rglob('trace.json')
        for trace in traces:
            # The root Context trace is a copy of its latest attempt. Errors
            # have no response ID, so counting both would double failed calls.
            if 'harness_contexts' in trace.parts and not trace.parent.name.startswith('attempt_'):
                continue
            meta_path=trace.with_name('metadata.json')
            meta=json.loads(meta_path.read_text()) if meta_path.exists() else {}
            if meta.get('group_cost_owner') is False:
                continue
            document = json.loads(trace.read_text())
            validation_records.extend(document.get('validation_errors', []))
            for index, event in enumerate(document.get('events', [])):
                key = str(trace.relative_to(trial['artifacts'])) + ':' + str(index)
                if event['kind'] == 'model_response':
                    responses[event['metadata']['response_id']] = event
                elif event['kind'] == 'model_error':
                    failures[key] = event
                elif event.get('error_category'):
                    protocol[key] = event
            for message in document.get('messages', []):
                for call in message.get('tool_calls', []):
                    arguments = call['function']['arguments']
                    try:
                        json.loads(arguments)
                    except (ValueError, TypeError):
                        digest = hashlib.sha256(str(arguments).encode()).hexdigest()
                        malformed[digest] = {'arguments_digest': digest,
                            'arguments_chars': len(arguments), 'tool_name': call['function']['name']}
        normalization = [e['metadata']['request_diagnostics'] for e in responses.values()
            if e['metadata'].get('request_diagnostics', {}).get('normalized_tool_history_count', 0)]
        rows.append({'case': trial['case'], 'status': trial['status'],
            'api_model':trial.get('api_model',trial['case']),'repetition':trial.get('repetition',1),
            'slice_status': trial['slice_status'], 'ft_status': trial['ft_status'],
            'minimal_ft_size': trial.get('minimal_ft_size'), 'core': trial.get('minimal_ft_core',[]),
            'context_complete': completeness.get('status') == 'complete',
            'generation_allowed': completeness.get('generation_allowed',False),
            'hard_gap_count': len(completeness.get('hard_missing',[])) if completeness else None,
            'hard_gap_codes': dict(Counter(x['code'] for x in completeness.get('hard_missing',[]))),
            'context_status':completeness.get('status','not_run'), 'validation_errors':completeness.get('validation_errors',[]),
            'proposal_validation_records':validation_records,
            'context_metrics': metrics,
            'actual_provider_responses': trial['actual_provider_responses'],
            'pipeline_tokens': trial['response_tokens'], 'served_models': trial['served_models'],
            'compile_success': trial['compile_success'], 'runtime_success': trial['runtime_success'],
            'graph_artifact': graph['artifact'] if graph else None, 'graph_nodes': graph['nodes'] if graph else 0, 'graph_edges': graph['edges'] if graph else 0,
            'graph_resolved_parameters': graph['resolved_parameters'] if graph else 0, 'graph_holes': graph['holes'] if graph else [],
            'graph_visible_in_saved_prompts': graph['graph_visible_in_saved_prompts'] if graph else False,
            'canonical_parameters':graph.get('canonical_parameters',[]) if graph else [],
            'canonical_active_parameters':graph.get('canonical_active_parameters',[]) if graph else [],
            'reconciliation_diagnostics':graph.get('reconciliation_diagnostics',[]) if graph else [],
            'failed_requests': [e for e in failures.values() if e.get('error_category')!='budget_exhausted'],
            'local_budget_stops': [e for e in failures.values() if e.get('error_category')=='budget_exhausted'],
            'request_error_counts': dict(Counter(e['error_category'] for e in failures.values() if e.get('error_category')!='budget_exhausted')),
            'protocol_events': list(protocol.values()),
            'malformed_original_tool_calls': list(malformed.values()),
            'normalized_history_successful_requests': normalization,
            'execution_failed_requirement_count': len(completeness.get('execution_failed_requirements',[]))})
    return {'source_directory': str(directory), 'native_summary_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'registration': summary['registration'], 'trials': rows,
        'totals': {'trials': len(rows), 'contexts_complete': sum(r['context_complete'] for r in rows),
            'compile_success': sum(r['compile_success'] for r in rows),
            'runtime_success': sum(r['runtime_success'] for r in rows),
            'pipeline_tokens': sum(r['pipeline_tokens']['total_tokens'] for r in rows),
            'graph_artifacts': sum(r['graph_artifact'] is not None for r in rows),
            'graph_visible_trials': sum(r['graph_visible_in_saved_prompts'] for r in rows)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--smoke-dir', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    batches = [collect(directory.resolve()) for directory in args.smoke_dir]
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'summary.json').write_text(json.dumps({'category': 'observational_development_smoke_collection',
        'blind_generalization_evidence': False, 'batches': batches}, ensure_ascii=False, indent=2) + '\n')
    report = ['# Native Argument Graph smoke collection', '',
        'Development / Regression only. Different production fingerprints are reported separately.', '']
    for batch in batches:
        report += ['## ' + Path(batch['source_directory']).name, '',
            'Production fingerprint: `' + batch['registration']['production_fingerprint'] + '`', '',
            '| Case | Context | Hard gaps | Graph resolved / holes | Context model / tools | Pipeline tokens | Compile / runtime | Request errors |',
            '| --- | --- | --- | --- | --- | --- | --- | --- |']
        for row in batch['trials']:
            metrics = row['context_metrics']
            report.append(f"| {row['case']} | {row['context_complete']} | {row['hard_gap_count']} | "
                f"{row['graph_resolved_parameters']} / {len(row['graph_holes'])} | "
                f"{metrics['model_calls']} / {metrics['tool_calls']} | {row['pipeline_tokens']['total_tokens']} | "
                f"{row['compile_success']} / {row['runtime_success']} | {row['request_error_counts']} |")
        report += ['', 'Totals: `' + json.dumps(batch['totals'], sort_keys=True) + '`', '']
    (args.output / 'report.md').write_text('\n'.join(report) + '\n')


if __name__ == '__main__':
    main()
