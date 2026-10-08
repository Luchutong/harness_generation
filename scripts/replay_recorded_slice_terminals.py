#!/usr/bin/env python3
"""Revalidate recorded json Slice terminals against freshly reconstructed issued choices.

Offline validation only. No model/provider invocation, persisted facts, source
changes or success-rate claims. The recorded artifacts remain read-only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness_generation.artifacts import ArtifactStore
from harness_generation.semantic_discovery.models import ValidationBudget, canonical
from harness_generation.semantic_discovery.tools import RepositoryIndex
from harness_generation.semantic_slicing import SemanticSliceTools, build_frontier
from harness_generation.semantic_slicing.models import ClassificationSchemaError, validate_submission
from harness_generation.semantic_slicing.proposals import choices
from harness_generation.sfg_adapter import load_sfg_artifacts


def read(path):
    return json.loads(Path(path).read_text())


def replay(root, trial_id):
    artifacts = root / trial_id / 'artifacts'
    store = ArtifactStore(artifacts)
    catalog = store.load_candidate_catalog()
    source = load_sfg_artifacts(artifacts)
    candidate = next(c for c in catalog.candidates if c.function_id == 'json.c:1125:json_parse')
    validation = next(r['validation'] for r in read(store.validated_candidates)['candidates']
                      if r['function_id'] == candidate.function_id)
    trace = read(next(store.semantic_slices_directory.glob('*/trace.json')))
    frontier = build_frontier(store, source, catalog, candidate, validation)
    index = RepositoryIndex(source, catalog, functions_path=store.functions)
    tools = SemanticSliceTools(source, catalog, frontier, ValidationBudget(), index=index)
    outcomes, event_index = [], 0
    events = trace['events']
    # Replay actual observations in message order, before each native terminal.
    for message in trace['messages']:
        if message['role'] != 'assistant':
            continue
        for call in message.get('tool_calls', []):
            function = call['function']
            if function['name'] == 'submit_semantic_slice':
                if not call['id'] in {e.get('tool_call_id') for e in events if e['kind'] == 'decision_submission'}:
                    continue  # Truncated calls were explicitly never executed.
                document = json.loads(function['arguments'])
                issued = {r['choice_id']: r for r in choices(tools)}
                assert all(row['choice_id'] in issued for row in document['classification'])
                try:
                    validate_submission(function['arguments'], tools)
                except ClassificationSchemaError as error:
                    outcomes.append({'tool_call_id': call['id'], 'accepted': False,
                                     'all_choices_source_issued': True, 'diagnostics': error.to_dict()})
                else:
                    raise AssertionError('Recorded invalid terminal was unexpectedly accepted')
                # Demonstrate explicit bounded shape correction, retaining each
                # existing unresolved role rather than inventing a decisive role.
                retained = {}
                for row in document['classification']:
                    signed = issued[row['choice_id']]
                    fid = signed['function_id']
                    if fid not in retained or signed['role'] == 'unresolved':
                        retained[fid] = row
                corrected = []
                for fid, original in retained.items():
                    row = dict(original)
                    if issued[row['choice_id']]['role'] == 'unresolved' and not row['open_questions']:
                        row['open_questions'] = [f'Which complete source establishes {fid} as an independent input/state dependency of json.c:1125:json_parse?']
                    corrected.append(row)
                accepted = validate_submission(canonical({'classification': corrected}), tools)
                outcomes[-1]['explicit_offline_shape_correction_valid'] = True
                outcomes[-1]['roles_after_explicit_correction'] = {r['function_id']: r['role'] for r in accepted['classification']}
                continue
            observed = next((e for e in events[event_index:] if e['kind'] == 'tool_call'
                             and e.get('tool_call_id') == call['id']), None)
            if observed is None:
                continue
            event_index = events.index(observed, event_index) + 1
            arguments = json.loads(function['arguments'])
            if observed.get('framework_bootstrap'):
                output = tools._frontier(arguments, page_size=1)
            else:
                output = tools.execute(function['name'], arguments)
            assert set(output['evidence_ids']) == set(observed['result_evidence_ids'])
    return {'trial_id': trial_id, 'offline_only': True, 'no_model_calls': True,
            'recorded_submissions': outcomes, 'replayed_source_chars': tools.source_chars,
            'note': 'Explicit correction illustrates validator behavior; it is not a new native run or automatic repair.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = {'schema_version': 1, 'category': 'offline_recorded_source_issued_slice_validation',
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'trials': [replay(args.experiment_root.resolve(), name) for name in ('json_parse_r01', 'json_parse_r04')]}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'trials': [{'trial_id': r['trial_id'], 'submissions': len(r['recorded_submissions']),
                                 'error_counts': [len(s['diagnostics']['errors']) for s in r['recorded_submissions']]}
                                for r in result['trials']], 'model_calls': 0}))


if __name__ == '__main__':
    main()
