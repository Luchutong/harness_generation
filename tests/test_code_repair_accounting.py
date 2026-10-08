"""Registered bounded code correction accounting; no model/provider requests."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location('repair_accounting_' + name, PROJECT / 'scripts' / (name + '_fresh_stability.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


collector, auditor, runner = module('collect'), module('audit'), module('repeat')


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return path


def response(name, total=12):
    return {'response_id': name, 'model': 'offline', 'usage': {
        'prompt_tokens': total-2, 'completion_tokens': 2, 'total_tokens': total}}


def generation(root, second='response'):
    directory = root / 'context_generations/ft/plan/run'
    plan = {'plan_id': 'plan', 'frozen': True, 'language': 'c++'}
    put(directory.parent / 'harness_plan.json', plan)
    put(directory / 'harness_plan.json', plan)
    put(directory / 'response.json', response('first'))
    put(directory / 'code_validation.json', {'status': 'valid' if second == 'response' else 'invalid'})
    attempts = []
    for index in (1, 2):
        folder = directory / 'code_attempts' / f'attempt_{index:04d}'
        path = 'response.json' if index == 1 else 'code_attempts/attempt_0002/response.json'
        if index == 2 and second in {'response', 'duplicate'}:
            put(directory / path, response('first' if second == 'duplicate' else 'second', 12 if second == 'duplicate' else 21))
        success = index == 1 or second in {'response', 'duplicate'}
        put(folder / 'prompt.json', {'attempt': index})
        if success:
            put(folder / 'code_validation.json', {'status': 'invalid' if index == 1 else 'valid'})
            (folder / 'harness.cpp').write_text('code' + str(index))
        entry = {'attempt': index, 'model_call': True,
                 'status': 'invalid_code' if index == 1 else 'passed' if success else 'generation_failed',
                 'error': None if success else 'HTTP 503' if second == 'http' else 'Timeout' if second == 'timeout' else 'ValueError',
                 'error_category': None if success else 'timeout' if second == 'timeout' else 'ValueError',
                 'plan_digest': auditor.digest(plan), 'response_path': path if success else None,
                 'usage_known': success, 'file_digests': {str(item.relative_to(directory)): auditor.sha(item)
                    for item in folder.rglob('*') if item.is_file()}}
        if success:
            entry['file_digests'][path] = auditor.sha(directory / path)
        put(folder / 'attempt.json', entry)
        attempts.append(entry)
    metadata = {'status': attempts[-1]['status'], 'model_calls': 2, 'code_repairs': 1,
                'code_origin': 'model_translation', 'model_attempts': attempts,
                'configuration': {'max_code_repairs': 1, 'plan_digest': auditor.digest(plan)}}
    put(directory / 'metadata.json', metadata)
    (directory / 'harness.cpp').write_text('code2' if second in {'response', 'duplicate'} else 'code1')
    return directory, metadata


@pytest.mark.parametrize('second,known,total,failed,unknown', [
    ('response', 2, 33, 0, 0), ('duplicate', 1, 12, 0, 0),
    ('http', 1, 12, 1, 0), ('timeout', 1, 12, 1, 0), ('unknown', 1, 12, 0, 1)])
def test_both_code_calls_are_accounted_and_missing_usage_remains_unknown(tmp_path, second, known, total, failed, unknown):
    root = tmp_path / 'artifacts'
    generation(root, second)
    put(root.parent / 'trial.json', {'status': 'passed' if second in {'response', 'duplicate'} else 'context-generate_failed'})
    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    costs = auditor.cost_observations(root)
    row = collector.collect_trial(root)
    assert row['totals']['model_calls'] == costs['observed_agent_model_calls']['code'] == 2
    assert row['totals']['code_repairs'] == 1
    assert row['totals']['provider_responses'] == costs['successful_responses'] == known
    assert row['totals']['tokens']['total_tokens'] == costs['known_response_tokens']['total_tokens'] == total
    assert row['totals']['failed_requests'] == costs['failed_request_usage_unknown'] == failed
    assert row['totals']['unrecorded_codegen_calls'] == costs['unknown_request_attempts'] == unknown
    assert row['totals']['cost_is_lower_bound'] == costs['cost_is_lower_bound'] == bool(failed or unknown)
    if second == 'duplicate':
        assert costs['response_id_collisions'] == ['first']
    assert before == {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}


def test_complete_attempt_chain_checks_same_plan_caps_and_hashes(tmp_path):
    directory, metadata = generation(tmp_path)
    checks = auditor.code_attempt_checks(directory / 'metadata.json', metadata, 1)
    assert all(checks.values()), checks
    for mutation, failed in [
        (lambda d: d['model_attempts'][1].update(plan_digest='other'), 'code_attempt:2:plan_digest'),
        (lambda d: d.update(model_calls=1), 'code_attempt_model_calls'),
        (lambda d: d.update(code_repairs=0), 'code_repair_count'),
        (lambda d: d['model_attempts'][0].update(status='runtime_failed'), 'code_repair_trigger'),
        (lambda d: d['model_attempts'][1].update(response_path='response.json'), 'code_attempt:2:response_path'),
        (lambda d: d['model_attempts'][1].update(file_digests={'../outside': 'hash'}), 'code_attempt:2:hash_paths_safe'),
    ]:
        changed = deepcopy(metadata)
        mutation(changed)
        checks = auditor.code_attempt_checks(directory / 'metadata.json', changed, 1)
        assert checks[failed] is False
    assert auditor.code_attempt_checks(directory / 'metadata.json', metadata, 0)['code_attempt_bound'] is False
    (directory / 'response.json').write_text('changed')
    # Do not parse a corrupted response here: preserve a structurally valid but wrong hash.
    put(directory / 'response.json', response('tampered'))
    assert auditor.code_attempt_checks(directory / 'metadata.json', metadata, 1)['code_attempt:1:hashes_match'] is False


def test_accepted_final_code_and_validation_must_match_last_snapshot(tmp_path):
    directory, metadata = generation(tmp_path)
    (directory / 'harness.cpp').write_text('unrecorded code')
    checks = auditor.code_attempt_checks(directory / 'metadata.json', metadata, 1)
    assert checks['accepted_snapshot:harness.cpp'] is False
    put(directory / 'code_validation.json', {'status': 'invalid'})
    checks = auditor.code_attempt_checks(directory / 'metadata.json', metadata, 1)
    assert checks['accepted_code_validation'] is False
    assert checks['accepted_snapshot:code_validation.json'] is False


def test_legacy_single_code_call_remains_one_response_without_repair_metadata(tmp_path):
    root = tmp_path / 'artifacts'
    directory = root / 'context_generations/ft/plan/run'
    put(directory / 'metadata.json', {'model_calls': 1, 'code_origin': 'model_translation', 'status': 'invalid_code'})
    put(directory / 'response.json', response('legacy'))
    row, costs = collector.collect_trial(root), auditor.cost_observations(root)
    assert row['totals']['model_calls'] == costs['observed_agent_model_calls']['code'] == 1
    assert row['totals']['provider_responses'] == costs['successful_responses'] == 1
    assert row['totals']['tokens']['total_tokens'] == costs['known_response_tokens']['total_tokens'] == 12


def test_generation_configuration_compares_registered_code_repair_limit():
    config = {'max_code_repairs': 1, 'model': {'max_tokens': 8192, 'temperature': 0.2, 'timeout': 120.0}}
    row = {'stages': {'context-generate': {'configurations': [config]}}}
    assert collector.configuration_audit(row, {'max_code_repairs': 1})['all_observed_match'] is True
    assert collector.configuration_audit(row, {})['all_observed_match'] is False
    config['max_code_repairs'] = 0
    assert collector.configuration_audit(row, {})['all_observed_match'] is True


def test_repair_cli_is_bounded_and_explicit():
    assert runner.argument_parser().parse_args([]).max_code_repairs == 0
    assert runner.argument_parser().parse_args(['--max-code-repairs', '1']).max_code_repairs == 1
    with pytest.raises(SystemExit):
        runner.argument_parser().parse_args(['--max-code-repairs', '2'])


@pytest.mark.parametrize('limit,second_failure', [(0, False), (1, False), (1, True)])
def test_actual_translation_attempt_records_match_independent_chain_audit(tmp_path, limit, second_failure):
    from harness_generation.context_generation.code_repair import translate

    class Prompt:
        def save(self, path):
            put(path, {'prompt': 'offline'})

    class Generator:
        calls = 0

        def render(self, plan):
            return Prompt()

        def render_repair(self, plan, previous_code, diagnostics):
            assert previous_code == 'first code'
            assert diagnostics['status'] == 'invalid_code'
            return Prompt()

        def request(self, plan, prompt):
            self.calls += 1
            if self.calls == 2 and second_failure:
                raise ValueError('test local failure')
            doc = response('actual_' + str(self.calls))
            returned = SimpleNamespace(usage=doc['usage'], to_dict=lambda: doc)
            return returned

        def decode_response(self, response, plan):
            return ('first code' if self.calls == 1 else 'second code'), {
                'status': 'invalid' if self.calls == 1 else 'valid'}

    directory = tmp_path / 'context_generations/ft/plan/run'
    directory.mkdir(parents=True)
    plan = {'plan_id': 'plan', 'frozen': True, 'language': 'c++'}
    put(directory.parent / 'harness_plan.json', plan)
    put(directory / 'harness_plan.json', plan)
    status, calls, error, attempts = translate(directory, plan, Generator(), max_code_repairs=limit)
    metadata = {'status': status, 'model_calls': calls, 'error': error, 'code_repairs': max(calls-1, 0),
                'code_origin': 'model_translation', 'model_attempts': attempts,
                'configuration': {'max_code_repairs': limit, 'plan_digest': auditor.digest(plan)}}
    put(directory / 'metadata.json', metadata)
    checks = auditor.code_attempt_checks(directory / 'metadata.json', metadata, limit)
    assert all(checks.values()), checks
    row = collector.collect_trial(tmp_path)
    costs = auditor.cost_observations(tmp_path)
    assert row['totals']['model_calls'] == costs['observed_agent_model_calls']['code'] == 1+limit
    assert row['totals']['tokens'] == costs['known_response_tokens']
    assert row['totals']['unrecorded_codegen_calls'] == costs['unknown_request_attempts'] == int(second_failure)
