"""Offline definitions for explicit revocation at the requirement resume boundary.

These definitions were authored while testing is paused and are not executed.
"""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from harness_generation.harness_context import persistence
from harness_generation.harness_context.callback_resources import VERSION as CALLBACK_RESOURCE_VERSION
from harness_generation.harness_context.closure_feedback import VERSION as CLOSURE_FEEDBACK_VERSION
from harness_generation.harness_context.models import POLICY_VERSION
from harness_generation.harness_context.repair_transactions import VERSION as TRANSACTION_VERSION
from harness_generation.harness_context.transaction_support import VERSION as SOURCE_SUPPORT_VERSION


def cached_requirement(tmp_path, monkeypatch, *, status="resolved", mandatory=True,
                       metadata=None, preserve_soft_unknown=False):
    store = SimpleNamespace(root=tmp_path,
        minimal_ft_run=lambda identity: tmp_path / "minimal_fts" / identity)
    requirement = {"requirement_id": "req_offline", "mandatory": mandatory}
    loaded = {"metadata": deepcopy(metadata or {}),
        "result": {"requirement_id": requirement["requirement_id"], "status": status}}
    monkeypatch.setattr(persistence, "load_run_documents", lambda *_args: deepcopy(loaded))
    monkeypatch.setattr(persistence, "_valid_revision_transaction", lambda *_args: True)
    return persistence.load_requirement(store, "ft_offline", requirement,
        {"policy_version": POLICY_VERSION}, SimpleNamespace(),
        preserve_soft_unknown=preserve_soft_unknown)


@pytest.mark.parametrize("status,mandatory,preserve", [
    ("resolved", True, False), ("not_applicable", True, False), ("unresolved", False, True),
])
def test_revoked_requirement_cannot_resume_without_a_generic_failure_marker(
        tmp_path, monkeypatch, status, mandatory, preserve):
    assert cached_requirement(tmp_path, monkeypatch, status=status, mandatory=mandatory,
        preserve_soft_unknown=preserve, metadata={"submission_revoked": True,
            "submission_revocation_reason": "dsh_cleanup_error"}) is None


@pytest.mark.parametrize("metadata", [{}, {"submission_revoked": False},
    {"execution_status": "answered", "execution_errors": [{"error_category": "timeout"}]}])
def test_accepted_requirement_with_recovered_historical_errors_remains_eligible(
        tmp_path, monkeypatch, metadata):
    loaded = cached_requirement(tmp_path, monkeypatch, metadata=metadata)
    assert loaded["result"]["status"] == "resolved"


def test_explicit_failed_requirement_remains_ineligible_without_revocation(tmp_path, monkeypatch):
    assert cached_requirement(tmp_path, monkeypatch,
        metadata={"resolution_attempt_failed": "protocol_error"}) is None


def test_policy_version_invalidates_contexts_created_before_initial_submission_guard(monkeypatch):
    monkeypatch.setattr(persistence, "context_directory",
        lambda *_args: pytest.fail("old policy must be rejected before cache access"))
    assert POLICY_VERSION == "source-grounded-harness-context-v18"
    assert persistence.load_context_documents(SimpleNamespace(), "ft_offline",
        {"policy_version": "source-grounded-harness-context-v17",
         "callback_resource_reference_version": CALLBACK_RESOURCE_VERSION,
         "closure_feedback_version": CLOSURE_FEEDBACK_VERSION,
         "context_revision_transaction_version": TRANSACTION_VERSION,
         "native_submission_version": "native-typed-submission-v1",
         "context_transaction_source_support_version": SOURCE_SUPPORT_VERSION},
        SimpleNamespace()) is None
