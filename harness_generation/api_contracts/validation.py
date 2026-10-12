"""Imported documentation, examples and model claims remain scoped proposals."""
from .models import APIContract


def validate_contract_proposals(contracts, snapshot, authorized_ids):
    if contracts is None:
        return [], []
    if isinstance(contracts, dict):
        contracts = contracts.get("contracts", [])
    if not isinstance(contracts, (tuple, list)) or len(contracts) > 256:
        return [], [{"kind": "api_contract_proposal_invalid", "detail": "at most 256 contract proposals"}]
    accepted, diagnostics = [], []
    for row in contracts:
        try:
            proposal = APIContract.proposal(row)
            if proposal.function_id not in set(authorized_ids) or proposal.function_id not in snapshot.functions:
                raise ValueError("api_contract_outside_authorized_scope")
            accepted.append(proposal.to_dict())
            diagnostics.append({"kind": "api_contract_proposal_unverified", "subject_id": proposal.function_id,
                                "contract_id": accepted[-1]["contract_id"], "detail": "Contract source and applicability require independent authentication."})
        except (ValueError, TypeError, KeyError) as error:
            diagnostics.append({"kind": "api_contract_proposal_invalid", "detail": str(error)})
    return accepted, diagnostics
