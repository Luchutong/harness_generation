"""Stable three-valued diagnostics shared by execution plan consumers."""
from ..api_contracts.models import ContractStatus


def check(code, *, status=ContractStatus.UNKNOWN, step_id="", detail="", **facts):
    return {"code": code, "status": ContractStatus(status).value, "step_id": step_id,
            "detail": str(detail), **facts}


def unknown(kind, subject_id="", detail="", **facts):
    return {"kind": kind, "status": ContractStatus.UNKNOWN.value, "subject_id": subject_id,
            "detail": str(detail), "source_proven": False, **facts}
