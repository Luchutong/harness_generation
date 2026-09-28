"""Mechanical questions from the frozen FT and Phase 1 signatures/types."""
import re

from ..semantic_discovery.models import digest
from ..semantic_slicing.frontier import function_types
from .models import REQUIREMENT_VERSION, POLICY_VERSION

QUESTIONS = {
    "input_binding": "Determine how fuzz bytes reach this API, directly or through a finite input path. Identify data/size, NUL, binary zero, mutability and alignment constraints.",
    "argument_construction": "Account for every parameter: input, derived length, constant, stack/zero initialization, creator, output storage or callback. Do not emit C expressions.",
    "buffer_length": "Determine actual buffer/length units, NUL-inclusive/exclusive, capacity and derived lengths from source; parameter names are not proof.",
    "lifecycle": "Determine creation, mandatory initialization and cleanup, reuse and ownership of context/handle/returned resources. Propose required API dependencies explicitly.",
    "return_semantics": "Determine the success/failure distinction, pointer nullability and ownership, and cleanup required on an error result.",
    "ownership": "Determine owned/borrowed/transferred/static lifetime for pointer parameters, input references, outputs and returned pointers; identify required release APIs.",
    "call_order": "Determine minimal evidenced ordering of CORE and required support, including creation/init before use and cleanup after use; shared types do not prove ordering.",
    "callback": "Determine callback ABI/signature, mandatory/optional status, setup, userdata, lifetime and null/default behavior.",
    "state": "Determine minimal context state preconditions, including initialization, feed or reset, without reconstructing a global state machine.",
    "support_decision": "Determine whether this candidate is required, optional, rejected or unresolved for the target. Cite concrete target dependence, not shared type/name similarity.",
}


def attach_basis(rows, ft):
    identities = {row["function_id"]: row for row in ft["core_functions"] + ft["support_candidates"]}
    for row in rows:
        fid = row["subject_function_id"]
        row["basis"] = {"source_slice": ft["source_slice"],
            "relation_ids": sorted(relation["relation_id"] for relation in ft["relations"]
                if fid in {relation["source_function_id"], relation["target_function_id"]}),
            "slice_evidence_ids": sorted(identities.get(fid, {}).get("evidence_ids", []))}
    return rows


def context_parameters(function):
    return [p for p in function.get("parameters", []) if p.get("is_struct_like") or p.get("is_opaque_handle")]


def callback_parameters(function, snapshot):
    types = function_types(function)
    declarations = [s["declaration"] for s in snapshot.artifacts.structs
                    if types & {s["name"], *s.get("aliases", [])}]
    callbacks = [p for p in function.get("parameters", []) if "(*" in p.get("declaration", "").replace(" ", "")]
    if any(re.search(r"\(\s*\*\s*\w+\s*\)", declaration) for declaration in declarations):
        callbacks.extend(context_parameters(function))
    return callbacks


def requirement(ft_id, fid, kind, *, mandatory=True, depth=0, required_by=(), discriminator="", question=None):
    identity = {"ft_id": ft_id, "function_id": fid, "kind": kind, "discriminator": discriminator,
                "builder_version": REQUIREMENT_VERSION}
    return {"requirement_id": "req_" + digest(identity)[:24], "subject_function_id": fid, "kind": kind,
            "status": "open", "mandatory": mandatory, "question": question or QUESTIONS[kind],
            "evidence_ids": [], "dependency_depth": depth, "required_by": sorted(set(required_by))}


class HarnessRequirementBuilder:
    def function_requirements(self, ft, snapshot, fid, *, depth=0, required_by=(), core=True):
        function = snapshot.functions[fid]
        params = function.get("parameters", [])
        kinds = ["input_binding"] if core else []
        if params:
            kinds.append("argument_construction")
        if any(p.get("is_pointer") and not p.get("is_struct_like") for p in params):
            kinds.append("buffer_length")
        if (core and context_parameters(function)) or function.get("return_pointer_depth", 0):
            kinds.append("lifecycle")
        if any(p.get("is_pointer") for p in params) or function.get("return_pointer_depth", 0):
            kinds.append("ownership")
        if function.get("return_type", "void").strip() != "void":
            kinds.append("return_semantics")
        if core and context_parameters(function):
            kinds.append("state")
        if callback_parameters(function, snapshot):
            kinds.append("callback")
        if core and (len(ft["core_functions"]) > 1 or ft["support_candidates"]):
            kinds.append("call_order")
        strong = [relation for relation in ft["relations"] if relation["strength"] == "strong"
                  and relation["kind"] == "shares_resource" and fid in {relation["source_function_id"], relation["target_function_id"]}]
        if core and strong:
            kinds.extend(kind for kind in ("lifecycle", "ownership", "call_order") if kind not in kinds)
        return attach_basis([requirement(ft["ft_id"], fid, kind, depth=depth, required_by=required_by) for kind in kinds], ft)

    def build(self, ft, snapshot):
        rows = []
        core_ids = [r["function_id"] for r in ft["core_functions"]]
        for fid in sorted(core_ids):
            rows.extend(self.function_requirements(ft, snapshot, fid))
        for support in ft["support_candidates"]:
            rows.append(requirement(ft["ft_id"], support["function_id"], "support_decision", mandatory=False,
                                    depth=1, required_by=core_ids))
        for gap in ft["unresolved_dependencies"]:
            fid = gap["function_id"] or ft["anchor_function_id"]
            rows.append(requirement(ft["ft_id"], fid, "support_decision", mandatory=False,
                discriminator=digest(gap), required_by=core_ids,
                question="Investigate this explicit upstream unknown conservatively: " + "; ".join(gap["questions"])))
        return {"schema_version": 1, "artifact_kind": "harness_requirements", "policy_version": POLICY_VERSION,
                "builder_version": REQUIREMENT_VERSION, "ft_id": ft["ft_id"],
                "minimal_ft_digest": digest(ft), "requirements": sorted(attach_basis(rows, ft), key=lambda r: (not r["mandatory"], r["subject_function_id"], r["kind"], r["requirement_id"]))}
