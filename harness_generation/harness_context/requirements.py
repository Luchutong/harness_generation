"""Mechanical questions from the frozen FT and Phase 1 signatures/types."""
import re

from ..semantic_discovery.models import digest
from ..semantic_slicing.frontier import function_types
from .models import REQUIREMENT_VERSION, POLICY_VERSION

QUESTIONS = {
    "input_binding": "Determine how fuzz bytes reach this API, directly or through a finite input path. Identify data/size, NUL, binary zero, mutability and alignment constraints.",
    "argument_construction": "Account for every parameter: input, derived length, constant, stack/zero initialization, creator, output storage or callback. Do not emit C expressions.",
    "buffer_length": "Determine actual buffer/length units, NUL-inclusive/exclusive, capacity and derived lengths from source; parameter names are not proof.",
    "lifecycle": "Determine creation, mandatory initialization and cleanup, reuse and ownership of context/handle/returned resources. Select source-issued support APIs in the corresponding action fields.",
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
    from .callbacks import callback_declarations
    identities = {e["parameter"] for e in callback_declarations(function, snapshot)}
    typedef_names = {t["name"] for t in snapshot.artifacts.callback_typedefs}
    identities.update(p["name"] for p in function.get("parameters", []) if p.get("base_type") in typedef_names)
    # Unparsed syntactic function pointers still create an obligation; unknown
    # ABI cannot disappear just because declaration resolution failed.
    identities.update(p["name"] for p in function.get("parameters", []) if "(*" in p.get("declaration", "").replace(" ", ""))
    for struct in snapshot.artifacts.structs:
        if typedef_names & set(re.findall(r"[A-Za-z_]\w*", struct["declaration"])):
            identities.update(p["name"] for p in function.get("parameters", []) if p["base_type"] in {struct["name"], *struct.get("aliases", [])})
    # A context merely carrying callbacks does not require construction when
    # this body only releases it through libc free. Never exempt a project
    # function with that spelling, or a body that accesses/calls anything else.
    from .value_flow import body_tree
    from ..semantic_discovery.tools import _walk, _text
    source, body = body_tree(function)
    if body and not body.has_error and not any(f["name"] == "free" for f in snapshot.functions.values()):
        calls = [n for n in _walk(body) if n.type == "call_expression"]
        if calls and all(_text(n.child_by_field_name("function"), source) == "free" for n in calls) and not any(n.type in {"field_expression", "assignment_expression"} for n in _walk(body)):
            identities -= {p["name"] for p in context_parameters(function)}
    return [p for p in function.get("parameters", []) if p["name"] in identities]


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
        # A required pointer-returning producer can carry fuzz input into a
        # later CORE consumer. Ask for that boundary explicitly; compatible
        # types alone do not prove an input path. Cleanup/support consumers do
        # not acquire a new independent fuzzer input obligation.
        producer_input = function.get("return_pointer_depth", 0) and any(
            p.get("is_pointer") and p.get("pointer_depth", 0) == 1
            and not (p.get("is_struct_like") or p.get("is_opaque_handle"))
            and p not in callback_parameters(function, snapshot) for p in params)
        kinds = ["input_binding"] if core or producer_input else []
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
        # Multiple upstream questions about one exact support API are one
        # investigation, retaining every question and parent. Unknown symbols
        # without an exact API identity remain separate obligations.
        mergeable = {r["function_id"] for r in ft["support_candidates"]} | {
            gap["function_id"] for gap in ft["unresolved_dependencies"] if gap["function_id"] is not None}
        merged, retained = {}, []
        for row in rows:
            if row["kind"] != "support_decision" or row["subject_function_id"] not in mergeable:
                retained.append(row)
                continue
            fid = row["subject_function_id"]
            entry = merged.setdefault(fid, {"parents": set(), "questions": set()})
            entry["parents"].update(row["required_by"])
            entry["questions"].add(row["question"])
        for fid, entry in sorted(merged.items()):
            retained.append(requirement(ft["ft_id"], fid, "support_decision", mandatory=False, depth=1,
                required_by=entry["parents"], question="\n".join(sorted(entry["questions"]))))
        rows = retained
        return {"schema_version": 1, "artifact_kind": "harness_requirements", "policy_version": POLICY_VERSION,
                "builder_version": REQUIREMENT_VERSION, "ft_id": ft["ft_id"],
                "minimal_ft_digest": digest(ft), "requirements": sorted(attach_basis(rows, ft), key=lambda r: (not r["mandatory"], r["subject_function_id"], r["kind"], r["requirement_id"]))}
