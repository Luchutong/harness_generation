"""Source-bound semantic obligations and conservative AND dependency closure.

The agent proposes existing typed facts. Only this deterministic projection can
produce nodes, dependencies and proof statuses. The graph is separate from the
Context projection so neither becomes a circular input to the other's proof.
"""
from copy import deepcopy

from ..semantic_discovery.models import canonical, digest

VERSION = "semantic-obligation-graph-v3"


def input_digests(context, closure, ft, requirements, resolutions, evidence):
    # Freezing is the outcome of closure, not a premise of the proof.
    return {"minimal_ft": digest(ft),
        "harness_context": digest({k: v for k, v in context.items() if k != "frozen"}),
        "api_closure": digest(closure), "requirements": digest(sorted(requirements, key=canonical)),
        "resolutions": digest(resolutions), "evidence": digest(evidence)}


def close_obligations(nodes, roots):
    """Least fixed point: cycles, missing dependencies and claims never self-prove."""
    rows = deepcopy(nodes)
    by_id = {n["obligation_id"]: n for n in rows}
    errors = []
    if len(by_id) != len(rows):
        errors.append({"code": "duplicate_obligation_identity"})
    for node in rows:
        if node["local_proof"]["status"] not in {"proved", "not_applicable", "missing", "contradicted"}:
            errors.append({"code": "invalid_local_proof_status", "obligation_id": node["obligation_id"]})
        for dep in node["dependencies"]:
            if dep["obligation_id"] not in by_id:
                errors.append({"code": "obligation_dependency_missing", "obligation_id": node["obligation_id"],
                    "dependency_id": dep["obligation_id"]})
    for root in roots:
        if root not in by_id:
            errors.append({"code": "obligation_root_missing", "obligation_id": root})
    closed = set()
    for _ in range(len(rows) + 1):
        additions = {nid for nid, node in by_id.items() if node["local_proof"]["status"] in {"proved", "not_applicable"}
            and all(dep["obligation_id"] in closed for dep in node["dependencies"])} - closed
        if not additions:
            break
        closed |= additions

    cycles = set()
    def leaves(nid, path):
        if nid in closed:
            return set()
        if nid in path:
            cycle = tuple(sorted(path[path.index(nid):]))
            cycles.add(cycle)
            return set(cycle)
        node = by_id.get(nid)
        if not node:
            return {nid}
        # A missing local proof is an actionable frontier even if dependencies
        # are also missing. Retain both; proving one cannot hide the other.
        result = {nid} if node["local_proof"]["status"] not in {"proved", "not_applicable"} else set()
        for dep in node["dependencies"]:
            result |= leaves(dep["obligation_id"], path + [nid])
        return result

    for node in rows:
        nid, local = node["obligation_id"], node["local_proof"]["status"]
        node["proof_status"] = ("proved" if nid in closed else "contradicted" if local == "contradicted"
            else "missing" if local == "missing" else "blocked")
        node["blocking_obligations"] = sorted(leaves(nid, []))
    errors += [{"code": "semantic_obligation_cycle", "obligation_ids": list(cycle)} for cycle in sorted(cycles)]
    frontier = sorted(set().union(*(leaves(root, []) for root in roots)) if roots else set())
    return {"nodes": sorted(rows, key=lambda n: n["obligation_id"]), "mandatory_roots": sorted(set(roots)),
        "closed_roots": sorted(set(roots) & closed), "open_roots": sorted(set(roots) - closed),
        "frontier": frontier, "diagnostics": sorted(errors, key=canonical)}


class SemanticObligationGraphBuilder:
    def build(self, context, closure, ft, snapshot, requirements, resolutions, state):
        from .semantic_proofs import SemanticProofEvaluator
        from .api_closure import callable_status
        audit = SemanticProofEvaluator().evaluate(context, closure, ft, snapshot, requirements, resolutions, state)
        nodes, roots, coverage = {}, set(), []
        reqs = {(r["subject_function_id"], r["kind"]): r for r in requirements}
        framework = set(audit["framework_satisfied_requirements"])
        failures = {}
        for failure in audit["failures"]:
            failures.setdefault(failure["requirement_id"], []).append(failure)

        def add(fid, kind, predicate, *, req=None, parameter=None, resource=None, qualifier=None, field=None,
                status="proved", evidence=(), facts=(), sources=(), diagnostics=(), question=None):
            identity = {"function_id": fid, "kind": kind, "predicate": predicate,
                "requirement_id": req["requirement_id"] if req else None,
                "parameter": parameter, "resource_id": resource, "qualifier": qualifier, "field": field}
            nid = "obligation_" + digest(identity)[:24]
            if nid not in nodes:
                nodes[nid] = {"obligation_id": nid, "requirement_id": identity["requirement_id"],
                    "subject_function_id": fid, "kind": kind, "predicate": predicate,
                    "subject_parameter": parameter, "resource_id": resource, "subject_field": field,
                    "question": question or (req["question"] if req else predicate),
                    "evidence_ids": sorted(set(evidence)), "fact_ids": sorted(set(facts)),
                    "local_proof": {"status": status, "sources": sorted(sources, key=canonical)},
                    "dependencies": [], "diagnostics": sorted(deepcopy(diagnostics), key=canonical)}
            return nid

        def depend(nid, dep, relation):
            edge = {"obligation_id": dep, "relation": relation}
            if edge not in nodes[nid]["dependencies"]:
                nodes[nid]["dependencies"].append(edge)

        req_nodes = {}
        for req in sorted(requirements, key=canonical):
            rid = req["requirement_id"]
            facts = [f for f in context["facts"] if f["requirement_id"] == rid]
            grounded = bool(facts) and req["status"] in {"resolved", "not_applicable"}
            local_failures = failures.get(rid, [])
            status = "proved" if grounded or rid in framework else "missing"
            # Collection roots aggregate exact subject proofs. A gap for one
            # parameter must not retract unrelated subjects in that slot.
            granular = req["kind"] in {"ownership", "argument_construction"}
            aggregate_failures = [f for f in local_failures if not granular or f.get("subject_parameter") is None
                and f["code"] not in {"parameter_ownership_unresolved", "return_ownership_unresolved", "out_pointee_ownership_unresolved",
                    "argument_construction_unresolved", "mandatory_requirement_unresolved", "ownership_unresolved"}]
            if granular:
                status = "proved"
            if aggregate_failures:
                status = "contradicted" if any("conflict" in f["code"] or "mismatch" in f["code"] for f in aggregate_failures) else "missing"
            if status == "proved" and req["status"] == "not_applicable":
                status = "not_applicable"
            sources = [{"kind": "validated_semantic_proposal", "fact_id": f["fact_id"]} for f in facts]
            proofs = [p for p in context["framework_satisfied_requirements"] if p["requirement_id"] == rid]
            sources += [{"kind": "recomputed_framework_projection", "proof": p} for p in proofs]
            nid = add(req["subject_function_id"], req["kind"], req["kind"], req=req, status=status,
                evidence=[e for f in facts for e in f["evidence_ids"]] + [e for p in proofs for e in p.get("evidence_ids", [])],
                facts=[f["fact_id"] for f in facts], sources=sources, diagnostics=aggregate_failures)
            req_nodes[(req["subject_function_id"], req["kind"])] = nid
            if req["mandatory"] or local_failures:
                roots.add(nid)

        # Some safety predicates have no pre-existing agent requirement. They
        # remain explicit mandatory obligations rather than being dropped.
        for failure in failures.get(None, []):
            fid, kind = failure["subject_function_id"], failure["kind"]
            nid = add(fid, kind, failure["code"], qualifier=failure, status="missing", diagnostics=[failure],
                question=failure["question"], parameter=failure.get("subject_parameter"))
            roots.add(nid)

        active = set(context["core_apis"]) | {r["function_id"] for r in closure["required_support_apis"]}
        owners = {}
        from .proposals import ownership_subjects, ownership_subject
        for fid in sorted(active):
            req = reqs.get((fid, "ownership"))
            for subject in ownership_subjects(fid, snapshot):
                matches = [r for r in context["ownership_contract"]["entries"] if r["function_id"] == fid
                    and ownership_subject(r, fid, snapshot)["subject_id"] == subject["subject_id"]]
                # The signed catalog also offers optional pointer-field
                # subjects; a field is not automatically a separately owned
                # Resource. Actual pointer parameters/returns/out pointees are
                # mandatory, and submitted field subjects are checked as well.
                if subject["subject_kind"] == "ResourceObject" and not matches:
                    continue
                parameter = subject["parameter"]
                diagnostics = [f for f in failures.get(req["requirement_id"] if req else None, [])
                    if f.get("subject_parameter") == parameter and f["code"] != "mandatory_requirement_unresolved"]
                known = bool(matches) and all(r["ownership"] != "unknown" and r["lifetime"] != "unknown" for r in matches)
                status = "proved" if known and not diagnostics else "missing"
                if any(d["code"] in {"ownership_escape_lifetime_conflict", "cleanup_object_or_path_conflict", "subject_repair_conflict"}
                        for d in diagnostics):
                    status = "contradicted"
                nid = add(fid, "ownership", "ownership_subject", req=req, parameter=parameter, field=subject.get("field"),
                    qualifier=subject["subject_id"], status=status,
                    evidence=[e for r in matches for e in r["evidence_ids"]], facts=[r["fact_id"] for r in matches if r.get("fact_id")],
                    sources=[{"kind": "declared_ownership_subject", "subject_id": subject["subject_id"],
                        "subject_kind": subject["subject_kind"]}, {"kind": "source_checked_ownership_projection",
                        "semantic_fact_ids": [r["fact_id"] for r in matches if r.get("fact_id")],
                        "framework_sources": [s['construction_id'] for s in context['construction_contract']['sources']
                            if s['function_id']==fid and s.get('parameter')==parameter and s.get('verified')]}], diagnostics=diagnostics,
                    question="Prove allocation/borrowing, escape and lifetime of this exact declared pointer subject.")
                owners[fid, parameter, subject["subject_kind"], subject.get("field")] = nid
                coverage.append({"kind": "ownership_subject", "function_id": fid, "subject_id": subject["subject_id"], "obligation_id": nid})
                if req:
                    depend(req_nodes[fid, "ownership"], nid, "required_pointer_subject")
        ready = {}
        from .value_flow import complete_bodies
        issued_bodies = complete_bodies(snapshot, state.evidence)
        def api_ready(fid):
            if fid in ready:
                return ready[fid]
            evidence = sorted(issued_bodies.get(fid, ()))
            available = fid in active and fid in snapshot.functions and callable_status(snapshot.functions[fid]) == "external_definition"
            api = add(fid, "api_closure", "api_source_available", status="proved" if available and evidence else "missing",
                evidence=evidence, sources=[{"kind": "source_definition", "active": fid in active}],
                question="Prove that this exact API has an issued complete callable definition and belongs to the required closure.")
            nid = add(fid, "invocation", "api_invocation_proved", sources=[{"kind": "required_api_obligations"}])
            ready[fid] = nid
            if fid in active:
                coverage.append({"kind": "api_invocation", "function_id": fid, "obligation_id": nid})
            depend(nid, api, "callable_source")
            # Lifecycle describes resources supplied by callers; requiring it
            # recursively here would conflate a release call with construction.
            for kind in ("argument_construction", "ownership", "return_semantics", "buffer_length", "state", "callback"):
                if (fid, kind) in req_nodes:
                    depend(nid, req_nodes[(fid, kind)], "invocation_" + kind)
            return nid

        # Parameter recipes stay separate, allowing callback userdata to depend
        # on its own construction without cycling through callback ABI setup.
        recipes = {}
        parameters = context["canonical_construction"]["parameters"]
        for fid in sorted(active):
            for index, parameter in enumerate(snapshot.functions[fid]["parameters"]):
                if not any(r["function_id"] == fid and r["parameter"] == parameter["name"] for r in parameters):
                    from .argument_graph import parameter_id
                    req = reqs.get((fid, "argument_construction"))
                    pid = parameter_id(fid, index)
                    recipes[pid] = add(fid, "argument_construction", "parameter_recipe", req=req,
                        parameter=parameter["name"], status="missing", question="Prove construction of this declared required parameter.")
                    coverage.append({"kind": "parameter_recipe", "function_id": fid, "parameter": parameter["name"], "obligation_id": recipes[pid]})
                    if req:
                        depend(req_nodes[fid, "argument_construction"], recipes[pid], "parameter_constructible")
        for row in parameters:
            if row["function_id"] not in active:
                continue
            recipe = row.get("recipe") or {}
            req = reqs.get((row["function_id"], "argument_construction"))
            diagnostics = [f for f in failures.get(req["requirement_id"] if req else None, [])
                if f.get("subject_parameter") == row["parameter"]]
            status = "proved" if row["status"] == "resolved" else "contradicted" if row["status"] == "conflict" else "missing"
            if diagnostics:
                status = "contradicted" if any("conflict" in f["code"] or "mismatch" in f["code"] for f in diagnostics) else "missing"
            recipes[row["parameter_id"]] = add(row["function_id"], "argument_construction", "parameter_recipe", req=req,
                parameter=row["parameter"], resource=recipe.get("resource_id"),
                status=status,
                evidence=row["evidence_ids"], facts=row["semantic_fact_ids"],
                diagnostics=diagnostics,
                sources=[{"kind": "canonical_construction", "parameter_id": row["parameter_id"],
                    "proof_digest": row["proof_digest"], "reason": row["reason"]}])
            coverage.append({"kind": "parameter_recipe", "function_id": row["function_id"], "parameter": row["parameter"],
                "obligation_id": recipes[row["parameter_id"]]})
            if req:
                depend(req_nodes[(row["function_id"], "argument_construction")], recipes[row["parameter_id"]], "parameter_constructible")
        for row in parameters:
            if row["parameter_id"] not in recipes:
                continue
            nid, recipe = recipes[row["parameter_id"]], row.get("recipe") or {}
            for pid in row.get("dependencies", []):
                # Foreign/missing IDs are retained and cannot discharge proof.
                dep = recipes.get(pid, "absent_parameter_" + pid)
                depend(nid, dep, "recipe_argument")
            if recipe.get("kind") in {"creator_call", "out_parameter_call"} and recipe.get("producer_api") != row["function_id"]:
                depend(nid, api_ready(recipe["producer_api"]), "producer_invocation")
            if recipe.get("kind") == "callback_object" and (row["function_id"], "callback") in req_nodes:
                depend(nid, req_nodes[(row["function_id"], "callback")], "callback_abi")

        for resource in context["lifecycle_contract"]["resources"]:
            fid = resource["function_id"]
            root = req_nodes.get((fid, "lifecycle"))
            if not root:
                continue
            for action in ("creation", "initialization", "cleanup"):
                row = resource[action]
                if row.get("api") and row["api"] != fid and (action == "creation" or row.get("mandatory")):
                    depend(root, api_ready(row["api"]), action + "_invocation")

        # Required incoming fields are derived from source, never from how many
        # preconditions a proposal happened to include.
        for proof in audit["source_field_proofs"]:
            fid = proof["function_id"]
            req = reqs.get((fid, "state")) or reqs.get((fid, "argument_construction"))
            diagnostic = {"requirement_id": req["requirement_id"] if req else None, "subject_function_id": fid,
                "kind": req["kind"] if req else "state", "code": proof["code"], "subject_parameter": proof["parameter"],
                "subject_field": proof["field"], "question": "Prove definite initialization of this exact object's field before its incoming read."}
            returned_cleanup = proof['code'] == 'source_observed_core_return_cleanup'
            question = ('Prove this cleanup argument is the exact owned result of the CORE invocation and its observed API pair.'
                if returned_cleanup else diagnostic['question'])
            nid = add(fid, "state", "cleanup_return_input_valid" if returned_cleanup else "incoming_field_initialized", req=req, parameter=proof["parameter"],
                field=proof["field"], resource=proof["resource_id"], status=proof["status"], evidence=proof["evidence_ids"],
                sources=[{"kind": "source_field_grounding", "writer_api": proof["writer_api"], "code": proof["code"],
                    **({'proof_scope': proof['proof_scope'], 'construction_source': proof['construction_source'],
                        'internal_target_fields': proof['fields']} if returned_cleanup else {})}],
                diagnostics=[] if proof["status"] == "proved" else [diagnostic], question=question)
            roots.add(nid)
            coverage.append({"kind": "incoming_field", "function_id": fid, "parameter": proof["parameter"], "field": proof["field"], "obligation_id": nid})
            depend(api_ready(fid), nid, "required_incoming_field")
            if returned_cleanup:
                producer = proof['writer_api']
                depend(nid, api_ready(producer), 'owned_result_producer_invocation')
                owner = owners.get((producer, None, 'PointerReturn', None))
                depend(nid, owner or 'absent_return_owner_' + producer, 'owned_result_lifetime')
            if (fid, "state") in req_nodes:
                depend(req_nodes[fid, "state"], nid, "required_incoming_field")

        # Exact signed state proposals link initialization to the initializer's
        # independent argument/ownership proofs. Same-origin field transitions
        # add a source-proved field obligation when the value-flow graph has it.
        for condition in context["invocation_contract"]["preconditions"]:
            fid, api = condition["function_id"], condition.get("api")
            root = req_nodes.get((fid, "state" if condition["source"] == "semantic_state" else "lifecycle"))
            if not root or condition["kind"] in {"none", "unknown"}:
                continue
            if api and api != fid:
                depend(root, api_ready(api), "precondition_initializer")
                if (fid, "call_order") in req_nodes:
                    depend(root, req_nodes[(fid, "call_order")], "initializer_before_use")
                for transition in context["invocation_contract"]["transitions"]:
                    if (transition["reason"] != "graph_same_origin_field_write_read" or transition["before"] != api
                            or transition["after"] != fid or transition["resource_id"] != condition.get("resource_id")):
                        continue
                    for field in transition["fields"]:
                        field_node = add(fid, "state", "resource_field_written", req=reqs.get((fid, "state")),
                            parameter=condition.get("parameter"), resource=transition["resource_id"], qualifier=[api, field],
                            evidence=transition["evidence_ids"],
                            sources=[{"kind": "same_origin_field_write_read", "field": field, "writer_api": api,
                                "transition_id": transition["transition_id"]}],
                            question="Prove that the same resource's field is written before this invocation reads it.")
                        depend(root, field_node, "initialized_field")
                        depend(field_node, api_ready(api), "field_writer_invocation")
            if condition["source"] == "semantic_state":
                if (fid, "lifecycle") in req_nodes:
                    depend(root, req_nodes[(fid, "lifecycle")], "resource_lifecycle")

        for callback in context["callback_contract"]["callbacks"]:
            root = req_nodes.get((callback["function_id"], "callback"))
            if not root or not callback.get("userdata"):
                continue
            # Qualified fields belong to exact owner storage, not a new ctx ID.
            owner = callback["userdata"].split(".")[0]
            for row in parameters:
                if row["function_id"] == callback["function_id"] and row["parameter"] == owner and row["parameter_id"] in recipes:
                    depend(root, recipes[row["parameter_id"]], "userdata_construction")
            lifetime = owners.get((callback["function_id"], owner, "PointerParameter", None))
            if lifetime:
                depend(root, lifetime, "userdata_lifetime")

        # Input extent evidence is an independent semantic obligation. A proved
        # byte path cannot close while its length contract remains unknown.
        for (fid, kind), nid in req_nodes.items():
            if kind == "input_binding" and (fid, "buffer_length") in req_nodes:
                depend(nid, req_nodes[(fid, "buffer_length")], "input_extent")

        for error in audit["validation_errors"]:
            nid = add(ft["anchor_function_id"], "integrity", error["code"], qualifier=error,
                status="contradicted", diagnostics=[error], sources=[{"kind": "input_validation"}])
            roots.add(nid)
        for fid in sorted(active):
            invocation = api_ready(fid)
            roots.add(invocation)
            for (function, parameter, subject_kind, field), nid in owners.items():
                if function == fid:
                    depend(invocation, nid, "required_pointer_subject")
            for row in coverage:
                if row["function_id"] == fid and row["kind"] == "parameter_recipe":
                    depend(invocation, row["obligation_id"], "required_parameter")
        for node in nodes.values():
            node["dependencies"].sort(key=canonical)
        result = {"schema_version": 1, "artifact_kind": "semantic_obligation_graph", "version": VERSION,
            "ft_id": ft["ft_id"],
            "required_coverage": sorted(coverage, key=canonical),
            "input_digests": input_digests(context, closure, ft, requirements, resolutions, state.evidence),
            **close_obligations(list(nodes.values()), roots),
            "validation_errors": audit["validation_errors"], "soft_unknowns": audit["soft_unknowns"],
            "framework_satisfied_requirements": audit["framework_satisfied_requirements"],
            "argument_graph_version": audit["argument_graph_version"], "graph_failure_taxonomy": audit["graph_failure_taxonomy"]}
        result["graph_digest"] = digest(result)
        return result


def investigation_view(graph, requirements):
    """Only requested nodes and transitive prerequisites; no full-project graph."""
    if graph is None:
        return {"version": VERSION, "targets": [], "proved": [], "missing_evidence": [], "blocked": []}
    rids = {r["requirement_id"] for r in requirements}
    nodes = {n["obligation_id"]: n for n in graph["nodes"]}
    targets = sorted(nid for nid, n in nodes.items() if n["requirement_id"] in rids and n["predicate"] == n["kind"])
    relevant, pending = set(), list(targets)
    while pending:
        nid = pending.pop()
        if nid in relevant or nid not in nodes:
            continue
        relevant.add(nid)
        pending.extend(dep["obligation_id"] for dep in nodes[nid]["dependencies"])
    rows = [{k: v for k, v in nodes[nid].items() if k != "local_proof"} for nid in sorted(relevant)]
    return {"version": VERSION, "graph_digest": graph["graph_digest"], "targets": targets,
        "proved": [n for n in rows if n["proof_status"] == "proved"],
        "missing_evidence": [n for n in rows if n["proof_status"] in {"missing", "contradicted"}],
        "blocked": [n for n in rows if n["proof_status"] == "blocked"]}
