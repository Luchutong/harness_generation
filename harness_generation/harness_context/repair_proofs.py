"""Evidence-based proposal retirement, using existing source/obligation proofs.

Counterfactuals replace one exact subject, never the whole requirement. A
missing proof is not a disproof. Competing proved claims remain blocking unless
they lower to the same recomputed recipe. No model controls this evaluator.
"""
from copy import deepcopy

from ..semantic_discovery.models import canonical, digest
from .models import fact_id
from .repairs import COLLECTIONS, subject_key, fact_conflicts


def claim_key(fact):
    return digest({k: fact[k] for k in ("requirement_id", "function_id", "predicate", "value")})


def supported_dependencies(result):
    """Remove retired API selections only when their fact role disappeared."""
    from .evidence import api_roles
    roles = {}
    for fact in result["facts"]:
        for api, values in api_roles(fact).items():
            roles.setdefault(api, set()).update(values)
        if fact["predicate"] == "support_decision":
            roles.setdefault(fact["function_id"], set()).add(fact["value"]["reason"])
    return [d for d in result["discovered_api_dependencies"]
        if d["necessity"] not in {"required", "optional"} or d["reason"] in roles.get(d["function_id"], set())]


class RepairProofEvaluator:
    def __init__(self, ft, snapshot, state):
        self.ft, self.snapshot, self.state = ft, snapshot, state
        self.protected = {}

    def configure(self, facts, requirements, resolutions):
        self.facts, self.requirements, self.resolutions = facts, requirements, resolutions
        return self

    def _nodes(self, graph, fact):
        kind, field = fact["predicate"], COLLECTIONS.get(fact["predicate"])
        row = fact["value"][field][0] if field else fact["value"]
        candidates = [n for n in graph["nodes"] if n["requirement_id"] == fact["requirement_id"]]
        if kind == "argument_construction":
            return [n for n in candidates if n["predicate"] == "parameter_recipe"
                and n["subject_parameter"] == row["parameter"]]
        if kind == "ownership":
            from .proposals import ownership_subject
            subject = ownership_subject(row, fact["function_id"], self.snapshot)
            return [n for n in candidates if n["predicate"] == "ownership_subject"
                and any(s.get("subject_id") == subject["subject_id"] for s in n["local_proof"]["sources"])]
        if kind == "state":
            return [n for n in candidates if n["predicate"] == "incoming_field_initialized"
                and n["subject_parameter"] == row["parameter"]]
        return []

    def remember(self, context, graph):
        """Protect actual closed subject proofs, not hypothetical alternatives."""
        from .value_flow import complete_bodies
        issued = complete_bodies(self.snapshot, self.state.evidence)
        conflicts = {(r["requirement_id"], tuple(r["subject_key"])) for r in fact_conflicts(context["facts"])}
        for fact in context["facts"]:
            field = COLLECTIONS.get(fact["predicate"])
            if not field or fact["function_id"] not in issued or (fact["requirement_id"], ("metadata",)) in conflicts:
                continue
            for row in fact["value"].get(field, []):
                if (fact["requirement_id"], subject_key(fact["predicate"], row)) in conflicts:
                    continue
                if fact['predicate'] == 'ownership':
                    if row['ownership'] == 'owned' and row['release_api'] is None:
                        continue  # An unclosed release contract is not a protected owner proof.
                    projected = [o for o in context['ownership_contract']['entries']
                        if o.get('fact_id') == fact['fact_id'] and o['parameter'] == row['parameter']
                        and o['return_value'] == row['return_value'] and o['field'] == row['field']]
                    if any(any(o[k] != row[k] for k in ('ownership', 'lifetime', 'release_api')) for o in projected):
                        continue  # A source-derived correction does not prove the original claim.
                single = deepcopy(fact)
                single["value"][field] = [deepcopy(row)]
                nodes = self._nodes(graph, single)
                if nodes and all(n["proof_status"] == "proved" for n in nodes):
                    self.protected.setdefault(claim_key(single), {"graph_digest": graph["graph_digest"],
                        "obligation_ids": sorted(n["obligation_id"] for n in nodes),
                        "evidence_ids": sorted({e for n in nodes for e in n["evidence_ids"]})})

    def _projection(self, result, requirement, *, counterfactual_resolutions=None):
        from .api_closure import build_api_closure
        from .evidence import build_context
        from .loop import expand_requirements
        from .obligations import SemanticObligationGraphBuilder
        overrides = {**(counterfactual_resolutions or {}), requirement["requirement_id"]: result}
        resolutions = {**deepcopy(self.resolutions), **deepcopy(overrides)}
        rows = deepcopy(self.requirements)
        for req in rows:
            resolution = resolutions.get(req["requirement_id"])
            if resolution:
                req["status"] = resolution["status"]
                req["evidence_ids"] = sorted({e for f in resolution["facts"] for e in f["evidence_ids"]})
        facts = [f for f in self.facts if f["requirement_id"] not in overrides]
        facts += [f for resolution in overrides.values() for f in resolution["facts"]]
        closure = build_api_closure(self.ft, rows, resolutions, self.snapshot, self.state)
        expand_requirements(self.ft, self.snapshot, rows, closure)
        context = build_context(self.ft, rows, facts, self.snapshot, self.state.evidence)
        context["dependencies"] = deepcopy(closure["unresolved_api_dependencies"])
        graph = SemanticObligationGraphBuilder().build(context, closure, self.ft, self.snapshot, rows, resolutions, self.state)
        return context, closure, graph

    def _extent_completions(self, result, requirement):
        """Complete a model-submitted omitted slot, not a source-disproved claim.

        A source pair is only a compatibility hint. The model must explicitly
        submit both contracts, with the same existing units and other fields.
        We recompute their harness recipes together before retiring one null
        slot. A concrete alternative is never retired by this rule.
        """
        from .input_pairs import buffer_pairs, BYTE_TYPES
        from .value_flow import complete_bodies
        kind, fid = requirement["kind"], requirement["subject_function_id"]
        if kind not in {"input_binding", "buffer_length"} or result["status"] != "resolved":
            return result, []
        field = COLLECTIONS[kind]
        extent = "size_parameter" if kind == "input_binding" else "length_parameter"
        subject = "parameter" if kind == "input_binding" else "buffer_parameter"
        issued = complete_bodies(self.snapshot, self.state.evidence)
        if fid not in issued:
            return result, []
        function = self.snapshot.functions[fid]
        parameters = {p["name"]: p for p in function["parameters"]}
        choices = {(p["buffer_parameter"], p["length_parameter"]): p for p in buffer_pairs(function)}

        def same_shape(facts, collection, slot):
            if any(len(f["value"].get(collection, [])) != 1 for f in facts):
                return False
            shapes = [{**{k: v for k, v in f["value"].items() if k != collection}, collection:
                [{k: v for k, v in f["value"][collection][0].items() if k != slot}]} for f in facts]
            return all(canonical(s) == canonical(shapes[0]) for s in shapes)

        groups = {}
        for fact in result["facts"]:
            if (fact["function_id"] != fid or fact["requirement_id"] != requirement["requirement_id"]
                    or fact["predicate"] != kind or len(fact["value"].get(field, [])) != 1):
                return result, []
            groups.setdefault(fact["value"][field][0][subject], []).append(fact)
        result, withdrawals = deepcopy(result), []
        for buffer, alternatives in sorted(groups.items(), key=lambda item: canonical(item[0])):
            if len(alternatives) < 2 or not same_shape(alternatives, field, extent):
                continue
            concrete = [f for f in alternatives if f["value"][field][0][extent] is not None]
            omitted = [f for f in alternatives if f["value"][field][0][extent] is None]
            if len(concrete) != 1 or not omitted:
                continue
            chosen = concrete[0]
            length = chosen["value"][field][0][extent]
            pointer, scalar = parameters.get(buffer, {}), parameters.get(length, {})
            choice = choices.get((buffer, length))
            if (not choice or pointer.get("pointer_depth") != 1 or pointer.get("base_type") not in BYTE_TYPES
                    or not scalar or scalar.get("is_pointer") or scalar.get("is_struct_like")):
                continue
            opposite = "buffer_length" if kind == "input_binding" else "input_binding"
            other_requirements = [r for r in self.requirements if r["subject_function_id"] == fid and r["kind"] == opposite]
            if len(other_requirements) != 1:
                continue
            other_req = other_requirements[0]
            other = deepcopy(self.resolutions.get(other_req["requirement_id"]))
            if not other or other["status"] != "resolved":
                continue
            other_field = COLLECTIONS[opposite]
            other_extent = "length_parameter" if opposite == "buffer_length" else "size_parameter"
            other_subject = "buffer_parameter" if opposite == "buffer_length" else "parameter"
            if any(len(f["value"].get(other_field, [])) != 1 for f in other["facts"]):
                continue
            counterparts = [f for f in other["facts"] if f["value"][other_field][0][other_subject] == buffer]
            if (not counterparts or not same_shape(counterparts, other_field, other_extent)
                    or any(f["function_id"] != fid or f["predicate"] != opposite
                        or f["requirement_id"] != other_req["requirement_id"] for f in counterparts)):
                continue
            selected = [f for f in counterparts if f["value"][other_field][0][other_extent] == length]
            if len(selected) != 1 or any(f["value"][other_field][0][other_extent] not in {None, length} for f in counterparts):
                continue
            other_chosen = selected[0]
            binding = (chosen if kind == "input_binding" else other_chosen)["value"]["bindings"][0]
            link = (chosen if kind == "buffer_length" else other_chosen)["value"]["links"][0]
            # Units, adapters, NUL semantics and mutability are not repaired by
            # this rule. Counterpart agreement proves a harness construction,
            # never that a source guard or index denotes an API byte extent.
            if (binding["source"] != "fuzz_data" or binding["transform"] not in {"direct", "copy"}
                    or binding["via_function_id"] is not None or binding["size_relation"] != "bytes"
                    or binding["nul_terminated"] or binding["binary_zero_allowed"] is None
                    or link["relation"] != "bytes" or link["requires_nul_termination"]
                    or link["binary_zero_allowed"] != binding["binary_zero_allowed"]
                    or (chosen if kind == "buffer_length" else other_chosen)["value"]["applicable"] is not True):
                continue
            alternative = deepcopy(result)
            alternative["facts"] = [f for f in result["facts"] if f not in alternatives] + [deepcopy(chosen)]
            other["facts"] = [f for f in other["facts"] if f not in counterparts] + [deepcopy(other_chosen)]
            alternative["facts"].sort(key=lambda f: f["fact_id"])
            other["facts"].sort(key=lambda f: f["fact_id"])
            context, _, graph = self._projection(alternative, requirement,
                counterfactual_resolutions={other_req["requirement_id"]: other})
            recipes = [p for p in context["canonical_construction"]["parameters"]
                if p["function_id"] == fid and p["parameter"] in {buffer, length}]
            nodes = [n for n in graph["nodes"] if n["subject_function_id"] == fid
                and n["predicate"] == "parameter_recipe" and n["subject_parameter"] in {buffer, length}]
            expected = {buffer: "fuzz_bytes", length: "fuzz_size"}
            if (graph["validation_errors"] or len(recipes) != 2 or len(nodes) != 2
                    or any(p["status"] != "resolved" or (p.get("recipe") or {}).get("kind") != expected[p["parameter"]]
                        for p in recipes) or any(n["proof_status"] != "proved" for n in nodes)):
                continue
            witness = {"status": "proved", "kind": "source_checked_harness_extent_completion",
                "proof_scope": [extent], "source_choice": deepcopy(choice), "source_choice_is_unit_proof": False,
                "counterpart_fact_id": other_chosen["fact_id"],
                "counterfactual_omitted_fact_ids": sorted(f["fact_id"] for f in counterparts
                    if f["value"][other_field][0][other_extent] is None),
                "obligation_ids": sorted(n["obligation_id"] for n in nodes),
                "evidence_ids": sorted(set(issued[fid]) | {e for n in nodes for e in n["evidence_ids"]}),
                "graph_digest": graph["graph_digest"]}
            result["facts"] = alternative["facts"]
            for fact in omitted:
                withdrawals.append({"requirement_id": requirement["requirement_id"],
                    "subject_key": list(subject_key(kind, fact["value"][field][0])),
                    "withdrawn_fact": deepcopy(fact), "replacement_fact_id": chosen["fact_id"],
                    "reason": "omitted_extent_slot_completed",
                    "previous_proof": {"status": "missing", "proof_scope": [extent], "code": "omitted_extent_slot"},
                    "replacement_proof": deepcopy(witness), "source_fingerprint": self.snapshot.source_fingerprint})
        result["facts"].sort(key=lambda f: f["fact_id"])
        return result, withdrawals

    def _callback_completions(self, result, requirement):
        """Retire omitted direct-callback slots after an explicit submission.

        Null behavior is not a generally nullable merge field. This rule only
        proves false for an unmodified, unconditional thin dispatch of the
        declared parameter to its already resolved canonical producer. It
        cannot select a producer, infer default behavior or repair competing
        concrete contracts, userdata, ABI or lifetime claims.
        """
        from .callbacks import callback_declarations, callback_matches, function_callback_abi
        from .evidence import callback_abis
        from .value_flow import complete_bodies, body_tree
        from ..semantic_discovery.tools import _walk, _text

        kind, fid = requirement["kind"], requirement["subject_function_id"]
        if kind != "callback" or result["status"] != "resolved":
            return result, []
        issued = complete_bodies(self.snapshot, self.state.evidence)
        if fid not in issued:
            return result, []
        declarations = callback_declarations(self.snapshot.functions[fid], self.snapshot)
        groups = {}
        for fact in result["facts"]:
            if (fact["requirement_id"] != requirement["requirement_id"] or fact["function_id"] != fid
                    or fact["predicate"] != kind or len(fact["value"].get("callbacks", [])) != 1):
                return result, []
            groups.setdefault(subject_key(kind, fact["value"]["callbacks"][0]), []).append(fact)

        result, withdrawals = deepcopy(result), []
        for key, alternatives in sorted(groups.items(), key=lambda item: canonical(item[0])):
            if len(alternatives) < 2:
                continue
            slots = {"setup_api", "null_allowed"}
            shapes = [{**{k: v for k, v in f["value"].items() if k != "callbacks"}, "callbacks":
                [{k: v for k, v in f["value"]["callbacks"][0].items() if k not in slots}]} for f in alternatives]
            if any(canonical(shape) != canonical(shapes[0]) for shape in shapes):
                continue
            concrete = [f for f in alternatives if f["value"]["callbacks"][0]["setup_api"] is not None
                and type(f["value"]["callbacks"][0]["null_allowed"]) is bool]
            if len(concrete) != 1:
                continue
            chosen = concrete[0]
            row = chosen["value"]["callbacks"][0]
            producer, parameter = row["setup_api"], row["parameter"]
            if (producer not in issued or row["mandatory"] is not True
                    or row["null_allowed"] is not False or row["lifetime"] != "during_call"):
                continue
            omitted = [f for f in alternatives if f is not chosen]
            if (any(claim_key(f) in self.protected for f in omitted)
                    or any(f["value"]["callbacks"][0]["null_allowed"] is not None for f in omitted)
                    or any(any(f["value"]["callbacks"][0][slot] not in (None, row[slot]) for slot in slots)
                        or not any(f["value"]["callbacks"][0][slot] is None for slot in slots) for f in omitted)):
                continue
            matched = callback_matches(row, declarations)
            if len(matched) != 1 or matched[0]["field"] is not None:
                continue  # Field registration/default protocols need their own proof.
            declaration = matched[0]
            declared_abi = callback_abis(declaration["signature"])
            if (not declared_abi or callback_abis(row["signature"]) != declared_abi
                    or function_callback_abi(self.snapshot.functions[producer]["signature"]) != declared_abi):
                continue

            # A model's mandatory label never proves that null is forbidden.
            # Require exactly the declared handler call as the sole statement;
            # guards, fallback paths, rebinding, retention and other calls fail.
            source, body = body_tree(self.snapshot.functions[fid])
            statements = [n for n in body.named_children if n.type != "comment"] if body is not None else []
            calls = [n for n in _walk(body) if n.type == "call_expression"] if body is not None else []
            if (body is None or body.has_error or len(statements) != 1 or len(calls) != 1
                    or statements[0].type not in {"return_statement", "expression_statement"}
                    or calls[0].parent != statements[0]
                    or calls[0].child_by_field_name("function").type != "identifier"
                    or _text(calls[0].child_by_field_name("function"), source) != parameter):
                continue

            alternative = deepcopy(result)
            alternative["facts"] = [f for f in result["facts"] if f not in alternatives] + [deepcopy(chosen)]
            alternative["facts"].sort(key=lambda f: f["fact_id"])
            context, _, graph = self._projection(alternative, requirement)
            recipes = [p for p in context["canonical_construction"]["parameters"]
                if p["function_id"] == fid and p["parameter"] == parameter]
            dispatches = [d for d in context["argument_graph"].get("callback_dispatches", [])
                if d["via_function_id"] == fid and d["callback_parameter"] == parameter]
            roots = [n for n in graph["nodes"] if n["requirement_id"] == requirement["requirement_id"]]
            recipe_nodes = [n for n in graph["nodes"] if n["subject_function_id"] == fid
                and n["predicate"] == "parameter_recipe" and n["subject_parameter"] == parameter]
            callbacks = [c for c in context["callback_contract"]["callbacks"]
                if c["function_id"] == fid and c["parameter"] == parameter]
            if (graph["validation_errors"] or len(recipes) != 1 or recipes[0]["status"] != "resolved"
                    or (recipes[0].get("recipe") or {}).get("kind") != "callback_object"
                    or recipes[0]["recipe"].get("producer_api") != producer
                    or len(dispatches) != 1 or dispatches[0]["proof_status"] != "proven"
                    or dispatches[0]["function_id"] != producer or dispatches[0]["calls_per_invocation"] != 1
                    or not roots or any(n["proof_status"] != "proved" for n in roots)
                    or len(recipe_nodes) != 1 or recipe_nodes[0]["proof_status"] != "proved"
                    or len(callbacks) != 1 or callbacks[0].get("declaration_identity") != declaration
                    or callbacks[0].get("registration", {}).get("kind") != "function_binding"):
                continue
            completed = sorted({slot for f in omitted for slot in slots
                if f["value"]["callbacks"][0][slot] is None})
            witness = {"status": "proved", "kind": "source_checked_direct_callback_completion",
                "proof_scope": completed, "declaration_identity": deepcopy(declaration),
                "canonical_producer_api": producer, "canonical_recipe_id": recipes[0]["recipe"]["recipe_id"],
                "dispatch": deepcopy(dispatches[0]), "null_behavior": "unconditional_unmodified_declared_handler_call",
                "obligation_ids": sorted(n["obligation_id"] for n in roots + recipe_nodes),
                "evidence_ids": sorted(set(issued[fid]) | set(issued[producer])
                    | set(dispatches[0]["evidence_ids"]) | {e for n in roots + recipe_nodes for e in n["evidence_ids"]}),
                "graph_digest": graph["graph_digest"]}
            result["facts"] = alternative["facts"]
            for fact in omitted:
                scope = sorted(slot for slot in slots if fact["value"]["callbacks"][0][slot] is None)
                withdrawals.append({"requirement_id": requirement["requirement_id"], "subject_key": list(key),
                    "withdrawn_fact": deepcopy(fact), "replacement_fact_id": chosen["fact_id"],
                    "reason": "omitted_callback_contract_completed",
                    "previous_proof": {"status": "missing", "proof_scope": scope, "code": "omitted_callback_contract_slot"},
                    "replacement_proof": deepcopy(witness), "source_fingerprint": self.snapshot.source_fingerprint})
        result["facts"].sort(key=lambda f: f["fact_id"])
        return result, withdrawals

    def _borrowed_source_proof(self, row, fid, context, graph):
        """A retention bound needs exact recipient storage and proved cleanup."""
        from .proof_grounding import analyze
        from .value_flow import complete_bodies
        issued = complete_bodies(self.snapshot, self.state.evidence)
        summary = analyze(self.snapshot.functions[fid], self.snapshot, issued)
        paths, origin = summary["paths"], "parameter:" + str(row["parameter"])
        if not paths or any(p["uncertain"] or origin in p["released"] for p in paths):
            return None
        if row["ownership"] != "borrowed" or row["release_api"] is not None or row["field"] is not None:
            return None
        escaped = any(origin in p["escapes"] for p in paths)
        if row["lifetime"] == "during_call" and not escaped:
            return {"kind": "source_nonretaining_borrow", "evidence_ids": sorted(issued[fid])}
        if row["lifetime"] not in {"until_context_cleanup", "until_release"} or not escaped:
            return None
        recipients = set()
        for path in paths:
            targets = {destination for value, destination, member in path["retentions"] if value == origin}
            if origin in path["escapes"] and not targets:
                return None  # Return/global/unknown escape is not context storage.
            recipients.update(targets)
        eids = set(issued[fid])
        for recipient in recipients:
            if not recipient.startswith("parameter:"):
                return None
            parameter = recipient.removeprefix("parameter:")
            selection = next((r for r in context["canonical_construction"]["parameters"]
                if r["function_id"] == fid and r["parameter"] == parameter and r["status"] == "resolved"), None)
            rid = (selection or {}).get("recipe", {}).get("resource_id")
            resources = [r for r in context["lifecycle_contract"]["resources"]
                if rid and r["resource_id"] == rid and r["cleanup"]["mandatory"]]
            apis = {r["cleanup"]["api"] for r in resources}
            if len(apis) != 1 or None in apis:
                return None
            cleanup = next(iter(apis))
            invocation = next((n for n in graph["nodes"] if n["subject_function_id"] == cleanup
                and n["predicate"] == "api_invocation_proved" and n["proof_status"] == "proved"), None)
            q = self.snapshot.functions[cleanup]
            target = next((p for p in self.snapshot.functions[fid]["parameters"] if p["name"] == parameter), {})
            params = [p for p in q["parameters"] if p.get("base_type") == target.get("base_type")
                and p.get("pointer_depth") == target.get("pointer_depth")]
            release = analyze(q, self.snapshot, issued)
            members = {member for path in paths for value, destination, member in path["retentions"]
                if value == origin and destination == recipient}
            if not invocation or len(params) != 1 or not release["paths"] or any(p["uncertain"]
                    or "parameter:" + params[0]["name"] not in p["released"] for p in release["paths"]):
                return None
            if any(parameter == params[0]["name"] and member in members for parameter, member in release["reads"]):
                return None  # Stored-pointer cleanup effects are not yet proved.
            eids.update(issued[cleanup])
        witness = {"kind": "source_retention_in_cleanup_bound_resource", "evidence_ids": sorted(eids),
            "recipients": sorted(recipients)} if recipients else None
        if witness and row["lifetime"] == "until_release":
            bound = self._exact_retained_release_bound(row, fid, context, graph, issued, summary, recipients)
            if bound is None:
                return None
            witness.update(lifetime_bound="until_release", release_bound=bound)
            witness["evidence_ids"] = sorted(set(witness["evidence_ids"]) | set(bound["evidence_ids"]))
        return witness

    def _exact_retained_release_bound(self, row, fid, context, graph, issued, summary, recipients):
        """Certify only exact input-member storage in an owned cleanup-bound object.

        An unsupported source form is missing proof, never an escape disproof.
        This deliberately narrow extension does not infer longer lifetimes from
        graph reachability, caller labels, a missing cleanup or arbitrary aliases.
        """
        from .value_flow import body_tree
        from ..semantic_discovery.tools import _walk, _text
        from .resource_identity import (exclusive_return_export_proof,
            exclusive_parameter_use_proof, parameter_release_proof)
        origin = "parameter:" + str(row["parameter"])
        source, body = body_tree(self.snapshot.functions[fid])
        if body is None or body.has_error or row["return_value"]:
            return None
        permitted = {(destination.removeprefix("parameter:"), member)
            for path in summary["paths"] for value, destination, member in path["retentions"]
            if value == origin and destination.startswith("parameter:") and member}
        # Every spelling of the retained pointer must be an exact RHS of a
        # certified direct member store. This rejects array/out/global/static
        # exports, casts, pointer arithmetic, local shadowing and call retention
        # that the bounded effect interpreter may not fully represent.
        occurrences = [n for n in _walk(body) if n.type == "identifier" and _text(n, source) == row["parameter"]]
        if not occurrences or not permitted:
            return None
        for node in occurrences:
            assignment = node.parent
            if (assignment is None or assignment.type != "assignment_expression"
                    or assignment.child_by_field_name("right") != node
                    or _text(assignment.child_by_field_name("operator"), source) != "="):
                return None
            left = assignment.child_by_field_name("left")
            argument = left.child_by_field_name("argument") if left.type == "field_expression" else None
            member = left.child_by_field_name("field") if left.type == "field_expression" else None
            if (argument is None or argument.type != "identifier" or member is None
                    or (_text(argument, source), _text(member, source)) not in permitted):
                return None
        eids, bindings = set(issued[fid]), []
        for recipient in sorted(recipients):
            parameter = recipient.removeprefix("parameter:")
            recipient_use = exclusive_parameter_use_proof(self.snapshot.functions[fid], parameter, self.snapshot, issued)
            if not recipient_use:
                return None
            selections = [r for r in context["canonical_construction"]["parameters"]
                if r["function_id"] == fid and r["parameter"] == parameter and r["status"] == "resolved"]
            if len(selections) != 1:
                return None
            recipe = selections[0].get("recipe") or {}
            producer, rid = recipe.get("producer_api"), recipe.get("resource_id")
            if recipe.get("kind") not in {"creator_call", "resource_reference"} or producer not in issued or not rid:
                return None
            allocation = exclusive_return_export_proof(self.snapshot.functions[producer], self.snapshot, issued)
            resources = [r for r in context["lifecycle_contract"]["resources"]
                if r["function_id"] == producer and r["return_value"] and r["resource_id"] == rid]
            if not allocation or len(resources) != 1:
                return None
            resource = resources[0]
            cleanup = resource["cleanup"]["api"]
            if (resource["creation"] != {"api": producer, "kind": "creator_api"}
                    or not resource["cleanup"]["mandatory"] or cleanup not in issued
                    or resource["reuse"] == "unknown"):
                return None
            owners = [o for o in context["ownership_contract"]["entries"]
                if o["function_id"] == producer and o["return_value"] and o["field"] is None and o["resource_id"] == rid]
            if (len(owners) != 1 or owners[0]["ownership"] != "owned"
                    or owners[0]["lifetime"] != "until_release" or owners[0]["release_api"] != cleanup):
                return None
            target = next(p for p in self.snapshot.functions[fid]["parameters"] if p["name"] == parameter)
            release_slots = [p for p in self.snapshot.functions[cleanup]["parameters"]
                if p.get("base_type") == target.get("base_type") and p.get("pointer_depth") == target.get("pointer_depth")]
            if len(release_slots) != 1:
                return None
            release_parameter = release_slots[0]["name"]
            cleanup_recipes = [r for r in context["canonical_construction"]["parameters"]
                if r["function_id"] == cleanup and r["parameter"] == release_parameter and r["status"] == "resolved"
                and (r.get("recipe") or {}).get("resource_id") == rid
                and (r.get("recipe") or {}).get("producer_api") == producer]
            release = parameter_release_proof(self.snapshot.functions[cleanup], release_parameter, self.snapshot, issued)
            if len(cleanup_recipes) != 1 or not release:
                return None
            release_source, release_body = body_tree(self.snapshot.functions[cleanup])
            for node in _walk(release_body):
                if node.type != "identifier" or _text(node, release_source) != release_parameter:
                    continue
                args = node.parent
                call = args.parent if args is not None and args.type == "argument_list" else None
                if (call is None or call.type != "call_expression" or len(args.named_children) != 1
                        or _text(call.child_by_field_name("function"), release_source) != "free"):
                    return None  # Extra aliases/stores/address exports are not modeled by release_counts.
            members = {member for destination, member in permitted if destination == parameter}
            if any(p == release_parameter and member in members for p, member in release["reads"]):
                return None  # Even an unrelated stored-member cleanup read stays unsupported.
            eids.update(issued[cleanup])
            eids.update(issued[producer])
            for source_fid in (set(summary["source_function_ids"]) | set(recipient_use["source_function_ids"])
                    | set(allocation["source_function_ids"]) | set(release["source_function_ids"])):
                if source_fid not in issued:
                    return None
                eids.update(issued[source_fid])
            bindings.append({"recipient_parameter": parameter, "resource_id": rid,
                "producer_api": producer, "cleanup_api": cleanup, "cleanup_parameter": release_parameter,
                "stored_members": sorted(members)})
        return {"version": "source-retained-borrow-release-bound-v1", "bindings": bindings,
            "evidence_ids": sorted(eids)} if bindings else None

    def assess(self, result, requirement, fact):
        from .proof_grounding import contradictions, field_proofs
        from .value_flow import complete_bodies
        kind, field = fact["predicate"], COLLECTIONS.get(fact["predicate"])
        row = fact["value"][field][0]
        proof = {"status": "missing", "evidence_ids": [], "diagnostics": [],
            "protected": deepcopy(self.protected.get(claim_key(fact)))}
        if kind not in {"argument_construction", "ownership", "state"}:
            return proof
        issued = complete_bodies(self.snapshot, self.state.evidence)
        if fact["function_id"] not in issued:
            return proof
        alternative = deepcopy(result)
        key = subject_key(kind, row)
        alternative["facts"] = [f for f in result["facts"]
            if subject_key(kind, f["value"][field][0]) != key] + [fact]
        alternative["facts"].sort(key=lambda f: f["fact_id"])
        alternative["discovered_api_dependencies"] = supported_dependencies(alternative)
        context, closure, graph = self._projection(alternative, requirement)
        proof["graph_digest"] = graph["graph_digest"]
        proof["validation_errors"] = graph["validation_errors"]
        negatives = [c for c in contradictions(context, self.snapshot, self.state.evidence)
            if c["fact_id"] == fact["fact_id"]]
        if kind == 'ownership' and row['ownership'] == 'owned' and row['release_api'] is None and row['field'] is None:
            consumption = [s for s in context['construction_contract']['sources'] if s['kind'] == 'cleanup_consumption'
                and s['verified'] and s['function_id'] == fact['function_id'] and s['parameter'] == row['parameter']]
            if len(consumption) == 1:
                negatives.append({'code': 'source_cleanup_consumption_contract_mismatch',
                    'evidence_ids': consumption[0]['evidence_ids']})
        if kind == "state":
            negatives += [p for p in field_proofs(context, self.snapshot, self.state.evidence, closure)
                if p["function_id"] == fact["function_id"] and p["parameter"] == row["parameter"] and p["status"] == "contradicted"]
        selection = next((r for r in context["canonical_construction"]["parameters"]
            if r["function_id"] == fact["function_id"] and r["parameter"] == row.get("parameter")), None)
        if kind == "argument_construction" and selection and selection["reason"] in {
                "graph_semantic_contradiction", "source_value_invalidated", "semantic_relation_contradiction"}:
            negatives.append({"code": selection["reason"], "evidence_ids": selection["evidence_ids"]})
        if negatives:
            proof.update(status="contradicted", diagnostics=negatives,
                evidence_ids=sorted({e for n in negatives for e in n["evidence_ids"]}))
            return proof
        nodes = self._nodes(graph, fact)
        if graph["validation_errors"] or not nodes or any(n["proof_status"] != "proved" for n in nodes):
            return proof
        if kind == "ownership":
            witness = self._borrowed_source_proof(row, fact["function_id"], context, graph)
            if witness is None and row['ownership'] == 'transferred' and row['field'] is None and row['release_api'] is None:
                sources = [s for s in context['construction_contract']['sources'] if s['kind'] == 'cleanup_consumption'
                    and s['verified'] and s['function_id'] == fact['function_id'] and s['parameter'] == row['parameter']]
                if len(sources) == 1:
                    witness = {'kind': 'source_exact_cleanup_consumption',
                        'construction_id': sources[0]['construction_id'], 'evidence_ids': sources[0]['evidence_ids']}
            if witness is None:
                return proof
            proof["source_witness"] = witness
        if kind == "state" and (row["kind"] in {"none", "unknown"} or row["api"] is None):
            return proof
        proof.update(status="proved", obligation_ids=sorted(n["obligation_id"] for n in nodes),
            evidence_ids=sorted({e for n in nodes for e in n["evidence_ids"]}))
        signature = selection["recipe"] if kind == "argument_construction" else fact["value"]
        proof["equivalence_key"] = digest({k: v for k, v in signature.items() if k not in {"recipe_id", "version"}})
        return proof

    def _lifecycle_necessity(self, result, requirement, alternatives):
        """Retire cleanup fields only after independent owner/release proofs."""
        if requirement['kind'] != 'lifecycle':
            return None
        rows = [f['value']['resources'][0] for f in alternatives]
        api_changes = len({r['cleanup']['api'] for r in rows}) > 1
        def rest(row):
            value = deepcopy(row)
            value['cleanup'].pop('mandatory')
            if api_changes:
                value['cleanup'].pop('api')
            return value
        if any(rest(row) != rest(rows[0]) for row in rows):
            return None
        selected = [f for f in alternatives if f['value']['resources'][0]['cleanup']['mandatory']
            and (not api_changes or f['value']['resources'][0]['cleanup']['api'] is not None)]
        if len(selected) != 1:
            return None
        chosen = selected[0]
        row = chosen['value']['resources'][0]
        if api_changes and any(r['cleanup']['api'] not in {None, row['cleanup']['api']} for r in rows):
            return None  # A second concrete release is not disproved by this witness.
        fid = chosen['function_id']
        from .value_flow import complete_bodies
        issued = complete_bodies(self.snapshot, self.state.evidence)
        if fid not in issued:
            return None
        alternative = deepcopy(result)
        alternative['facts'] = [f for f in result['facts'] if f not in alternatives] + [chosen]
        context, closure, graph = self._projection(alternative, requirement)
        if graph['validation_errors']:
            return None
        owners = [o for o in context['ownership_contract']['entries'] if o['function_id'] == fid
            and o['return_value'] == row['return_value'] and o['parameter'] == row['subject_parameter']
            and o['field'] is None]
        if not owners or any(o['ownership'] != 'owned' or o['lifetime'] != 'until_release' for o in owners):
            return None
        from .proposals import ownership_subject
        subject = ownership_subject(owners[0], fid, self.snapshot)
        nodes = [n for n in graph['nodes'] if n['predicate'] == 'ownership_subject'
            and any(s.get('subject_id') == subject['subject_id'] for s in n['local_proof']['sources'])]
        if not nodes or any(n['proof_status'] != 'proved' for n in nodes):
            return None
        scope = ['cleanup.mandatory']
        source_eids = set(issued[fid])
        if api_changes:
            from .resource_identity import parameter_release_proof, exact_cleanup_connection
            cleanup = row['cleanup']['api']
            if cleanup not in issued or cleanup not in {r['function_id'] for r in closure['required_support_apis']}:
                return None
            owner_resources = {o['resource_id'] for o in owners}
            if len(owner_resources) != 1 or any(o['release_api'] not in {None, cleanup} for o in owners):
                return None
            connection = None
            projected_cleanup = any(s['kind'] == 'owned_return_cleanup' and s['function_id'] == fid
                and s['cleanup_api'] == cleanup for s in context['construction_contract']['sources'])
            if any(o['release_api'] is None for o in owners) or projected_cleanup:
                # A returned owned object may leave its cleanup API omitted.
                # Do not fill the ownership fact: certify only this selected
                # lifecycle correction with independent allocation, same
                # caller origin and exact nonescaping release evidence.
                if not row['return_value'] or row['subject_parameter'] is not None:
                    return None
                connection = exact_cleanup_connection(context, self.snapshot, self.state.evidence,
                    fid, None, True, cleanup)
                if not connection or connection['resource_id'] not in owner_resources:
                    return None
            slots = [p for p in context['canonical_construction']['parameters']
                if p['function_id'] == cleanup and p['status'] == 'resolved'
                and (p.get('recipe') or {}).get('resource_id') in owner_resources]
            releases = [(p, parameter_release_proof(self.snapshot.functions[cleanup], p['parameter'], self.snapshot, issued))
                for p in slots]
            releases = [(p, release) for p, release in releases if release]
            if len(releases) != 1:
                return None
            scope.append('cleanup.api')
            source_eids.update(e for api in releases[0][1]['source_function_ids'] for e in issued[api])
            if connection:
                source_eids.update(connection['evidence_ids'])
        witness = {'status': 'proved', 'proof_scope': scope,
            'kind': 'independent_owned_until_release_obligation',
            'obligation_ids': sorted(n['obligation_id'] for n in nodes),
            'evidence_ids': sorted(source_eids | {e for n in nodes for e in n['evidence_ids']}),
            'graph_digest': graph['graph_digest'], 'cleanup_api_proved': api_changes}
        if api_changes and connection:
            witness['source_witness'] = connection
        return chosen, witness

    def _lifecycle_creation(self, result, requirement, alternatives):
        """An exact fresh pointer return can replace an omitted self creator."""
        if requirement['kind'] != 'lifecycle':
            return None
        fid = requirement['subject_function_id']
        rows = [f['value']['resources'][0] for f in alternatives]
        if any(not r['return_value'] or r['subject_parameter'] is not None
                or r['creation']['kind'] != 'creator_api' or r['creation']['api'] not in {None, fid} for r in rows):
            return None
        def rest(row):
            value = deepcopy(row)
            value['creation'].pop('api')
            return value
        if any(rest(row) != rest(rows[0]) for row in rows):
            return None
        selected = [f for f in alternatives if f['value']['resources'][0]['creation']['api'] == fid]
        if len(selected) != 1:
            return None
        from .resource_identity import allocated_export_proof
        from .value_flow import complete_bodies
        issued = complete_bodies(self.snapshot, self.state.evidence)
        source = self.snapshot.functions[fid]
        if source.get('return_pointer_depth') != 1 or not allocated_export_proof(source, self.snapshot, issued):
            return None
        chosen = selected[0]
        alternative = deepcopy(result)
        alternative['facts'] = [f for f in result['facts'] if f not in alternatives] + [chosen]
        context, closure, graph = self._projection(alternative, requirement)
        if graph['validation_errors']:
            return None
        return chosen, {'status': 'proved', 'proof_scope': ['creation.api'],
            'kind': 'source_exact_allocated_pointer_return', 'evidence_ids': sorted(issued[fid]),
            'graph_digest': graph['graph_digest']}

    def reconcile(self, result, requirement):
        """Select a unique source-supported class; preserve all other subjects."""
        result, completions = self._extent_completions(result, requirement)
        result, callbacks = self._callback_completions(result, requirement)
        completions += callbacks
        field = COLLECTIONS.get(requirement["kind"])
        if not field or not fact_conflicts(result["facts"]):
            return result, completions
        # Conflicting collection metadata has no exact-subject replacement.
        extras = [{k: v for k, v in f["value"].items() if k != field} for f in result["facts"]]
        if any(e != extras[0] for e in extras):
            return result, completions
        groups = {}
        for fact in result["facts"]:
            values = fact["value"][field]
            if len(values) != 1:
                return result, completions
            groups.setdefault(subject_key(requirement["kind"], values[0]), []).append(fact)
        result, withdrawals = deepcopy(result), completions
        for key, alternatives in sorted(groups.items(), key=lambda item: canonical(item[0])):
            if len(alternatives) < 2:
                continue
            necessity = (self._lifecycle_necessity(result, requirement, alternatives)
                or self._lifecycle_creation(result, requirement, alternatives))
            if necessity:
                chosen, witness = necessity
                result['facts'] = [f for f in result['facts'] if f not in alternatives] + [chosen]
                for fact in alternatives:
                    if fact is chosen:
                        continue
                    withdrawals.append({'requirement_id': requirement['requirement_id'], 'subject_key': list(key),
                        'withdrawn_fact': deepcopy(fact), 'replacement_fact_id': chosen['fact_id'],
                        'reason': ('source_checked_allocated_return_creator' if witness['proof_scope'] == ['creation.api']
                            else 'source_checked_ownership_requires_cleanup'),
                        'previous_proof': {'status': 'contradicted', 'proof_scope': witness['proof_scope']},
                        'replacement_proof': witness, 'source_fingerprint': self.snapshot.source_fingerprint})
                continue
            proofs = [(fact, self.assess(result, requirement, fact)) for fact in alternatives]
            proved = [(f, p) for f, p in proofs if p["status"] == "proved"]
            if not proved or len({p["equivalence_key"] for f, p in proved}) != 1:
                continue
            if any(p["protected"] for f, p in proofs) and any(p["status"] != "proved" for f, p in proofs):
                continue
            # Preserve a proved existing representative; otherwise canonical
            # selection is content based and independent of answer chronology.
            chosen, witness = min(proved, key=lambda pair: (not bool(pair[1]["protected"]), canonical(pair[0]["value"])))
            if (requirement["kind"] == "ownership" and
                    witness.get("source_witness", {}).get("lifetime_bound") == "until_release"):
                selected_row = chosen["value"][field][0]
                def same_borrowed_short_claim(fact, proof):
                    row = fact["value"][field][0]
                    return (proof["status"] == "contradicted" and row["lifetime"] == "during_call"
                        and row["ownership"] == "borrowed" and row["release_api"] is None
                        and {k: v for k, v in row.items() if k != "lifetime"}
                            == {k: v for k, v in selected_row.items() if k != "lifetime"})
                if any(not same_borrowed_short_claim(fact, proof) for fact, proof in proofs if fact is not chosen):
                    continue  # Never retire explicit owned/static/unknown or a missing claim.
            equivalent_eids = {e for f, p in proved for e in f["evidence_ids"]}
            replacement = deepcopy(chosen)
            replacement["evidence_ids"] = sorted(equivalent_eids)
            replacement["fact_id"] = fact_id(replacement)
            result["facts"] = [f for f in result["facts"] if f not in alternatives] + [replacement]
            for fact, proof in proofs:
                if fact is chosen:
                    continue
                withdrawals.append({"requirement_id": requirement["requirement_id"], "subject_key": list(key),
                    "withdrawn_fact": deepcopy(fact), "replacement_fact_id": replacement["fact_id"],
                    "reason": "equivalent_proven_recipe" if proof["status"] == "proved" else
                        "source_disproved" if proof["status"] == "contradicted" else "unique_source_supported_selection",
                    "previous_proof": proof, "replacement_proof": witness,
                    "source_fingerprint": self.snapshot.source_fingerprint})
        if withdrawals:
            result["facts"].sort(key=lambda f: f["fact_id"])
            dependencies = supported_dependencies(result)
            retired = [d for d in result["discovered_api_dependencies"] if d not in dependencies]
            result["discovered_api_dependencies"] = dependencies
            if retired:
                withdrawals[0]["withdrawn_dependencies"] = deepcopy(retired)
        return result, withdrawals
