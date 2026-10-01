"""Project typed frozen contracts into an executable, provider-free plan."""
from copy import deepcopy
from pathlib import Path
import re

from ..semantic_discovery.models import digest
from ..semantic_slicing.frontier import function_types

PLAN_POLICY = "frozen-context-harness-plan-v8"


class PlanError(ValueError):
    pass


def _shape(row):
    return {k: v for k, v in row.items() if k not in {"fact_id", "evidence_ids", "function_id"}}


class HarnessPlanBuilder:
    def build(self, minimal_ft, context, closure, snapshot, completeness, *, language="c++", headers=(), max_input_bytes=1048576):
        if (completeness.get("generation_allowed") is not True or context.get("frozen") is not True
                or completeness.get("status") != "complete" or completeness.get("hard_missing") or completeness.get("validation_errors")):
            raise PlanError("generation requires generation_allowed=true and frozen=true with a complete gate")
        ft_id = minimal_ft["ft_id"]
        core = sorted(row["function_id"] for row in minimal_ft["core_functions"])
        if (context["ft_id"] != ft_id or closure["ft_id"] != ft_id or completeness["ft_id"] != ft_id
                or context["core_apis"] != core or closure["core_apis"] != core
                or context["minimal_ft_digest"] != digest(minimal_ft) or closure["minimal_ft_digest"] != digest(minimal_ft)):
            raise PlanError("frozen input identities disagree")
        if language not in {"c", "c++"} or type(max_input_bytes) is not int or not 1 <= max_input_bytes <= 16777216:
            raise PlanError("invalid language or max_input_bytes")
        headers = tuple(sorted(set(headers)))
        if any(not isinstance(h, str) or not re.fullmatch(r"[A-Za-z0-9_./+-]+\.(?:h|hpp|hh)", h)
               or Path(h).is_absolute() or ".." in Path(h).parts for h in headers):
            raise PlanError("headers must be project-relative header paths")
        active = set(core) | {row["function_id"] for row in closure["required_support_apis"]}
        if active & set(minimal_ft["excluded_functions"]) or any(fid not in snapshot.functions for fid in active):
            raise PlanError("unknown or excluded API")
        declarations = []
        for fid in sorted(active):
            function = snapshot.functions[fid]
            if not function.get("defined") or "static" in function.get("storage", []):
                raise PlanError("callable API definition is unavailable")
            declarations.append({"function_id": fid, "symbol": function["name"], "signature": function["signature"],
                "parameters": deepcopy(function["parameters"]), "return_type": function["return_type"],
                "return_pointer_depth": function.get("return_pointer_depth", 0),
                "linkage": "c" if Path(function["file"]).suffix == ".c" else "c++"})
        if len({row["symbol"] for row in declarations}) != len(declarations):
            raise PlanError("overloaded or duplicate API symbols require an explicit ABI adapter")
        types = set().union(*(function_types(snapshot.functions[fid]) for fid in active))
        structs = []
        for _ in range(len(snapshot.artifacts.structs) + 1):
            added = False
            for struct in snapshot.artifacts.structs:
                if types & {struct["name"], *struct.get("aliases", [])} and struct["declaration"] not in structs:
                    structs.append(struct["declaration"])
                    types |= set(re.findall(r"[A-Za-z_]\w*", struct["declaration"]))
                    added = True
            if not added:
                break
        typedef_declarations = [d["declaration"] for d in snapshot.artifacts.callback_typedefs if d["name"] in types]
        contracts = {key: deepcopy(value) for key, value in context.items() if key.endswith("_contract")
            and key not in {"construction_contract", "resource_contract", "invocation_contract", "parameter_semantic_contract"}}
        for section in contracts.values():
            for key, rows in section.items():
                section[key] = [row for row in rows if row["function_id"] in active]
        resources = contracts["lifecycle_contract"]["resources"]
        by_resource = {row["resource_id"]: {**deepcopy(row), "bindings": [b for b in row["bindings"] if b["function_id"] in active]}
            for row in context["resource_contract"]["resources"] if any(b["function_id"] in active for b in row["bindings"])}
        for binding in contracts["input_contract"]["bindings"]:
            if binding["source"] != "context" or binding["via_function_id"] is None:
                continue
            consumers = [row for row in resources if row["function_id"] == binding["function_id"]
                         and row["subject_parameter"] == binding["parameter"]]
            if len(consumers) != 1:
                raise PlanError("context input path needs one explicit consumer resource")
            consumer = consumers[0]
            origins = {row["resource_id"] for row in resources if row["function_id"] == binding["via_function_id"]
                       and row["type"] == consumer["type"]}
            if consumer["resource_id"] not in origins:
                raise PlanError("context input path lacks a shared resource identity with its input API")
        edges = set()
        graph = context["ordering_graph"]
        if graph["hard_cycles"]:
            raise PlanError("hard ordering cycle: " + str(graph["hard_cycles"]))
        for order in graph["edges"]:
            if order["strength"] == "hard":
                before, after = order["before"], order["after"]
                if before not in active or after not in active:
                    raise PlanError("ordering relies on an API outside the required closure")
                edges.add((before, after))
        ordered, remaining = [], set(active)
        cleanup_ids = {r["cleanup"]["api"] for r in resources if r["cleanup"]["mandatory"]} - set(core)
        while remaining:
            available = sorted((fid for fid in remaining if not any(b == fid and a in remaining for a, b in edges)),
                               key=lambda fid: (fid in cleanup_ids, fid))
            if not available:
                raise PlanError("cyclic API order")
            # Select a legal order with independent active calls before cleanup.
            # Hard cleanup-before-use edges still force an early cleanup and
            # fail the explicit lifetime-schedule check below.
            fid = available[0]
            ordered.append(fid)
            remaining.remove(fid)
        cleanup_resources, created_resources, initialized_resources = {}, {}, {}
        for rid, resource in by_resource.items():
            for action, mapping in (("creation", created_resources), ("cleanup", cleanup_resources)):
                api = resource[action]["api"]
                if api:
                    mapping.setdefault(api, []).append(rid)
        for obligation in context["invocation_contract"]["initializations"]:
            action = obligation["initialization"]
            if obligation["function_id"] in active and action["mandatory"] and action["api"]:
                initialized_resources.setdefault(action["api"], []).append(obligation["resource_id"])
        initialized_resources = {api: sorted(set(ids)) for api, ids in initialized_resources.items()}
        for fid in active:
            if fid in cleanup_resources and fid in core:
                raise PlanError("CORE cleanup role needs explicit invocation multiplicity")
        arguments = contracts["argument_contract"]["arguments"]
        bindings = contracts["input_contract"]["bindings"]
        from .recipes import lower_recipes
        try:
            recipes=lower_recipes(context,active,snapshot)
        except (ValueError,KeyError,TypeError) as error:
            raise PlanError(str(error)) from None
        recipes_by_id={r['recipe_id']:r for r in recipes}
        invocations = []
        for fid in ordered:
            function = snapshot.functions[fid]
            cleanup = fid in cleanup_resources
            resource_instances = cleanup_resources.get(fid) or created_resources.get(fid) or initialized_resources.get(fid) or [None]
            # Repeat support calls per explicit resource, not per shared type.
            if fid in core:
                resource_instances = [None]
            for rid in sorted(set(resource_instances), key=lambda value: value or ""):
                args = []
                for parameter in function["parameters"]:
                    name = parameter["name"]
                    values = [row for row in arguments if row["function_id"] == fid and row["parameter"] == name]
                    if len(values) != 1:
                        raise PlanError("each invocation argument needs one construction contract")
                    value = deepcopy(values[0])
                    if value.get('recipe_id') not in recipes_by_id:
                        raise PlanError('argument is not a canonical recipe projection')
                    recipe=recipes_by_id[value['recipe_id']]
                    value['canonical_recipe']=recipe
                    if recipe.get('binding_expression'):
                        value['binding_expression']=recipe['binding_expression']
                    relevant = [row for row in bindings if row["function_id"] == fid and row["parameter"] == name]
                    size_for = [row for row in bindings if row["function_id"] == fid and row["size_parameter"] == name]
                    candidates = [row["resource_id"] for row in resources if row["function_id"] == fid and row["subject_parameter"] == name]
                    if rid and (cleanup or fid in initialized_resources):
                        type_match = parameter["base_type"] == by_resource[rid]["type"] and parameter.get("is_pointer")
                        if type_match:
                            candidates.append(rid)
                    candidates = sorted(set(candidates + ([value["resource_id"]] if value["resource_id"] else [])))
                    if len(candidates) > 1 or candidates and candidates[0] not in by_resource:
                        raise PlanError("argument resource binding is ambiguous or unknown")
                    value["resource_id"] = candidates[0] if candidates else None
                    if recipe['kind'] == 'out_parameter_storage':
                        if value.get('pointee_resource_id') != recipe['resource_id'] or recipe['resource_id'] not in by_resource:
                            raise PlanError('out storage lacks an explicit pointee lifecycle')
                        value['resource_id'] = None
                    value["binding_role"] = "out_parameter" if recipe['kind'] == 'out_parameter_storage' else "argument"
                    value["input_binding"] = relevant[0] if len(relevant) == 1 else None
                    value["length_for"] = size_for
                    if value["construction"] == "constant" and value["constant"] is None:
                        raise PlanError("constant argument has no explicit value")
                    if value["construction"] == "derived" and not (value["resource_id"] or relevant or size_for or recipe['kind'] in {'derived_scalar', 'out_parameter_storage'}):
                        raise PlanError("derived argument lacks an explicit input, length or resource relation")
                    args.append(value)
                return_resources = sorted({row["resource_id"] for row in resources if row["function_id"] == fid and row["return_value"]}
                    | (set(created_resources.get(fid, [])) if function.get("return_pointer_depth", 0) else set()))
                if len(return_resources) > 1:
                    raise PlanError("creator return aliases need one explicit resource identity")
                result = next((row for row in contracts["return_contract"]["functions"] if row["function_id"] == fid), None)
                invocation = {"function_id": fid, "symbol": function["name"],
                    "role": "core" if fid in core else "cleanup" if cleanup else "create" if fid in created_resources
                            else "initialize" if fid in initialized_resources else "support",
                    "resource_instance": rid, "arguments": args,
                    "return_resource": return_resources[0] if return_resources else None,
                    "out_resources": [{"parameter": a["parameter"], "resource_id": a['pointee_resource_id']} for a in args if a["binding_role"] == "out_parameter"],
                    "result_contract": result, "guard_nullable_resources": True, "calls_per_input": 1}
                invocation["preconditions"] = [deepcopy(p) for p in context["invocation_contract"]["preconditions"]
                    if p["function_id"] == fid and (rid is None or p["resource_id"] in {None, rid})]
                invocation["invocation_id"] = "call_" + digest(invocation)[:24]
                invocations.append(invocation)
        if any(row["role"] != "cleanup" for row in invocations[ next((i for i, row in enumerate(invocations) if row["role"] == "cleanup"), len(invocations)): ]):
            raise PlanError("cleanup interleaved with active API use needs an explicit lifetime schedule")
        transforms = [{"function_id": b["function_id"], "parameter": b["parameter"], "kind": "nul_terminate",
            "steps": ["reject_size_above_max_before_addition", "allocate_bounded_heap", "copy_nonempty_input", "append_zero_at_size", "release_copy_after_use"],
            "max_source_bytes": max_input_bytes, "extra_bytes": 1, "max_allocation_bytes": max_input_bytes + 1,
            "allocation": "heap", "unbounded_stack_allowed": False, "length_parameter": b["size_parameter"]}
            for b in contracts["input_contract"]["bindings"] if b["transform"] == "nul_terminate"]
        plan = {"schema_version": 2, "artifact_kind": "context_harness_plan", "policy_version": PLAN_POLICY,
            "ft_id": ft_id, "entrypoint": "LLVMFuzzerTestOneInput", "language": language,
            "input_digests": {"minimal_ft": digest(minimal_ft), "harness_context": digest(context),
                             "api_closure": digest(closure), "completeness": digest(completeness)},
            "core_apis": core, "required_support_apis": sorted(active - set(core)),
            "api_declarations": declarations, "type_declarations": sorted(typedef_declarations) + sorted(structs), "headers": list(headers),
            "contracts": contracts, "resources": [by_resource[rid] for rid in sorted(by_resource)],
            "invocation_contract": {"version": context["invocation_contract"]["version"],
                "preconditions": [deepcopy(p) for p in context["invocation_contract"]["preconditions"] if p["function_id"] in active],
                "transitions": [deepcopy(t) for t in context["invocation_contract"]["transitions"] if t["before"] in active and t["after"] in active]},
            "input_policy": {"max_bytes": max_input_bytes, "allocation_scope": "per_input", "preserve_binary_zero": True},
            "input_transforms": transforms,
            "callback_policy": {"implementation": "ABI-matching deterministic zero-return stub", "external_effects": False},
            "call_sequence": [row for row in invocations if row["role"] != "cleanup"],
            "cleanup_sequence": [row for row in invocations if row["role"] == "cleanup"],
            "ordering_edges": [list(edge) for edge in sorted(edges)],
            "ordering_provenance": deepcopy(graph),
            "resource_identity": deepcopy(context["resource_identity"]),
            "construction_sources": deepcopy(context["construction_contract"]),
            "canonical_construction_digest":digest(context['canonical_construction']),
            "construction_recipe_version":context['canonical_construction']['recipe_version'],
            "construction_recipes":recipes,
            "failure_policy": "skip dependent calls on failure; release all acquired owned resources on every exit",
            "frozen": True}
        plan["plan_id"] = "plan_" + digest(plan)[:24]
        return plan

    def validate(self, plan, *inputs, **options):
        return plan == self.build(*inputs, **options)
