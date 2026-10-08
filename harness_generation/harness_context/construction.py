"""Source certificates for local resource chains and public callback objects.

No names or shared types establish construction. Certificates cover a deliberately
small C subset; the ordinary model requirements remain when proof is incomplete.
"""
from collections import defaultdict
from copy import deepcopy
import re

from ..semantic_discovery.models import canonical, digest
from ..semantic_discovery.tools import _walk, _text
from .value_flow import body_tree, complete_bodies, resource_flows

VERSION = "verified-construction-v7"


def prepare_local_evidence(tools, facts=(), *, requirements=()):
    """Use existing bounded queries once, charging the normal tool budget."""
    from ..semantic_discovery.tools import ToolBudgetExceeded
    fid = tools.requirement["subject_function_id"]
    function = tools.snapshot.functions[fid]
    has_resource_subject = any(p.get("is_pointer") or p.get("is_struct_like") or p.get("is_opaque_handle")
        for p in function["parameters"]) or function.get("return_pointer_depth")
    events = []
    initial_tool_calls = tools.state.tool_calls
    configured_limit = tools.state.budget.max_preparation_tool_calls
    if not configured_limit:
        return events
    optional_limit = getattr(tools, 'investigation_tool_limit', None)
    tool_ceiling = min(tools.state.budget.max_tool_calls,
        optional_limit if optional_limit is not None else tools.state.budget.max_tool_calls)
    # Leave one repository query for the agent inside the current allocation.
    preparation_limit = min(configured_limit, max(0, tool_ceiling - initial_tool_calls - 1))
    active_kinds = {row['kind'] for row in requirements
        if row['subject_function_id'] == fid} if requirements else {tools.requirement['kind']}
    def visible_bodies():
        return complete_bodies(tools.snapshot, {eid: tools.evidence[eid] for eid in tools.visible_ids})
    def query(name, arguments):
        key = canonical([name, arguments])
        if key in tools.query_cache:
            output = tools.query_cache[key]
            tools.visible_ids.update(output["evidence_ids"])
            events.append({"kind": "tool_call", "tool": name, "arguments": arguments,
                           "result_evidence_ids": output["evidence_ids"], "framework_construction": True,
                           "evidence_reuse": True, "tool_executed": False, "round": 0})
            return tools.query_cache[key]
        if tools.state.tool_calls - initial_tool_calls >= preparation_limit:
            events.append({"kind": "preparation_stop", "reason": "max_preparation_tool_calls",
                           "round": 0, "provider_request": False,
                           "tool_executed": False, "limit": preparation_limit,
                           "configured_limit": configured_limit, "reserved_agent_tool_calls": 1})
            raise ToolBudgetExceeded("preparation_tool_limit")
        before = tools.state.tool_calls
        try:
            output = tools.execute(name, arguments)
        except (ToolBudgetExceeded, OSError, ValueError) as error:
            charged = tools.state.tool_calls > before
            reason = (error.args[0] if isinstance(error, ToolBudgetExceeded) else
                'source_unavailable' if isinstance(error, OSError) else 'source_unavailable_or_invalid_query')
            events.append({"kind": "tool_call" if charged else "preparation_stop",
                "tool": name, "arguments": arguments, "result_evidence_ids": [],
                "framework_construction": True, "round": 0,
                "error": reason, "tool_executed": charged, "provider_request": False})
            raise
        events.append({"kind": "tool_call", "tool": name, "arguments": arguments,
                       "result_evidence_ids": output.get("evidence_ids", []), "framework_construction": True,
                       "tool_executed": True, "error": output.get('error'), "round": 0})
        return output
    expanded_sources = set()
    def complete_source(target):
        if target not in tools.scope_ids or target in expanded_sources:
            return
        indexed = tools.snapshot.functions[target]
        if target not in visible_bodies():
            output = query("get_function", {"function": target})
            record = next((r for r in output.get("evidence", []) if r.get("function_id") == target), None)
            if not record or not record.get("content") or not indexed.get("body", "").startswith(record["content"]):
                return
            start = record["line_end"]  # overlap the possibly truncated last line
            while start <= indexed["end_line"] and target not in visible_bodies():
                end = min(indexed["end_line"], start + tools.state.budget.max_lines_per_read - 1)
                part = query("read_source_range", {"file": indexed["file"], "line_start": start, "line_end": end})
                chunks = part.get("evidence", [])
                if not chunks:
                    break
                last = chunks[-1]
                next_line = last["line_end"] if last.get("truncated") else last["line_end"] + 1
                if next_line <= start:
                    break  # A single line larger than the record budget stays open.
                start = next_line
        if target not in visible_bodies():
            return
        expanded_sources.add(target)
        from .value_flow import unique_callee
        source, body = body_tree(indexed)
        if body is None or body.has_error:
            return
        if target == fid and active_kinds & {'ownership', 'lifecycle'}:
            owners = [row for fact in facts if fact.get('function_id') == fid
                and fact.get('predicate') == 'ownership'
                for row in fact['value']['entries'] if row.get('return_value')]
            if indexed.get('return_pointer_depth') and (not owners or any(
                    row['ownership'] == 'owned' for row in owners)):
                # Only the already issued subject body supplies these exact
                # spellings. Ordinary tools issue target IDs/body evidence;
                # syntax and signatures select no cleanup contract or API.
                from .investigation import _return_cleanup_queries
                from .source_queries import SourceDetails
                try:
                    spellings = _return_cleanup_queries(SourceDetails(tools.snapshot, target),
                        tools.snapshot, {'support_candidates': []}, excluded=tools.excluded)
                except ValueError:
                    spellings = []
                for spelling in spellings[:tools.state.budget.max_references_per_query]:
                    observed = query('get_call_sites', {'function': target, 'callee': spelling})
                    helpers = {api for record in observed.get('evidence', [])
                        for api in record.get('possible_callee_ids', [])
                        if api in tools.scope_ids and api not in tools.excluded}
                    for helper in sorted(helpers, key=lambda api: (
                            'static' in tools.snapshot.functions[api].get('storage', []), api)):
                        complete_source(helper)
        fields, forwarded = set(), set()
        formal_pointers = {p['name'] for p in indexed['parameters'] if p.get('is_pointer')}
        for node in _walk(body):
            if node.type == 'assignment_expression':
                left, right = node.child_by_field_name('left'), node.child_by_field_name('right')
                while right.type in {'parenthesized_expression', 'pointer_expression'} and len(right.named_children) == 1:
                    right = right.named_children[0]
                if left.type == 'field_expression' and right.type == 'identifier' and unique_callee(tools.snapshot, _text(right, source), indexed):
                    fields.add(_text(left.child_by_field_name('field'), source))
            if node.type != 'call_expression':
                continue
            callee = node.child_by_field_name('function')
            project = unique_callee(tools.snapshot, _text(callee, source), indexed) if callee.type == 'identifier' else None
            args = node.child_by_field_name('arguments').named_children
            if project and (node.parent.type == 'return_statement' or any(
                    a.type == 'identifier' and _text(a, source) in formal_pointers for a in args)):
                forwarded.add(project['id'])
        for field_name in sorted(fields)[:tools.state.budget.max_references_per_query]:
            output = query('find_field_writes', {'function': target, 'field': field_name})
            helpers = {api for record in output.get('evidence', []) for api in record.get('possible_callee_ids', [])
                if api in tools.scope_ids}
            for helper in sorted(helpers)[:tools.state.budget.max_references_per_query]:
                complete_source(helper)
        if forwarded:
            query('find_callees', {'function': target})
            for helper in sorted(forwarded)[:tools.state.budget.max_references_per_query]:
                if helper not in tools.excluded:
                    complete_source(helper)
    try:
        complete_source(fid)
        if not has_resource_subject:
            return events
        output = query("find_resource_flows", {"function": fid})
        callers = sorted({r["caller_id"] for r in output.get("evidence", []) if r.get("caller_id")})
        for caller in callers[:tools.state.budget.max_references_per_query]:
            # Scope discovery remains owned by the existing find_callees tool.
            query("find_callees", {"function": caller})
        flow = resource_flows(tools.snapshot, tools.evidence)
        origin_ids = {r["resource_id"] for r in flow["observations"] if r["function_id"] == fid}
        related = {r["function_id"] for r in flow["observations"] if r["resource_id"] in origin_ids}
        # Use the generic graph to target creator arguments, out slots and
        # type-erased callback userdata. Structural types never certify roles.
        from .evidence import build_context
        preview = build_context(tools.ft, [tools.requirement], list(facts), tools.snapshot, tools.evidence)
        graph = preview["argument_graph"]
        nodes = {n["node_id"]:n for n in graph["nodes"]}
        origin_ids |= {r.get("resource_id") for r in graph["construction_candidates"]
            if nodes[r["target_parameter"]]["function_id"] == fid and r.get("resource_id")}
        related |= {r["origin"]["function_id"] for r in graph["resource_origins"] if r["resource_id"] in origin_ids}
        related |= {nodes[dep]["function_id"] for hole in graph["dependency_graph"]["unresolved_parameters"]
            if hole["function_id"] == fid for dep in hole["missing_dependencies"] if nodes.get(dep,{}).get("node_type")=="Parameter"}
        for target in sorted(related)[:tools.state.budget.max_references_per_query]:
            if target in tools.scope_ids:
                complete_source(target)
    except (ToolBudgetExceeded, ValueError, OSError):
        pass  # Evidence limits never become permission to guess construction.
    return events


def plain_fields(function, parameter):
    """Return member reads/writes only when the object never escapes."""
    source, body = body_tree(function)
    if body is None or body.has_error:
        return None
    nodes = list(_walk(body))
    if any(n.type in {"call_expression", "cast_expression", "goto_statement", "preproc_if", "update_expression"} for n in nodes):
        return None
    reads, writes = set(), {}
    for node in nodes:
        if node.type == "identifier" and _text(node, source) == parameter:
            if node.parent.type != "field_expression" or node.parent.child_by_field_name("argument") != node:
                return None
        if node.type != "field_expression" or _text(node.child_by_field_name("argument"), source) != parameter:
            continue
        field = _text(node.child_by_field_name("field"), source)
        parent = node.parent
        if parent.type == "assignment_expression" and parent.child_by_field_name("left") == node:
            value = parent.child_by_field_name("right")
            if _text(parent.child_by_field_name("operator"), source) != "=" or value.type != "identifier":
                return None
            if field in writes or _text(value, source) not in {p["name"] for p in function["parameters"]}:
                return None
            writes[field] = _text(value, source)
        else:
            reads.add(field)
    if writes and any(n.type in {"if_statement", "switch_statement", "for_statement", "while_statement", "do_statement", "conditional_expression"} for n in nodes):
        return None
    return {"reads": sorted(reads), "writes": writes} if reads or writes else None


def zero_creator(function, snapshot):
    if function.get("return_pointer_depth") != 1 or function.get("parameters"):
        return False
    if any(f["name"] == "calloc" for f in snapshot.functions.values()):
        return False
    kind = re.escape(function.get("return_base_type", ""))
    # Exact builtin allocation of one declared object, no preceding free,
    # side effects, alternative return or hidden initialization to guess.
    return bool(re.fullmatch(r"\s*\{\s*return\s+calloc\s*\(\s*1\s*,\s*sizeof\s*\(\s*(?:struct\s+)?" + kind + r"\s*\)\s*\)\s*;\s*\}\s*", function.get("body", "")))


def plain_release(function, parameter, snapshot):
    return not any(f["name"] == "free" for f in snapshot.functions.values()) and bool(re.fullmatch(
        r"\s*\{\s*free\s*\(\s*" + re.escape(parameter) + r"\s*\)\s*;\s*\}\s*", function.get("body", "")))


def local_chains(snapshot, records, allowed):
    bodies = complete_bodies(snapshot, records)
    flow = resource_flows(snapshot, records)
    groups, endpoints = defaultdict(list), defaultdict(set)
    for row in flow["observations"]:
        groups[row["resource_id"]].append(row)
        endpoints[(row["function_id"], row["parameter"], row["return_value"])].add(row["resource_id"])
    chains = []
    for rid, rows in sorted(groups.items()):
        if any(r.get('conditional') for r in rows):
            # Value identity alone does not prove that every lifecycle stage
            # executes. Conditional uses cannot certify a complete local chain.
            continue
        origins = [r for r in rows if r["return_value"] and r["origin"]["kind"] == "return"]
        if len(origins) != 1:
            continue
        origin = origins[0];creator = origin["function_id"]
        if creator not in bodies or creator not in allowed or not zero_creator(snapshot.functions[creator], snapshot):
            continue
        consumers, releases = [], []
        incomplete = False
        for row in rows:
            fid, name = row["function_id"], row["parameter"]
            if row["return_value"]:
                continue
            if fid not in bodies or fid not in allowed or len(endpoints[(fid, name, False)]) != 1:
                incomplete = True
                continue
            function = snapshot.functions[fid]
            if plain_release(function, name, snapshot):
                releases.append(row)
            else:
                fields = plain_fields(function, name)
                if fields and not function.get("return_pointer_depth"):
                    consumers.append({**row, **fields})
                else:
                    incomplete = True
        if incomplete or len(releases) != 1 or not consumers:
            continue
        release = releases[0]
        # Repeated calls and use after release require a multiplicity schedule.
        if len({(r["function_id"], r["parameter"]) for r in consumers}) != len(consumers):
            continue
        if any(not origin["call_offset"] < r["call_offset"] < release["call_offset"] for r in consumers):
            continue
        dependencies = []
        for consumer in consumers:
            for producer in consumers:
                fields = set(producer["writes"]) & set(consumer["reads"])
                if fields and producer["call_offset"] < consumer["call_offset"]:
                    dependencies.append({"before": producer["function_id"], "after": consumer["function_id"], "fields": sorted(fields)})
        eids = sorted({e for r in rows for e in r["evidence_ids"]} | {e for r in [origin, release, *consumers] for e in bodies[r["function_id"]]})
        chain = {"kind": "creator_return", "resource_id": rid, "type": origin["origin"]["type"],
                 "pointer_depth": origin["origin"]["pointer_depth"], "creator_api": creator,
                 "cleanup_api": release["function_id"], "cleanup_parameter": release["parameter"],
                 "origin": origin["origin"], "consumers": consumers, "state_transitions": dependencies,
                 "evidence_ids": eids, "verified": True, "allocation_scope": "per_input"}
        chain["construction_id"] = "construction_" + digest(chain)[:24]
        chains.append(chain)
    return chains


def public_callback_object(context, function, name, snapshot, records):
    from .callbacks import parse_declaration
    if function["id"] not in complete_bodies(snapshot, records):
        return None
    param = next(p for p in function["parameters"] if p["name"] == name)
    if param.get("pointer_depth") != 1:
        return None
    layouts = [s for s in snapshot.artifacts.structs if param["base_type"] in {s["name"], *s.get("aliases", [])}]
    if len(layouts) != 1:
        return None
    source, root = parse_declaration(layouts[0]["declaration"])
    fields = {}
    if root.has_error:
        return None
    for node in _walk(root):
        if node.type == "field_declaration":
            names = [n for n in _walk(node) if n.type == "field_identifier"]
            if len(names) != 1 or any(n.type in {"array_declarator", "bitfield_clause"} for n in _walk(node)):
                return None
            fields[_text(names[0], source)] = _text(node, source)
    callbacks = [c for c in context["callback_contract"]["callbacks"] if c["function_id"] == function["id"] and c["parameter"] == name]
    if not callbacks or any(not c.get("declaration_identity") or c["setup_api"] is not None or c["lifetime"] == "unknown" or c["null_allowed"] is None for c in callbacks):
        return None
    assignments, initialized, targets = [], set(), set()
    for cb in callbacks:
        identity = cb["declaration_identity"]
        if identity.get("field_path") or identity["field"] not in fields:
            return None
        targets.add(name + "." + identity["field"]);initialized.add(identity["field"])
        assignments.append({"field": identity["field"], "source": "callback_stub", "callback_id": identity["callback_id"]})
        if cb["userdata"]:
            user = cb.get("userdata_binding", {})
            member = user.get("identity", "").split(".")
            if not user.get("source_verified") or len(member) != 2 or member[0] != name or member[1] not in fields:
                return None
            if not re.fullmatch(r"\s*(?:const\s+)?void\s*\*\s*" + re.escape(member[1]) + r"\s*;\s*", fields[member[1]]):
                return None
            initialized.add(member[1]);assignments.append({"field": member[1], "source": "null_userdata_for_non_dereferencing_stub"})
    # Even an unread extra field may impose a construction invariant. Require
    # the complete layout to consist exclusively of the verified assignments.
    if set(fields) != initialized:
        return None
    source, body = body_tree(function)
    if body is None or body.has_error:
        return None
    used = set()
    for node in _walk(body):
        if node.type in {"assignment_expression", "update_expression", "cast_expression", "goto_statement", "preproc_if"}:
            return None
        if node.type == "identifier" and _text(node, source) == name:
            if node.parent.type != "field_expression" or node.parent.child_by_field_name("argument") != node:
                return None
        if node.type == "field_expression" and _text(node.child_by_field_name("argument"), source) == name:
            used.add(_text(node.child_by_field_name("field"), source))
        if node.type == "call_expression" and re.sub(r"\s+", "", _text(node.child_by_field_name("function"), source)).replace("->", ".") not in targets:
            return None
    if not used or not used <= initialized:
        return None
    owners = [o for o in context["ownership_contract"]["entries"] if o["function_id"] == function["id"] and o["parameter"] == name and o["field"] is None]
    if len(owners) != 1 or owners[0]["ownership"] != "borrowed" or owners[0]["lifetime"] != "during_call" or owners[0]["release_api"] is not None:
        return None
    certificate = {"function_id": function["id"], "parameter": name, "kind": "public_callback_object", "verified": True,
        "storage": "stack", "initialization": "zero_init_then_explicit_fields", "owner_type": param["base_type"],
        "declaration": layouts[0]["declaration"], "assignments": sorted(assignments, key=canonical),
        "escape_analysis": "only_synchronous_declared_field_callbacks", "allocation_scope": "per_input",
        "until": "call_return", "evidence_ids": sorted(complete_bodies(snapshot, records)[function["id"]] | {e for c in callbacks for e in c["evidence_ids"]})}
    certificate["construction_id"] = "construction_" + digest(certificate)[:24]
    return certificate


def project_owned_return_cleanup(context, snapshot, records, allowed):
    """Fill only an omitted release API for one already owned pointer return.

    The model must select the mandatory lifecycle cleanup and declare ownership
    and lifetime. Fresh, unretained allocation, one exact caller origin and its
    all-path release are recomputed independently. Explicit ownership/lifetime
    or a different concrete release API remains unchanged and blocking.
    """
    from .resource_identity import exact_cleanup_connection
    owners = context['ownership_contract']['entries']
    certificates = []
    for owner in owners:
        fid = owner['function_id']
        if (owner.get('subject_kind') != 'PointerReturn' or not owner['return_value']
                or owner.get('parameter') is not None or owner.get('field') is not None
                or owner['ownership'] != 'owned' or owner['lifetime'] != 'until_release'
                or owner['release_api'] is not None or fid not in allowed):
            continue
        siblings = [o for o in owners if o['function_id'] == fid and o['return_value']
            and o.get('parameter') is None and o.get('field') is None]
        resources = [r for r in context['lifecycle_contract']['resources'] if r['function_id'] == fid
            and r['return_value'] and r['subject_parameter'] is None]
        if (len(siblings) != 1 or len(resources) != 1 or not resources[0]['cleanup']['mandatory']
                or resources[0]['cleanup']['api'] not in allowed):
            continue
        cleanup = resources[0]['cleanup']['api']
        connection = exact_cleanup_connection(context, snapshot, records, fid, None, True, cleanup)
        if not connection:
            continue
        certificate = {'kind': 'owned_return_cleanup', 'verified': True,
            'function_id': fid, 'parameter': None, 'creator_api': fid,
            'cleanup_api': cleanup, 'resource_id': connection['resource_id'],
            'evidence_ids': connection['evidence_ids'], 'source_witness': connection,
            'proof_scope': ['release_api'], 'semantic_fact_id': owner.get('fact_id')}
        certificate['construction_id'] = 'construction_' + digest(certificate)[:24]
        owner.update(release_api=cleanup, construction_source=certificate['construction_id'])
        certificates.append(certificate)
    return certificates


def project_cleanup_consumption(context, snapshot, records, allowed):
    """Bind a source-proved cleanup slot to one existing owned return.

    The producer's already grounded ownership/lifecycle contract remains a
    prerequisite. Only consumption and the cleanup argument are source-derived.
    """
    from .resource_identity import allocated_return, parameter_release_proof
    bodies = complete_bodies(snapshot, records)
    observations = resource_flows(snapshot, records)["observations"]
    resources = context["lifecycle_contract"]["resources"]
    owners = context["ownership_contract"]["entries"]
    arguments = context["argument_contract"]["arguments"]
    certificates = []
    release_bodies = {api: eids for api, eids in bodies.items() if api in allowed}
    for fid in sorted(allowed - set(context["core_apis"])):
        function = snapshot.functions[fid]
        if fid not in bodies or function["return_type"].strip() != "void":
            continue
        for param in function['parameters']:
            name = param['name']
            if param.get('pointer_depth') != 1:
                continue
            release = parameter_release_proof(function, name, snapshot, release_bodies)
            if not release:
                continue
            # Two independently released formals must not both be assigned the
            # same unique producer merely because their pointer types match.
            if any(p['name'] != name and p.get('pointer_depth') == 1 and p['base_type'] == param['base_type']
                    and parameter_release_proof(function, p['name'], snapshot, release_bodies)
                    for p in function['parameters']):
                continue
            producers = [r for r in resources if r["return_value"] and r["cleanup"] == {"mandatory": True, "api": fid}
                and r["type"] == param["base_type"] and r["function_id"] in allowed & bodies.keys()
                and snapshot.functions[r["function_id"]].get("return_pointer_depth") == 1
                and any(o["function_id"] == r["function_id"] and o["return_value"] and o["ownership"] == "owned"
                        and o["release_api"] == fid for o in owners)]
            if len(producers) != 1:
                continue
            producer = producers[0]
            origins = {r["resource_id"] for r in observations if r["function_id"] == producer["function_id"] and r["return_value"]}
            consumed = {r["resource_id"] for r in observations if r["function_id"] == fid and r["parameter"] == name and not r["return_value"]}
            paired = origins & consumed
            if (origins and consumed and not paired) or (not paired and not allocated_return(snapshot.functions[producer['function_id']], snapshot)):
                continue
            # Callers demonstrate legal API pairs, not the multiplicity of a
            # new harness. One declared owned CORE return has one invocation
            # slot even when many independent examples call that API.
            single_invocation = len(origins) > 1 or bool(consumed - origins)
            rid = (next(iter(origins)) if len(origins) == 1 and not single_invocation else
                'resource_' + digest({'function_id': producer['function_id'], 'kind': 'return',
                    'parameter': None, 'type': producer['type']})[:24])
            args = [a for a in arguments if a["function_id"] == fid and a["parameter"] == name]
            own = [o for o in owners if o["function_id"] == fid and o["parameter"] == name and o["field"] is None]
            if len(args) > 1 or len(own) > 1 or any(a["api"] not in {None, producer["function_id"]}
                    or a["construction"] not in {"input", "unknown", "derived", "creator_api"} or a["constant"] is not None for a in args):
                continue
            if any(o["release_api"] is not None or o['ownership'] not in {'unknown', 'transferred'} for o in own):
                continue
            proof = {"kind": "cleanup_consumption", "verified": True, "function_id": fid, "parameter": name,
                "creator_api": producer["function_id"], "resource_id": rid, "operation": "free_parameter_once",
                "observed_pair_origins": sorted(paired),
                "evidence_ids": sorted(set().union(*(bodies[f] for f in release['source_function_ids']))
                    | set(bodies[producer["function_id"]]) | set(producer["evidence_ids"])
                    | {e for row in observations if row['resource_id'] in paired for e in row['evidence_ids']})}
            if single_invocation:
                proof.update(binding_scope='single_harness_invocation')
            proof["construction_id"] = "construction_" + digest(proof)[:24]
            if not args:
                arguments.append({"function_id": fid, "parameter": name, "construction": "derived", "api": None,
                    "constant": None, "resource_id": rid, "fact_id": None, "evidence_ids": proof["evidence_ids"],
                    "construction_source": proof["construction_id"]})
            else:
                args[0].update(construction="derived", api=None, resource_id=rid, construction_source=proof["construction_id"])
            if not own:
                owners.append({"function_id": fid, "parameter": name, "field": None, "return_value": False,
                    "resource_id": rid, "ownership": "transferred", "release_api": None, "lifetime": "during_call",
                    "fact_id": None, "evidence_ids": proof["evidence_ids"]})
            else:
                own[0].update(ownership="transferred", lifetime="during_call", resource_id=rid)
            certificates.append(proof)
    return certificates


def project_out_cleanup_consumption(context, snapshot, records, allowed):
    """Consume an exact exported pointee, keeping its pointer storage separate."""
    from .resource_identity import allocated_export_proof, parameter_release_proof
    bodies = complete_bodies(snapshot, records)
    issued = {fid: eids for fid, eids in bodies.items() if fid in allowed}
    observations = resource_flows(snapshot, records)['observations']
    owners, arguments = context['ownership_contract']['entries'], context['argument_contract']['arguments']
    certificates = []
    for owner in list(owners):
        creator, output, cleanup = owner['function_id'], owner['parameter'], owner['release_api']
        if (owner.get('subject_kind') != 'OutParameterPointee' or owner['ownership'] != 'owned'
                or owner['lifetime'] != 'until_release' or creator not in issued or cleanup not in issued
                or cleanup in context['core_apis']):
            continue
        producer = snapshot.functions[creator]
        export = allocated_export_proof(producer, snapshot, issued, output)
        if not export:
            continue
        produced = [o for o in observations if o['origin']['function_id'] == creator
            and o['origin']['kind'] == 'out_parameter' and o['origin']['parameter'] == output]
        origins = {o['resource_id'] for o in produced}
        if len(origins) != 1:
            continue
        rid = next(iter(origins))
        lifetimes = [r for r in context['lifecycle_contract']['resources']
            if r['cleanup'] == {'mandatory': True, 'api': cleanup} and r['creation']['api'] == creator
            and any(o['function_id'] == r['function_id'] and o['parameter'] == r['subject_parameter']
                and o['resource_id'] == rid for o in produced)]
        consumed = [o for o in produced if o['function_id'] == cleanup and not o['return_value']]
        slots = {o['parameter'] for o in consumed}
        if not lifetimes or len(slots) != 1:
            continue
        parameter = next(iter(slots))
        function = snapshot.functions[cleanup]
        release = parameter_release_proof(function, parameter, snapshot, issued)
        if not release or any(p['name'] != parameter and parameter_release_proof(function, p['name'], snapshot, issued)
                for p in function['parameters'] if p.get('pointer_depth') == 1):
            continue
        args = [a for a in arguments if a['function_id'] == cleanup and a['parameter'] == parameter]
        own = [o for o in owners if o['function_id'] == cleanup and o['parameter'] == parameter and o['field'] is None]
        if len(args) > 1 or len(own) > 1 or any(a['api'] not in {None, creator} or a['constant'] is not None
                or a['construction'] not in {'unknown', 'derived', 'input', 'creator_api'} for a in args):
            continue
        if any(o['release_api'] is not None or o['ownership'] not in {'unknown', 'transferred'} for o in own):
            continue
        proof = {'kind': 'cleanup_consumption', 'verified': True, 'function_id': cleanup, 'parameter': parameter,
            'creator_api': creator, 'out_parameter': output, 'resource_id': rid, 'operation': 'free_parameter_once',
            'producer_subject_kind': 'OutParameterPointee', 'observed_pair_origins': [rid],
            'evidence_ids': sorted(set(issued[creator]) | set(owner['evidence_ids'])
                | {e for fid in release['source_function_ids'] for e in issued[fid]}
                | {e for o in produced for e in o['evidence_ids']})}
        proof['construction_id'] = 'construction_' + digest(proof)[:24]
        if not args:
            arguments.append({'function_id': cleanup, 'parameter': parameter, 'construction': 'derived', 'api': None,
                'constant': None, 'resource_id': rid, 'fact_id': None, 'evidence_ids': proof['evidence_ids'],
                'construction_source': proof['construction_id']})
        else:
            args[0].update(construction='derived', api=None, resource_id=rid, construction_source=proof['construction_id'])
        if not own:
            owners.append({'function_id': cleanup, 'parameter': parameter, 'field': None, 'return_value': False,
                'resource_id': rid, 'ownership': 'transferred', 'release_api': None, 'lifetime': 'during_call',
                'fact_id': None, 'evidence_ids': proof['evidence_ids']})
        else:
            own[0].update(ownership='transferred', lifetime='during_call', resource_id=rid)
        certificates.append(proof)
    return certificates


def project_allocated_return_creation(context, snapshot, records, allowed):
    """Fill an omitted self creator API only for a proved fresh pointer return."""
    from .resource_identity import allocated_export_proof
    bodies = {fid: eids for fid, eids in complete_bodies(snapshot, records).items() if fid in allowed}
    certificates = []
    for row in context['lifecycle_contract']['resources']:
        fid = row['function_id']
        if (not row['return_value'] or row['creation'] != {'kind': 'creator_api', 'api': None}
                or snapshot.functions[fid].get('return_pointer_depth') != 1
                or not allocated_export_proof(snapshot.functions[fid], snapshot, bodies)):
            continue
        proof = {'kind': 'allocated_return_creation', 'verified': True, 'function_id': fid, 'parameter': None,
            'creator_api': fid, 'resource_id': row['resource_id'], 'evidence_ids': sorted(bodies[fid])}
        proof['construction_id'] = 'construction_' + digest(proof)[:24]
        row['creation'] = {'kind': 'creator_api', 'api': fid}
        certificates.append(proof)
    return certificates


def project_construction(context, snapshot, records, allowed):
    chains = local_chains(snapshot, records, allowed)
    arguments, resources = context["argument_contract"]["arguments"], context["lifecycle_contract"]["resources"]
    entries = project_allocated_return_creation(context, snapshot, records, allowed)
    for chain in chains:
        for use in chain["consumers"]:
            fid, name = use["function_id"], use["parameter"]
            entry = {k: deepcopy(v) for k, v in chain.items() if k not in {"consumers", "state_transitions"}}
            entry.update(function_id=fid, parameter=name, state_transitions=chain["state_transitions"])
            entries.append(entry)
            args = [a for a in arguments if a["function_id"] == fid and a["parameter"] == name]
            if len(args) == 1 and args[0]["construction"] in {"input", "context", "unknown", "derived", "creator_api"} and args[0]["api"] in {None, chain["creator_api"]}:
                args[0].update(construction="derived", api=None, resource_id=chain["resource_id"], construction_source=entry["construction_id"])
            existing = [r for r in resources if r["function_id"] == fid and r["subject_parameter"] == name]
            if not existing:
                resources.append({"function_id": fid, "subject_parameter": name, "return_value": False,
                    "resource_id": chain["resource_id"], "type": chain["type"], "creation": {"kind": "creator_api", "api": chain["creator_api"]},
                    "initialization": {"mandatory": False, "api": None}, "cleanup": {"mandatory": True, "api": chain["cleanup_api"]},
                    "reuse": "per_input", "evidence_ids": chain["evidence_ids"], "fact_id": None, "derived_by": entry["construction_id"]})
            elif len(existing) == 1 and existing[0]["creation"]["api"] in {None, chain["creator_api"]} and existing[0]["cleanup"]["api"] in {None, chain["cleanup_api"]}:
                existing[0].update(creation={"kind": "creator_api", "api": chain["creator_api"]},
                    cleanup={"mandatory": True, "api": chain["cleanup_api"]}, reuse="per_input")
            owners = [o for o in context["ownership_contract"]["entries"] if o["function_id"] == fid and o["parameter"] == name and o["field"] is None]
            if not owners:
                context["ownership_contract"]["entries"].append({"function_id": fid, "parameter": name, "field": None,
                    "return_value": False, "resource_id": chain["resource_id"], "ownership": "borrowed", "release_api": None,
                    "lifetime": "during_call", "fact_id": None, "evidence_ids": chain["evidence_ids"]})
            transitions = [t for t in chain["state_transitions"] if t["after"] == fid and set(use["reads"]) <= set(t["fields"])]
            state = [s for s in context["state_contract"]["preconditions"] if s["function_id"] == fid and s["parameter"] == name]
            if not state and len(transitions) == 1:
                context["state_contract"]["preconditions"].append({"function_id": fid, "parameter": name, "kind": "input_fed",
                    "api": transitions[0]["before"], "fact_id": None, "evidence_ids": chain["evidence_ids"]})
            # Feed is a scheduled consumer operation, not a second global
            # initializer to repeat for every binding of the same object.
            if len(transitions) == 1:
                before = transitions[0]["before"]
                for resource in existing:
                    if resource["initialization"] == {"mandatory": True, "api": before} and any(
                            s["function_id"] == fid and s["parameter"] == name and s["api"] == before
                            and s["kind"] == "input_fed" for s in context["state_contract"]["preconditions"]):
                        resource["initialization"] = {"mandatory": False, "api": None}
        # Bind the release argument explicitly, even when its model resource ID
        # is missing or mismatched. A second allocation is not this cleanup's source.
        for a in arguments:
            if a["function_id"] == chain["cleanup_api"] and a["parameter"] == chain["cleanup_parameter"] and a["construction"] in {"input", "unknown", "derived", "creator_api"} and a["api"] in {None, chain["creator_api"]}:
                a.update(construction="derived", api=None, resource_id=chain["resource_id"], construction_source=chain["construction_id"])
    for a in arguments:
        function = snapshot.functions[a["function_id"]]
        if a["construction"] not in {"input", "unknown", "stack", "zero_init"}:
            continue
        certificate = public_callback_object(context, function, a["parameter"], snapshot, records)
        if not certificate:
            continue
        lifetimes = [r for r in resources if r["function_id"] == a["function_id"] and r["subject_parameter"] == a["parameter"]]
        if len(lifetimes) != 1 or lifetimes[0]["creation"]["kind"] not in {"input", "stack", "borrowed", "unknown"} or lifetimes[0]["cleanup"]["mandatory"] or lifetimes[0]["initialization"]["api"] is not None:
            continue
        a.update(construction="zero_init", api=None, construction_source=certificate["construction_id"])
        lifetimes[0].update(creation={"kind": "stack", "api": None}, reuse="per_input",
                            initialization={"mandatory": False, "api": None})
        entries.append(certificate)
    entries.extend(project_owned_return_cleanup(context, snapshot, records, allowed))
    entries.extend(project_cleanup_consumption(context, snapshot, records, allowed))
    entries.extend(project_out_cleanup_consumption(context, snapshot, records, allowed))
    return {"version": VERSION, "sources": sorted(entries, key=canonical), "local_chains": chains}


def covered_requirements(context, requirements, snapshot):
    """Proof coverage is reported separately; model statuses/facts stay intact."""
    sources = context["construction_contract"]["sources"]
    covered = []
    for req in requirements:
        fid, kind = req["subject_function_id"], req["kind"]
        if req["status"] not in {"open", "unresolved"}:
            continue
        cleanup = [s for s in sources if s["function_id"] == fid and s["kind"] == "cleanup_consumption"]
        if (len(cleanup) == 1 and len(snapshot.functions[fid]['parameters']) == 1
                and kind in {"argument_construction", "ownership"}):
            covered.append({"requirement_id": req["requirement_id"], "predicate": kind,
                            "construction_ids": [cleanup[0]["construction_id"]]})
            continue
        params = [p for p in snapshot.functions[fid]["parameters"] if p.get("is_struct_like") or p.get("is_opaque_handle")]
        proofs = [s for s in sources if s["function_id"] == fid and s["kind"] == "creator_return"]
        if not params or {p["name"] for p in params} != {s["parameter"] for s in proofs}:
            continue
        if kind == "lifecycle":
            covered.append({"requirement_id": req["requirement_id"], "predicate": kind,
                            "construction_ids": sorted({s["construction_id"] for s in proofs})})
        if kind == "call_order":
            covered.append({"requirement_id": req["requirement_id"], "predicate": kind,
                            "construction_ids": sorted({s["construction_id"] for s in proofs})})
        # All context fields read by this sole-parameter consumer are supplied
        # by one proved writer. Other parameters/partial writers stay open.
        if kind == "state" and len(snapshot.functions[fid]["parameters"]) == len(params) and all(
                any(t["after"] == fid and s["parameter"] == row["parameter"] and set(row["reads"]) <= set(t["fields"])
                    for chain in context["construction_contract"]["local_chains"]
                    for row in chain["consumers"] if row["function_id"] == fid
                    for t in chain["state_transitions"]) for s in proofs):
            covered.append({"requirement_id": req["requirement_id"], "predicate": kind,
                            "construction_ids": sorted({s["construction_id"] for s in proofs})})
    return covered
