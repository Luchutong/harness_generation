"""The HarnessPlan's structured promise to the mined protocol contract.

Stage 4 asks the LLM for two documents: a :class:`~harness_generation.stage4.
HarnessPlan`, and then the C harness that plan describes.  Nothing used to sit
between them, so a plan that quietly moved ``payload_offset``, dropped the
checksum repair, or rebuilt its context on every frame still reached the
transform call and produced a harness that *looked* protocol-aware.

This module closes that gap without asking the LLM to explain itself twice and
without reading its prose.  It works in three steps:

1. **Typed projection.**  :func:`protocol_contract_projection` reduces the mined
   :class:`~harness_generation.protocol_ir.ProtocolIR` to the exact facts a plan
   has to preserve -- frame layout, input-construction policy, context lifetime,
   stateful opcodes and evidenced helpers.  Only those facts are ever compared.

2. **Structured binding.**  The plan returns a ``protocol_contract_bindings``
   object with the same shape.  It is a declaration, not a description: every
   leaf is a number, a boolean, an enum, or a token copied from the projection.

3. **Deterministic comparison.**  :func:`validate_plan_contract` compares the
   two and returns the disagreements.  It never parses a sentence, never
   re-mines the protocol, and never guesses: a leaf either equals the contract's
   leaf or it is reported.

Deliberately **not** checked here -- these are warnings, carried in
:attr:`ProtocolContractProjection.warnings` so a run records what the gate is
blind to, but they can never fail a plan:

* the miner's *descriptive* field values (``"le16() load"``, ``"fuzzer-controlled
  bytes"``).  Only bare C constants such as the magic and version guards are
  literals, and only those are compared -- see :func:`_constant_value`.
* the IR's ``requirements`` / ``notes`` prose, and its ``limitations``.
* coverage equivalence between the published harness and the reference
  implementation.  That is a dynamic question and belongs to its own task.

Comparison is one-directional where the contract can only require behaviour: a
contract that repairs a checksum makes ``repair_checksum: false`` a failure, but
a plan that repairs more than the contract demands is not thereby wrong.  The
checks that catch *invention* -- extra frame fields, unlisted stateful opcodes,
unevidenced helpers -- are set comparisons and are two-directional.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Iterable, Mapping, Sequence

from .protocol_ir_helpers import collect_protocol_helpers


#: The miner's role vocabulary for the three fields that carry a protocol
#: *policy* rather than a literal.  A contract only says "repair the length"
#: when a field with this role exists.
ROLE_PAYLOAD = "payload"
ROLE_PAYLOAD_LENGTH = "payload_length"
ROLE_CHECKSUM = "checksum"

#: The two lifetimes a plan may claim.  An enum, not a sentence, because the
#: whole point of this gate is that the answer is decidable.
LIFETIME_PER_ITERATION = "per_iteration"
LIFETIME_PER_FRAME = "per_frame"
#: What the projection says when the IR's own lifetime text is not in the
#: vocabulary below.  ``unknown`` is never a failure: the gate cannot enforce a
#: lifetime the contract never stated.
LIFETIME_UNKNOWN = "unknown"

#: The miner's free-text lifetime values, normalised.  The vocabulary is the one
#: ``PROTOCOL_CONVENTION_REFINEMENT`` and the static miner actually emit.
_LIFETIME_VOCABULARY = {
    "one per fuzz iteration": LIFETIME_PER_ITERATION,
    "one context per fuzz iteration": LIFETIME_PER_ITERATION,
    "one context per libfuzzer iteration": LIFETIME_PER_ITERATION,
    "per fuzz iteration": LIFETIME_PER_ITERATION,
    "per iteration": LIFETIME_PER_ITERATION,
    LIFETIME_PER_ITERATION: LIFETIME_PER_ITERATION,
    "per frame": LIFETIME_PER_FRAME,
    "per_frame": LIFETIME_PER_FRAME,
    "one context per frame": LIFETIME_PER_FRAME,
    "rebuilt per frame": LIFETIME_PER_FRAME,
}

#: A bare C constant: ``'M'``, ``1``, ``0x7f``.  Everything else the miner puts
#: in ``FrameField.value`` describes how the field is loaded, and comparing a
#: description would be comparing prose.
_CONSTANT = re.compile(r"^(?:'(?:\\.|[^'\\])'|0[xX][0-9A-Fa-f]+|-?\d+)$")

#: ``mp_init(&ctx)`` -> ``mp_init``.  The contract stores a convention
#: expression; a binding stores the function name, which is the part the harness
#: audit can check.
_CALL_NAME = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")


@dataclass(frozen=True)
class ProtocolContractProjection:
    """What a plan has to preserve, and what this gate cannot see.

    ``bindings`` is the shape rendered into the plan prompt and compared
    against the plan's ``protocol_contract_bindings``.  ``warnings`` is the
    honest list of contract content the gate deliberately does not judge.
    """

    bindings: Mapping[str, Any]
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "bindings": json.loads(json.dumps(self.bindings)),
            "warnings": list(self.warnings),
        }

    def renderable(self) -> Mapping[str, Any]:
        """Exactly what the plan prompt shows: no prose, no commentary."""

        return self.bindings


@dataclass(frozen=True)
class PlanContractConformance:
    """The verdict of one plan-versus-contract comparison.

    ``violations`` are hard failures; ``warnings`` are carried through so an
    attempt records the items the comparison could not decide.  An absent
    projection is not a violation by itself: it means the run is FT-only.
    """

    projection: ProtocolContractProjection | None
    bindings: Mapping[str, Any] | None
    violations: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "passed" if self.ok else "failed",
            "protocol_contract": (
                None if self.projection is None else self.projection.to_dict()
            ),
            "protocol_contract_bindings": (
                None if self.bindings is None else json.loads(json.dumps(self.bindings))
            ),
            "violations": list(self.violations),
            "warnings": list(self.warnings),
        }


def protocol_contract_projection(
    ir: Any,
    *,
    project_functions: Iterable[str] = (),
) -> ProtocolContractProjection | None:
    """Project a mined IR onto the facts a plan must preserve, or ``None``.

    ``None`` means "no protocol_ir.json", which is the FT-only run: the plan
    must then carry no bindings at all, and the projection cannot be invented
    from anything else.
    """

    if ir is None:
        return None

    frame = ir.frame
    fields = [_field_projection(field) for field in frame.fields]
    roles = {field.role for field in frame.fields if field.role}

    frame_block: dict[str, Any] = {
        "header_size": frame.header_size,
        "payload_offset": frame.payload_offset,
        "max_payload": frame.max_payload,
        "fields": fields,
    }
    max_symbol = getattr(frame, "max_payload_symbol", None)
    if max_symbol:
        frame_block["max_payload_symbol"] = max_symbol

    sequence = getattr(ir, "sequence", None)
    multi_frame = bool(getattr(sequence, "multi_frame", False))
    step_cap, step_source = _step_cap(sequence)
    input_model: dict[str, Any] = {
        "bounded_multi_frame": multi_frame,
        "payload_fuzzer_controlled": ROLE_PAYLOAD in roles,
        "repair_length": ROLE_PAYLOAD_LENGTH in roles,
        "repair_checksum": ROLE_CHECKSUM in roles,
    }
    if multi_frame and step_cap is not None:
        input_model["bounded_steps"] = step_cap
    if step_source:
        input_model["bounded_steps_source"] = step_source

    helpers = collect_protocol_helpers(ir).allowed & frozenset(project_functions)
    bindings = {
        "frame": frame_block,
        "input_model": input_model,
        "context": _context_projection(getattr(ir, "context", None)),
        "stateful_operations": sorted(
            operation.opcode for operation in getattr(ir, "stateful_operations", ())
        ),
        "helpers": sorted(helpers),
    }
    return ProtocolContractProjection(
        bindings=bindings, warnings=_projection_warnings(ir, input_model, fields)
    )


def validate_plan_contract(
    bindings: Any,
    *,
    projection: ProtocolContractProjection | None,
    input_strategy: Mapping[str, Any] | None = None,
) -> PlanContractConformance:
    """Compare a plan's ``protocol_contract_bindings`` against the projection.

    Returns the disagreements rather than raising: the caller owns the error
    vocabulary, and Stage 4 needs the same verdict to be recordable in
    ``parsed.json`` on the passing path too.
    """

    warnings = () if projection is None else projection.warnings

    if projection is None:
        if _is_bound(bindings):
            return PlanContractConformance(
                None, bindings,
                (
                    "HarnessPlan declares protocol_contract_bindings but no protocol "
                    "IR was supplied; a plan with no contract must stay FT-only",
                ),
                warnings,
            )
        return PlanContractConformance(None, None, (), warnings)

    if bindings is None:
        return PlanContractConformance(
            projection, None,
            (
                "HarnessPlan omits protocol_contract_bindings while a protocol IR "
                "was supplied; the plan must declare how it preserves the contract",
            ),
            warnings,
        )
    if not isinstance(bindings, Mapping):
        return PlanContractConformance(
            projection, None,
            ("HarnessPlan protocol_contract_bindings must be an object",),
            warnings,
        )

    violations = _frame_violations(bindings.get("frame"), projection.bindings["frame"])
    violations += _input_model_violations(
        bindings.get("input_model"),
        projection.bindings["input_model"],
        input_strategy,
    )
    violations += _context_violations(
        bindings.get("context"), projection.bindings["context"]
    )
    violations += _stateful_violations(
        bindings.get("stateful_operations"),
        projection.bindings["stateful_operations"],
    )
    violations += _helper_violations(
        bindings.get("helpers"), projection.bindings["helpers"]
    )
    return PlanContractConformance(projection, bindings, tuple(violations), warnings)


# -- the projection --------------------------------------------------------


def _field_projection(field: Any) -> dict[str, Any]:
    """One frame field, with prose stripped out and literals kept."""

    entry: dict[str, Any] = {
        "role": field.role,
        "name": field.name,
        "offset": field.offset,
        "width": field.width,
    }
    if getattr(field, "endianness", None):
        entry["endianness"] = field.endianness
    constant = _constant_value(field)
    if constant is not None:
        entry["value"] = constant
    return entry


def _constant_value(field: Any) -> str | None:
    """The field's value, but only when it is a bare C constant.

    ``magic0.value`` is ``'M'`` -- a guard the harness must reproduce exactly.
    ``payload_length.value`` is ``"le16() load"``, which describes the load
    rather than giving a value; requiring a plan to echo that string back would
    be checking prose, which this gate exists to avoid.
    """

    value = getattr(field, "value", None)
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped if _CONSTANT.match(stripped) else None


def _step_cap(sequence: Any) -> tuple[int | None, str | None]:
    """The contract's loop cap and where it came from, when it states one."""

    max_steps = getattr(sequence, "max_steps", None)
    if max_steps is None:
        return None, None
    if isinstance(max_steps, Mapping):
        return max_steps.get("value"), max_steps.get("source")
    return max_steps, None


def _context_projection(context: Any) -> dict[str, Any] | None:
    if context is None:
        return None
    if not (context.type or context.init or context.destroy):
        return None
    return {
        "type": context.type,
        "init": _function_name(context.init),
        "destroy": _function_name(context.destroy),
        "lifetime": _lifetime(context.lifetime),
    }


def _function_name(expression: Any) -> Any:
    if not isinstance(expression, str):
        return expression
    match = _CALL_NAME.match(expression)
    return match.group(1) if match else expression.strip()


def _lifetime(text: Any) -> str:
    if not isinstance(text, str):
        return LIFETIME_UNKNOWN
    normalized = " ".join(text.split()).strip(".").lower()
    if not normalized:
        return LIFETIME_UNKNOWN
    if normalized in _LIFETIME_VOCABULARY:
        return _LIFETIME_VOCABULARY[normalized]
    # The vocabulary is small but the miner writes free text, so fall back to
    # the one distinction the gate actually needs: does the context outlive a
    # command, or is it rebuilt for each one?
    frames = "frame" in normalized
    iterations = "iteration" in normalized
    if frames and not iterations:
        return LIFETIME_PER_FRAME
    if iterations:
        return LIFETIME_PER_ITERATION
    return LIFETIME_UNKNOWN


def _projection_warnings(
    ir: Any,
    input_model: Mapping[str, Any],
    fields: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    """What the comparison above is deliberately blind to.

    Recorded, never enforced.  This is the honest boundary of a static gate: it
    says out loud which of the contract's claims it does not decide, instead of
    approximating them with a string match.
    """

    warnings: list[str] = []
    descriptive = [entry["name"] for entry in fields if "value" not in entry]
    if descriptive:
        warnings.append(
            "frame field values are descriptive, not literals, and are not "
            "compared: " + ", ".join(str(name) for name in descriptive)
        )
    if input_model.get("bounded_steps_source") == "engineering_choice":
        warnings.append(
            "the contract's loop cap is a harness policy, not source-backed"
        )
    for limitation in getattr(ir, "limitations", ()) or ():
        warnings.append(f"mining limitation not checked here: {limitation}")
    for requirement in getattr(ir, "requirements", ()) or ():
        warnings.append(f"prose requirement not checked here: {requirement}")
    return tuple(warnings)


# -- the comparison --------------------------------------------------------


def _frame_violations(bindings: Any, expected: Mapping[str, Any]) -> list[str]:
    if not isinstance(bindings, Mapping):
        return ["protocol_contract_bindings.frame must be an object"]

    violations: list[str] = []
    for key in ("header_size", "payload_offset", "max_payload", "max_payload_symbol"):
        if key not in expected:
            continue
        actual = bindings.get(key)
        if actual != expected[key]:
            violations.append(
                f"protocol_contract_bindings.frame.{key} is {actual!r}, "
                f"the contract says {expected[key]!r}"
            )

    fields = bindings.get("fields")
    wanted = expected["fields"]
    if not isinstance(fields, list) or any(not isinstance(item, Mapping) for item in fields):
        return violations + ["protocol_contract_bindings.frame.fields must be an array of objects"]
    if len(fields) != len(wanted):
        violations.append(
            "protocol_contract_bindings.frame.fields is "
            f"{_roles(fields)}, the contract says {_roles(wanted)}"
        )
        return violations

    for index, (actual, want) in enumerate(zip(fields, wanted)):
        where = f"protocol_contract_bindings.frame.fields[{index}]"
        for key in ("role", "offset", "width"):
            if actual.get(key) != want[key]:
                violations.append(
                    f"{where}.{key} is {actual.get(key)!r}, the contract says {want[key]!r}"
                )
        for key in ("endianness", "value"):
            # Only stated where the contract states it: a missing literal is a
            # dropped repair, but an unstated one is not a requirement.
            if key in want and actual.get(key) != want[key]:
                violations.append(
                    f"{where}.{key} is {actual.get(key)!r}, the contract says {want[key]!r}"
                )
        if "name" in actual and actual["name"] != want["name"]:
            violations.append(
                f"{where}.name is {actual['name']!r}, the contract says {want['name']!r}"
            )
    return violations


def _input_model_violations(
    bindings: Any,
    expected: Mapping[str, Any],
    input_strategy: Mapping[str, Any] | None,
) -> list[str]:
    if not isinstance(bindings, Mapping):
        return ["protocol_contract_bindings.input_model must be an object"]

    violations: list[str] = []

    if expected["bounded_multi_frame"] and bindings.get("bounded_multi_frame") is not True:
        violations.append(
            "the contract frames a bounded multi-frame command loop, but "
            "protocol_contract_bindings.input_model.bounded_multi_frame is not true"
        )

    if expected["bounded_multi_frame"]:
        declared = _positive_int((input_strategy or {}).get("bounded_steps"))
        bound = _positive_int(bindings.get("bounded_steps"))
        if declared is None:
            violations.append(
                "input_strategy.bounded_steps must be a positive cap for a "
                f"multi-frame contract, got {(input_strategy or {}).get('bounded_steps')!r}"
            )
        if bound is None:
            violations.append(
                "protocol_contract_bindings.input_model.bounded_steps must be a "
                f"positive integer, got {bindings.get('bounded_steps')!r}"
            )
        if declared is not None and bound is not None and declared != bound:
            violations.append(
                "the plan states two different loop caps: "
                f"input_strategy.bounded_steps is {declared} and "
                f"protocol_contract_bindings.input_model.bounded_steps is {bound}"
            )

    # One-directional: the contract can require a repair or a fuzz-driven
    # payload, but it cannot forbid a harness from being more careful than it.
    for key, message in _POLICY_MESSAGES.items():
        if expected.get(key) and bindings.get(key) is not True:
            violations.append(message)
    return violations


_POLICY_MESSAGES = {
    "payload_fuzzer_controlled": (
        "the contract's payload comes from fuzz bytes, but "
        "protocol_contract_bindings.input_model.payload_fuzzer_controlled is not true"
    ),
    "repair_length": (
        "the contract has a payload_length field the harness has to fill in, but "
        "protocol_contract_bindings.input_model.repair_length is not true"
    ),
    "repair_checksum": (
        "the contract has a checksum field the harness has to fill in, but "
        "protocol_contract_bindings.input_model.repair_checksum is not true"
    ),
}


def _context_violations(bindings: Any, expected: Mapping[str, Any] | None) -> list[str]:
    if expected is None:
        if isinstance(bindings, Mapping) and bindings:
            return [
                "protocol_contract_bindings binds a context the contract does not "
                "declare: " + ", ".join(sorted(str(key) for key in bindings))
            ]
        return []
    if not isinstance(bindings, Mapping):
        return [
            "the contract declares a context lifecycle, but "
            "protocol_contract_bindings.context is missing"
        ]

    violations: list[str] = []
    for key in ("type", "init", "destroy"):
        if expected.get(key) and bindings.get(key) != expected[key]:
            violations.append(
                f"protocol_contract_bindings.context.{key} is {bindings.get(key)!r}, "
                f"the contract says {expected[key]!r}"
            )
    wanted = expected.get("lifetime")
    if wanted in (LIFETIME_PER_ITERATION, LIFETIME_PER_FRAME) and bindings.get("lifetime") != wanted:
        violations.append(
            f"protocol_contract_bindings.context.lifetime is {bindings.get('lifetime')!r}, "
            f"the contract says {wanted!r}; state a context that outlives the "
            "commands it carries state between"
        )
    return violations


def _stateful_violations(bindings: Any, expected: Sequence[str]) -> list[str]:
    actual, error = _name_list(bindings, "stateful_operations")
    if error:
        return [error]
    expected_set = set(expected)
    actual_set = set(actual)
    violations = []
    if missing := sorted(expected_set - actual_set):
        violations.append(
            "the plan drops stateful opcodes the contract names: " + ", ".join(missing)
        )
    if invented := sorted(actual_set - expected_set):
        violations.append(
            "the plan binds stateful opcodes the contract does not name: "
            + ", ".join(invented)
        )
    return violations


def _helper_violations(bindings: Any, expected: Sequence[str]) -> list[str]:
    actual, error = _name_list(bindings, "helpers")
    if error:
        return [error]
    invented = sorted(set(actual) - set(expected))
    if not invented:
        return []
    return [
        "the plan binds helpers the mined protocol does not evidence as project "
        "functions: " + ", ".join(invented)
    ]


# -- small helpers ---------------------------------------------------------


def _roles(fields: Sequence[Mapping[str, Any]]) -> list[Any]:
    return [field.get("role") for field in fields]


def _name_list(bindings: Any, field: str) -> tuple[list[str], str | None]:
    if bindings is None:
        return [], f"protocol_contract_bindings.{field} must be an array of names"
    if not isinstance(bindings, list) or any(not isinstance(item, str) for item in bindings):
        return [], f"protocol_contract_bindings.{field} must be an array of names"
    return list(bindings), None


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value > 0 else None


def _is_bound(bindings: Any) -> bool:
    """Whether the plan actually declared a contract binding.

    ``None`` and an empty object both mean "declared nothing"; anything else is
    the plan claiming a protocol it was not given.
    """

    if bindings is None:
        return False
    if isinstance(bindings, Mapping):
        return bool(bindings)
    return True
