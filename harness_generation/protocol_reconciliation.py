"""Reconciling a mined protocol IR against the FT it is about to drive.

The IR and the FT are produced by two different stages that never speak to each
other.  The FT is assembled from the structural edges its ISF shares with other
functions; the IR is mined from the source, and its convention block names the
lifecycle and checksum helpers the protocol's implementation really uses.  The
two overlap by accident, and a real run showed what that costs: the mined
``context`` block named ``mp_init``, the plan dutifully bound it, and the plan
gate refused the attempt for referencing a function outside the FT.  The
contract was arguing with itself.

:func:`reconcile_protocol_ir` is where that argument is settled, once, before any
model is asked to write anything.  It answers three questions and refuses the
attempt when the answers do not add up:

Does the IR describe *this* FT?
    ``ir.entry_function`` must be the triplet's ISF.  Nothing else is identity:
    a source file name cannot stand in, because ``target.c`` is the name half
    the projects in the world give their only file.
Which declared helpers may the harness actually call?
    A helper is authorized by provenance *and* by the project having exactly one
    linkable definition of that name -- see :mod:`.project_functions`.  A name
    the project merely declares, or defines twice, is a broken claim and is
    reported; a name it defines ``static`` is not, because the evidence for it is
    real and the harness is free to compute the same thing under its own name.
Which lifecycle functions may it call?
    ``context.init`` / ``context.destroy`` are the contract's own claims, and a
    claim is not a licence.  Each slot is first read as C -- one call, one bare
    name, or one declaration -- and a slot that reads as none of those is a
    sentence, which names nothing to call and is refused rather than passed
    through.  A name it does state must be corroborated by ``context.evidence``
    and then runs on one of two permissions: the project's, which requires a
    single linkable definition of that name, or the C library's, which is what
    ``init: "malloc(...)"`` is asking for and which the audit already allows
    everywhere else.  Unlike a helper, a lifecycle function is one the contract
    *requires*: a harness that cannot call it cannot preserve the contract at
    all, so an unresolvable slot costs the run.

The difference between those last two is the whole design.  A helper is
optional, so failing to resolve one costs an authorization.  A lifecycle is
mandatory, so failing to resolve one costs the run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .policy import DEFAULT_ALLOWED_FUNCTIONS
from .project_functions import (
    ABSENT,
    AMBIGUOUS,
    DECLARED_ONLY,
    INTERNAL_LINKAGE,
    LINKABLE,
    FunctionResolution,
    ProjectFunctionIndex,
)
from .protocol_ir import ProtocolIR
from .protocol_ir_helpers import (
    LIFECYCLE_INITIALIZATION,
    LIFECYCLE_INVALID,
    collect_protocol_helpers,
    read_lifecycle_expression,
)

#: The lifecycle slots of the convention block, in the order they are reported.
LIFECYCLE_ROLES = ("init", "destroy")

#: Helper verdicts that make the IR's own claim unbuildable.  ``ABSENT`` is not
#: among them: an IR that names ``memset`` is naming the standard library, and
#: the audit has an allow-list of its own for that.  Only a name the *project*
#: owns and cannot deliver is a broken claim.
_BROKEN_CLAIMS = frozenset({DECLARED_ONLY, AMBIGUOUS})


@dataclass(frozen=True)
class ReconciledHelper:
    """One declared helper, with the verdict on calling it."""

    name: str
    origin: str
    evidence: str
    resolution: FunctionResolution
    #: The name is the C library's, so the project's rows say nothing about
    #: whether a call to it links.  Recorded rather than assumed: it is the
    #: difference between "the contract names ``memset``" and "the contract
    #: names a function this project does not have".
    standard_library: bool = False

    @property
    def callable(self) -> bool:
        return self.resolution.callable

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "origin": self.origin,
            "evidence": self.evidence,
            "status": self.resolution.status,
            "callable": self.callable,
            "standard_library": self.standard_library,
        }


@dataclass(frozen=True)
class ReconciledLifecycle:
    """One ``context`` slot: what it says, and whether it can be performed.

    ``kind`` is how the slot read as C -- see
    :func:`.protocol_ir_helpers.read_lifecycle_expression`.  Only a call and a
    bare name carry a ``function``; a declaration has nothing to call, and a
    sentence is refused rather than read as a name it never stated.
    """

    role: str
    expression: str
    kind: str = LIFECYCLE_INVALID
    function: str | None = None
    corroboration: tuple[str, ...] = ()
    resolution: FunctionResolution | None = None
    standard_library: bool = False

    @property
    def callable(self) -> bool:
        """Whether this slot widens the *project* allowance.

        False for a library call: ``malloc`` is already permitted everywhere a
        harness may call anything, and listing it among the project's helpers
        would say the contract declared a project function it never named.
        """

        return self.resolution is not None and self.resolution.callable

    @property
    def performable(self) -> bool:
        """Whether the harness can carry this slot out at all."""

        if self.kind == LIFECYCLE_INITIALIZATION:
            return True
        return self.callable or self.standard_library

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "expression": self.expression,
            "kind": self.kind,
            "function": self.function,
            "status": (
                None if self.resolution is None else self.resolution.status
            ),
            "callable": self.callable,
            "standard_library": self.standard_library,
            "performable": self.performable,
            "corroboration": list(self.corroboration),
        }


@dataclass(frozen=True)
class ProtocolReconciliation:
    """What the IR and the FT agree on, and every place they do not."""

    isf_function: str = ""
    entry_function: str = ""
    helpers: tuple[ReconciledHelper, ...] = ()
    lifecycle: tuple[ReconciledLifecycle, ...] = ()
    diagnostics: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.diagnostics

    @property
    def callable_helpers(self) -> frozenset[str]:
        """The project functions the contract lets the harness call.

        This is the one set every consumer widens by: the plan's projection, the
        plan validator, the C audit and the pipeline's re-validation.  They
        cannot drift apart while they are reading the same object.
        """

        names = {helper.name for helper in self.helpers if helper.callable}
        names.update(item.function for item in self.lifecycle if item.callable)
        return frozenset(names)

    @property
    def reference_only_helpers(self) -> frozenset[str]:
        """Helpers evidenced for what they compute but not callable.

        ``le16`` is the case this exists for: the contract's ``payload_length``
        field says its value comes from ``le16() load``, which is true and worth
        keeping, and a harness that called it would not link.
        """

        return frozenset(
            helper.name
            for helper in self.helpers
            if helper.resolution.status == INTERNAL_LINKAGE
        )

    @property
    def unresolved(self) -> tuple[str, ...]:
        """Declared names the project owns but cannot deliver a call to."""

        return tuple(sorted(
            helper.name
            for helper in self.helpers
            if helper.resolution.status in _BROKEN_CLAIMS
        ))

    @property
    def standard_library_names(self) -> frozenset[str]:
        """Names the IR leans on that the C library owns rather than the project.

        Recorded so the attempt's ``parsed.json`` distinguishes the two ways a
        name can be absent from the index: ``free`` and ``memset`` are absent
        because libc has them, and a name nothing has is a different finding.
        """

        return self._absent(standard_library=True)

    @property
    def unknown_names(self) -> frozenset[str]:
        """Names the IR leans on that neither the project nor the library has."""

        return self._absent(standard_library=False)

    def _absent(self, *, standard_library: bool) -> frozenset[str]:
        names = {
            helper.name
            for helper in self.helpers
            if helper.resolution.status == ABSENT
            and helper.standard_library is standard_library
        }
        names.update(
            item.function
            for item in self.lifecycle
            if item.function is not None
            and item.resolution is not None
            and item.resolution.status == ABSENT
            and item.standard_library is standard_library
        )
        return frozenset(names)

    def to_dict(self) -> dict[str, Any]:
        return {
            "isf_function": self.isf_function,
            "entry_function": self.entry_function,
            "callable_helpers": sorted(self.callable_helpers),
            "reference_only_helpers": sorted(self.reference_only_helpers),
            "standard_library_names": sorted(self.standard_library_names),
            "unknown_names": sorted(self.unknown_names),
            "helpers": [helper.to_dict() for helper in self.helpers],
            "lifecycle": [item.to_dict() for item in self.lifecycle],
            "diagnostics": list(self.diagnostics),
        }


def reconcile_protocol_ir(
    ir: ProtocolIR | None,
    triplet: Any,
    functions: ProjectFunctionIndex,
) -> ProtocolReconciliation:
    """Settle the IR against the FT, once, before any model is called.

    With no IR this returns an empty reconciliation whose callable set is empty,
    so the FT-only path is unchanged: every consumer widens by nothing and
    behaves exactly as it did before a protocol could reach it.
    """

    isf = triplet.isf.function
    if ir is None:
        return ProtocolReconciliation(isf_function=isf)

    diagnostics: list[str] = []
    entry = ir.entry_function
    if entry != isf:
        diagnostics.append(
            f"protocol_ir.json was mined for entry function {entry!r}, but this "
            f"triplet's ISF is {isf!r}; the IR describes a different function"
        )

    helpers = tuple(
        _reconcile_helper(helper, functions, diagnostics)
        for helper in collect_protocol_helpers(ir).helpers
    )
    return ProtocolReconciliation(
        isf_function=isf,
        entry_function=entry,
        helpers=helpers,
        lifecycle=_reconcile_lifecycle(ir, functions, diagnostics),
        diagnostics=tuple(diagnostics),
    )


def _links_from_the_c_library(name: str, resolution: FunctionResolution) -> bool:
    """Whether a call to ``name`` is answered by the C library, not the project.

    ``init: "malloc(sizeof(mp_context))"`` asks for a lifecycle the harness can
    perform, and the project's rows are the wrong thing to judge it by: a
    ``static`` definition of the name lives inside the target's own translation
    unit and is invisible here.  What permits an otherwise absent call is the
    audit's standard-C allow-list, the same list every other ``memset`` runs on.

    That allow-list is why a name merely declared, or defined only ``static``,
    is not disqualifying: it says the harness may *write* the call.  It does not
    say what the linker binds it to, which is why two linkable project
    definitions of a library's name are still refused.  The ambiguity is not
    resolved by the name being a familiar one -- it is the one case where the
    project's own rows decide the target and cannot, and reading it as
    "the library's, then" would be this module answering a question the project
    left open.  A helper pays for that with its authorization; the asymmetry
    with a lifecycle (see the module docstring) does not extend to it, because
    a broken claim is not the same finding as an optional one.

    A name the project defines *and* links is not this case: it is a project
    function, and the project's verdict is the interesting one.
    """

    return resolution.status in {
        ABSENT, DECLARED_ONLY, INTERNAL_LINKAGE,
    } and name in DEFAULT_ALLOWED_FUNCTIONS


def _reconcile_helper(
    helper: Any,
    functions: ProjectFunctionIndex,
    diagnostics: list[str],
) -> ReconciledHelper:
    resolution = functions.resolve(helper.name)
    standard_library = _links_from_the_c_library(helper.name, resolution)
    if resolution.status in _BROKEN_CLAIMS and not standard_library:
        diagnostics.append(
            f"the protocol evidence names {helper.name} "
            f"(from {helper.origin}), but {resolution.why()}"
        )
    return ReconciledHelper(
        name=helper.name,
        origin=helper.origin,
        evidence=helper.evidence,
        resolution=resolution,
        standard_library=standard_library,
    )


def _reconcile_lifecycle(
    ir: ProtocolIR,
    functions: ProjectFunctionIndex,
    diagnostics: list[str],
) -> tuple[ReconciledLifecycle, ...]:
    context = ir.context
    if context is None:
        return ()
    evidence = tuple(
        item for item in context.evidence if isinstance(item, str) and item
    )
    reconciled: list[ReconciledLifecycle] = []
    for role in LIFECYCLE_ROLES:
        expression = getattr(context, role, "")
        if not isinstance(expression, str) or not expression.strip():
            continue
        parsed = read_lifecycle_expression(expression)
        if parsed.kind == LIFECYCLE_INVALID:
            # A sentence is not a lifecycle.  Letting it through unnamed is how
            # it reached the plan as a ``context.init`` binding the model was
            # told to reproduce, and a plan that echoes prose has preserved
            # nothing about the context it was supposed to build.
            reconciled.append(ReconciledLifecycle(
                role, expression, parsed.kind,
            ))
            diagnostics.append(
                f"context.{role} is {expression!r}, which is not a lifecycle "
                f"the harness can run: state the call it makes, the function it "
                f"names, or a declaration it performs"
            )
            continue
        if parsed.kind == LIFECYCLE_INITIALIZATION:
            # A declaration is performed by the harness's own C and names no
            # helper.  It can initialize the context only when it declares the
            # context's type; it cannot stand in for destruction.
            type_names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", context.type)
            expected_type = type_names[-1] if type_names else ""
            valid_declaration = role == "init" and parsed.declared_type == expected_type
            reconciled.append(ReconciledLifecycle(
                role, expression,
                parsed.kind if valid_declaration else LIFECYCLE_INVALID,
            ))
            if role != "init":
                diagnostics.append(
                    f"context.{role} declaration {expression!r} cannot destroy "
                    "the context"
                )
            elif not valid_declaration:
                diagnostics.append(
                    f"context.{role} declaration {expression!r} does not initialize "
                    f"the declared context type {context.type!r}"
                )
            continue
        name = parsed.function
        corroboration = tuple(
            item for item in evidence if re.search(rf"\b{re.escape(name)}\b", item)
        )
        resolution = functions.resolve(name)
        standard_library = _links_from_the_c_library(name, resolution)
        reconciled.append(ReconciledLifecycle(
            role, expression, parsed.kind, name, corroboration, resolution,
            standard_library,
        ))
        # Both halves are reported, and the harder one first.  They are separate
        # facts -- a lifecycle can name a function the project defines without
        # any evidence that the miner found it, or evidence one it cannot link --
        # and a retry loop that is told only one of them fixes it and comes back
        # with the other.  Resolution leads because a name that is not a project
        # function at all is the answer that subsumes the rest.
        if not resolution.callable and not standard_library:
            diagnostics.append(
                f"context.{role} requires a call to {name}, but {resolution.why()}"
            )
        if not corroboration:
            # ``context.evidence`` is what turns the convention block's claim
            # into something the miner found.  Without it the expression is
            # only asserting itself, and a self-asserting claim must not be
            # able to authorize a call.
            diagnostics.append(
                f"context.{role} is {expression!r}, which names {name}, but no "
                f"context.evidence backs that name; the expression cannot "
                f"authorize a call on its own"
            )
    return tuple(reconciled)
