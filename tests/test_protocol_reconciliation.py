"""The mined IR and the extracted FT have to be reconciled before either is used.

``protocol_ir.json`` is mined from source by one stage and the FT is assembled
from shared-structural edges by another.  They overlap by accident: an FT is not
a call closure, so a function the ISF genuinely calls -- a checksum, a context
constructor -- can sit outside it forever, and a name the IR's evidence quotes
can be ``static`` in the target's translation unit and therefore uncallable.

Nothing used to compare the two.  ``functions.json`` was read as a set of names
in two places, and a name cannot say whether it is defined or merely declared,
whether its definition links, or which of two definitions a call means; the
lifecycle expressions in ``context`` were taken as an authorization on their own
say-so.  These tests pin the reconciliation that replaces all of that, and the
refusals it makes *before* any model is asked anything.

``MiniParserFunctionClassesTests`` is the measured half: the four real function
classes in ``benchmarks/mini_parser/target.c``, each one landing on the verdict
it has to land on for the explanation to be about the real project rather than
about a fixture written to agree with the code.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.pipeline_validation import (
    PipelineStageValidator,
    PipelineValidationConfig,
)
from harness_generation.project_functions import (
    ABSENT,
    AMBIGUOUS,
    DECLARED_ONLY,
    INTERNAL_LINKAGE,
    LINKABLE,
    ProjectFunctionIndex,
)
from harness_generation.protocol_conventions import ContextModel
from harness_generation.protocol_ir_helpers import (
    LIFECYCLE_CALL,
    LIFECYCLE_INITIALIZATION,
    LIFECYCLE_INVALID,
    LIFECYCLE_NAME,
    read_lifecycle_expression,
)
from harness_generation.protocol_plan_validation import protocol_contract_projection
from harness_generation.protocol_reconciliation import reconcile_protocol_ir
from harness_generation.stage4 import (
    Stage4Error,
    declared_contract_helpers,
    parse_harness_plan,
)

from tests.test_stage4_plan_helpers import plan_json
from tests.test_stage4_protocol_ir import Stage4ProjectTests, mined_ir
from tests.test_stage4_structured_input import recorded_ir


def function(name: str, *, defined: bool = True, storage: tuple[str, ...] = (),
             file: str = "target.c", line: int = 1) -> dict[str, Any]:
    """One ``functions.json`` row, reduced to the fields linkage depends on."""

    return {
        "id": f"{file}:{line}:{name}",
        "name": name,
        "defined": defined,
        "storage": list(storage),
        "file": file,
        "start_line": line,
    }


class ProjectFunctionIndexTests(unittest.TestCase):
    """The five verdicts, on rows written by hand so each one is isolated."""

    def setUp(self):
        self.functions = ProjectFunctionIndex.from_document({"functions": [
            function("defined_here", line=10),
            function("internal_here", storage=("static",), line=20),
            function("declared_here", defined=False, line=30),
            function("twice", line=40),
            function("twice", file="other.c", line=50),
            function("declared_then_defined", defined=False, line=60),
            function("declared_then_defined", defined=True, line=61),
        ]})

    def test_a_plain_definition_is_callable(self):
        resolution = self.functions.resolve("defined_here")
        self.assertEqual(resolution.status, LINKABLE)
        self.assertTrue(resolution.callable)

    def test_a_static_definition_is_not_callable(self):
        resolution = self.functions.resolve("internal_here")
        self.assertEqual(resolution.status, INTERNAL_LINKAGE)
        self.assertFalse(resolution.callable)
        self.assertIn("static", resolution.why())
        self.assertIn("target.c:20", resolution.why())

    def test_a_declaration_with_nothing_behind_it_is_not_callable(self):
        resolution = self.functions.resolve("declared_here")
        self.assertEqual(resolution.status, DECLARED_ONLY)
        self.assertFalse(resolution.callable)
        self.assertIn("never defined", resolution.why())

    def test_two_linkable_definitions_make_a_call_ambiguous(self):
        """Both are real, so the name does not say which one a call means."""

        resolution = self.functions.resolve("twice")
        self.assertEqual(resolution.status, AMBIGUOUS)
        self.assertFalse(resolution.callable)
        self.assertIn("target.c:40", resolution.why())
        self.assertIn("other.c:50", resolution.why())

    def test_a_declaration_beside_a_definition_resolves_to_the_definition(self):
        """The miner emits both rows; only the definition can be linked to."""

        resolution = self.functions.resolve("declared_then_defined")
        self.assertEqual(resolution.status, LINKABLE)
        self.assertEqual(resolution.records[0].start_line, 61)

    def test_an_unknown_name_is_absent_and_not_a_verdict_about_linkage(self):
        resolution = self.functions.resolve("never_heard_of")
        self.assertEqual(resolution.status, ABSENT)
        self.assertFalse(resolution.callable)
        self.assertEqual(resolution.records, ())

    def test_names_is_every_row_including_the_ones_that_cannot_be_called(self):
        """The redefinition rule reads names, and it is not a linkage question.

        A harness that writes its own ``internal_here`` is still writing a name
        the project owns -- the check that refuses it is about names.
        """

        self.assertIn("internal_here", self.functions.names)
        self.assertIn("declared_here", self.functions.names)
        self.assertNotIn("never_heard_of", self.functions.names)

    def test_an_unreadable_document_is_an_empty_index_not_an_error(self):
        for document in ({}, {"functions": "not a list"}, [], None, 7):
            with self.subTest(document=document):
                self.assertEqual(
                    ProjectFunctionIndex.from_document(document), ProjectFunctionIndex()
                )

    def test_a_storage_field_of_the_wrong_shape_is_refused(self):
        """``storage: "static"`` is not the same row as ``storage: []``.

        Read as absent it would arrive as *no* specifiers, and no specifiers is
        what an externally linked definition looks like -- the one misreading
        that authorizes a call.  The row is refused instead, and the message
        names it so the miner that wrote it can be fixed.
        """

        for storage in ("static", 3, {"specifiers": ["static"]}, ["static", 3]):
            with self.subTest(storage=storage):
                with self.assertRaises(ValueError) as caught:
                    ProjectFunctionIndex.from_document({"functions": [
                        dict(function("hero"), storage=storage),
                    ]})
                self.assertIn("'hero'", str(caught.exception))
                self.assertIn(
                    "not a list of storage-class specifiers", str(caught.exception)
                )

    def test_a_storage_field_that_is_absent_is_a_plain_definition(self):
        """The shape the miner actually writes, and the one it omits."""

        index = ProjectFunctionIndex.from_document({"functions": [
            dict(function("hero"), storage=None),
            dict(function("villain"), storage=[]),
        ]})
        self.assertEqual(index.resolve("hero").status, LINKABLE)
        self.assertEqual(index.resolve("villain").status, LINKABLE)

    def test_rows_without_a_usable_name_are_skipped(self):
        functions = ProjectFunctionIndex.from_document({"functions": [
            function("keeper"),
            {"id": "x", "defined": True},
            "not an object",
            {"id": "y", "name": "", "defined": True},
        ]})
        self.assertEqual(functions.names, frozenset({"keeper"}))


class MiniParserFunctionClassesTests(Stage4ProjectTests):
    """The four classes in the real ``target.c``, measured rather than asserted."""

    def test_the_isf_and_its_cleanup_are_linkable(self):
        for name in ("mp_parse", "mp_destroy"):
            with self.subTest(function=name):
                self.assertEqual(self.functions.resolve(name).status, LINKABLE)

    def test_the_helpers_the_ft_cannot_contain_are_linkable_too(self):
        """``mp_init`` and ``mp_checksum``: outside the FT, and real.

        An FT is built from the structural edges its ISF shares with other
        functions, so a whole-struct ``memset`` (``mp_init``) and a pure helper
        (``mp_checksum``) yield no field-level evidence and no edge.  They are
        project functions all the same, and a call to them links.
        """

        in_ft = {item.function for item in self.triplet.functions}
        for name in ("mp_init", "mp_checksum"):
            with self.subTest(function=name):
                self.assertNotIn(name, in_ft)
                self.assertEqual(self.functions.resolve(name).status, LINKABLE)

    def test_the_static_helper_is_defined_evidenced_and_uncallable(self):
        """``le16`` is the case a set of names cannot express, in one row.

        It is defined, it carries the evidence the IR quotes for
        ``payload_length``, and it is ``static``, so the name is not something a
        harness can be asked to call.
        """

        resolution = self.functions.resolve("le16")
        self.assertEqual(resolution.status, INTERNAL_LINKAGE)
        self.assertTrue(resolution.records[0].defined)
        self.assertIn("static", resolution.why())


class HelperReconciliationTests(Stage4ProjectTests):
    """Which of the IR's evidenced helpers a harness may actually call.

    The three properties here are the ones the deleted ``_declared_helpers``
    used to hold, restated against the reconciliation and a real index.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.reconciliation = reconcile_protocol_ir(
            mined_ir(), cls.triplet, cls.functions
        )

    def test_the_ir_evidences_a_name_the_project_cannot_link(self):
        """The refusal this whole layer exists for, from the real IR."""

        self.assertIn("le16", {item.name for item in self.reconciliation.helpers})
        self.assertIn("le16", self.reconciliation.reference_only_helpers)
        self.assertNotIn("le16", self.reconciliation.callable_helpers)
        self.assertTrue(self.reconciliation.ok)

    def test_a_declared_name_the_project_does_not_define_is_not_callable(self):
        """The IR's evidence quotes real source; a ghost name is not a licence.

        Kept from ``_declared_helpers``: allowing it would silently disable the
        unknown-API check for that name in the audit.
        """

        ir = mined_ir()
        # ``frame.fields[].value`` is a *strong* provenance source -- a field's
        # documented access form -- so this is the shape the real ``le16``
        # arrived in, with a name the project only declares.
        frame = replace(ir.frame, fields=tuple(
            (replace(field, value="ghost_helper() load")
             if field.name == "payload_length" else field)
            for field in ir.frame.fields
        ))
        index_with_ghost = ProjectFunctionIndex.from_document({"functions": [
            function("mp_init"), function("mp_destroy"), function("mp_parse"),
            function("ghost_helper", defined=False),
        ]})
        reconciliation = reconcile_protocol_ir(
            replace(ir, frame=frame), self.triplet, index_with_ghost
        )
        ghost = next(
            item for item in reconciliation.helpers if item.name == "ghost_helper"
        )
        self.assertEqual(ghost.resolution.status, DECLARED_ONLY)
        self.assertIn("ghost_helper", reconciliation.unresolved)
        self.assertFalse(reconciliation.ok)
        self.assertIn("never defined", " ".join(reconciliation.diagnostics))

    def test_a_project_function_the_contract_does_not_declare_is_not_admitted(self):
        """``mp_reset`` is a plausible mini_parser entry the IR never evidences."""

        declared = ProjectFunctionIndex.from_document({"functions": [
            function("mp_init"), function("mp_reset"),
        ]})
        reconciliation = reconcile_protocol_ir(
            mined_ir(), self.triplet, declared
        )
        self.assertNotIn("mp_reset", reconciliation.callable_helpers)

    def test_no_ir_reconciles_to_the_empty_set(self):
        reconciliation = reconcile_protocol_ir(None, self.triplet, self.functions)
        self.assertTrue(reconciliation.ok)
        self.assertEqual(reconciliation.callable_helpers, frozenset())
        self.assertEqual(reconciliation.reference_only_helpers, frozenset())
        self.assertEqual(reconciliation.helpers, ())
        self.assertEqual(reconciliation.lifecycle, ())
        self.assertEqual(reconciliation.isf_function, "mp_parse")
        self.assertEqual(reconciliation.entry_function, "")

    def test_the_recorded_ir_of_the_real_run_still_reconciles(self):
        """An older IR, written by the pipeline before any of this existed.

        The recorded run's own ``protocol_ir.json`` has to load and reconcile
        unchanged, or the layer would be measuring its fixtures and not the
        artifacts it was built for.
        """

        reconciliation = reconcile_protocol_ir(
            recorded_ir(), self.triplet, self.functions
        )
        self.assertTrue(reconciliation.ok, reconciliation.diagnostics)
        self.assertEqual(
            reconciliation.callable_helpers,
            frozenset({"mp_checksum", "mp_destroy", "mp_init", "mp_parse"}),
        )
        # ``free`` and ``memset`` are named by the IR's provenance -- libc, not
        # this project.  A helper the project does not have is simply not a
        # project function, which is the behaviour the FT-only path always had.
        self.assertNotIn("free", self.functions.names)
        self.assertNotIn("free", reconciliation.callable_helpers)


class LifecycleReconciliationTests(Stage4ProjectTests):
    """``context.init``/``destroy`` are claims, and a claim needs a second source.

    A helper is optional: the plan may name it or not, and the audit's
    allow-set is a licence rather than an obligation.  A lifecycle is not --
    the plan prompt tells the model to name it -- so a lifecycle that cannot be
    resolved has to be a refusal rather than a name silently dropped from the
    allowance.
    """

    #: Names both roles, the way the miner's own convention sample does -- a
    #: single evidence line reading "mp_init/mp_destroy are the declared
    #: lifecycle helpers".
    BOTH_ROLES = ("mp_init(&ctx) and mp_destroy(&ctx) are the lifecycle helpers",)

    def reconciled(self, *, init: str, destroy: str = "mp_destroy(&ctx)",
                   evidence: tuple[str, ...] = BOTH_ROLES,
                   functions: ProjectFunctionIndex | None = None):
        context = ContextModel(
            type="mp_context", init=init, destroy=destroy,
            lifetime="one per iteration", evidence=evidence,
        )
        return reconcile_protocol_ir(
            replace(mined_ir(), context=context),
            self.triplet,
            self.functions if functions is None else functions,
        )

    def test_the_real_lifecycle_reconciles_and_is_callable(self):
        reconciliation = self.reconciled(init="mp_init(&ctx)")
        self.assertTrue(reconciliation.ok, reconciliation.diagnostics)
        self.assertIn("mp_init", reconciliation.callable_helpers)
        self.assertIn("mp_destroy", reconciliation.callable_helpers)

    def test_a_lifecycle_the_project_never_heard_of_is_refused(self):
        """Gap two: the expression used to authorize the call on its own."""

        reconciliation = self.reconciled(
            init="invented_init(&ctx)", evidence=("invented_init(&ctx) sets it up",)
        )
        self.assertFalse(reconciliation.ok)
        self.assertIn(
            "context.init requires a call to invented_init, but invented_init "
            "is not a function of this project",
            reconciliation.diagnostics,
        )
        self.assertNotIn("invented_init", reconciliation.callable_helpers)

    def test_a_lifecycle_that_is_only_declared_is_refused(self):
        functions = ProjectFunctionIndex.from_document({"functions": [
            function("mp_init", defined=False), function("mp_destroy"),
            function("mp_parse"), function("mp_checksum"),
        ]})
        reconciliation = self.reconciled(
            init="mp_init(&ctx)", functions=functions
        )
        self.assertFalse(reconciliation.ok)
        self.assertIn(
            "context.init requires a call to mp_init, but mp_init is declared "
            "in target.c:1 but never defined in this project, so there is "
            "nothing to link",
            reconciliation.diagnostics,
        )

    def test_a_static_lifecycle_is_refused_rather_than_dropped(self):
        """``le16`` may be demoted to evidence; a lifecycle may not be.

        A helper the contract evidences and cannot link is recorded and left
        out of the allowance.  A lifecycle in the same position is a refusal:
        the plan is told to call it, and there is nothing to call.
        """

        functions = ProjectFunctionIndex.from_document({"functions": [
            function("mp_init", storage=("static",)), function("mp_destroy"),
            function("mp_parse"), function("mp_checksum"),
        ]})
        reconciliation = self.reconciled(
            init="mp_init(&ctx)", functions=functions
        )
        self.assertFalse(reconciliation.ok)
        self.assertIn("static", " ".join(reconciliation.diagnostics))
        self.assertNotIn("mp_init", reconciliation.callable_helpers)

    def test_an_ambiguous_lifecycle_is_refused(self):
        functions = ProjectFunctionIndex.from_document({"functions": [
            function("mp_init"), function("mp_init", file="other.c", line=99),
            function("mp_destroy"), function("mp_parse"), function("mp_checksum"),
        ]})
        reconciliation = self.reconciled(
            init="mp_init(&ctx)", functions=functions
        )
        self.assertFalse(reconciliation.ok)
        self.assertIn("does not say which one", " ".join(reconciliation.diagnostics))

    def test_a_lifecycle_no_evidence_backs_is_refused(self):
        """The expression asserting itself is not a second source.

        ``context.evidence`` is what turns the convention block's claim into
        something the miner found.  Here the name is real and callable, so the
        only thing missing is the corroboration -- and that alone is enough.
        """

        reconciliation = self.reconciled(
            init="mp_init(&ctx)",
            evidence=("mp_destroy(&ctx) releases the context",),
        )
        self.assertFalse(reconciliation.ok)
        self.assertEqual(len(reconciliation.diagnostics), 1)
        self.assertIn("no context.evidence backs that name",
                      reconciliation.diagnostics[0])
        # Resolved, so it is still recorded as the lifecycle's function.
        self.assertEqual(reconciliation.lifecycle[0].function, "mp_init")
        self.assertEqual(reconciliation.lifecycle[0].corroboration, ())

    def test_a_slot_that_names_a_second_call_authorizes_neither(self):
        """The measured counterexample: one slot, two statements.

        ``init`` names ``mp_init``, the evidence backs only ``mp_init``, and the
        project defines ``invented`` -- so the resolution half is satisfied and
        the slot used to reconcile clean while handing ``invented`` an
        authorization it was never given.  The slot is now unreadable, which is
        what makes the claim and the licence the same size.
        """

        # The project really does define ``invented``, so nothing but the shape
        # of the slot stands between it and an authorization.
        functions = ProjectFunctionIndex.from_document({"functions": [
            function("mp_init"), function("invented"), function("mp_destroy"),
            function("mp_parse"), function("mp_checksum"),
        ]})
        reconciliation = self.reconciled(
            init="mp_init(&ctx); invented(&ctx)", functions=functions,
        )
        self.assertFalse(reconciliation.ok)
        self.assertEqual(reconciliation.diagnostics, (
            "context.init is 'mp_init(&ctx); invented(&ctx)', which is not a "
            "lifecycle the harness can run: state the call it makes, the "
            "function it names, or a declaration it performs",
        ))
        self.assertNotIn("invented", reconciliation.callable_helpers)
        self.assertNotIn("invented",
                         {item.name for item in reconciliation.helpers})

    def test_a_prose_lifecycle_is_refused_rather_than_passed_through(self):
        """``"rebuilt for every frame"`` is a sentence, not a call to make.

        It used to reconcile quietly and travel on into the plan prompt as the
        ``context.init`` binding the model had to reproduce -- a lifecycle
        nothing can run, declared as if it were one.  Reading it as a function
        name would be the opposite error: inventing a call the contract never
        asked for.  It is neither, and the slot is refused.
        """

        reconciliation = self.reconciled(init="rebuilt for every frame")
        self.assertFalse(reconciliation.ok)
        self.assertEqual(
            reconciliation.diagnostics[-1],
            "context.init is 'rebuilt for every frame', which is not a lifecycle "
            "the harness can run: state the call it makes, the function it "
            "names, or a declaration it performs",
        )
        self.assertEqual(reconciliation.lifecycle[0].function, None)
        self.assertFalse(reconciliation.lifecycle[0].performable)
        self.assertNotIn("rebuilt for every frame", reconciliation.callable_helpers)

    def test_a_declaration_is_a_lifecycle_the_harness_performs_itself(self):
        """``mp_context ctx = {0}`` asks for no call, so there is nothing to link."""

        reconciliation = self.reconciled(init="mp_context ctx = {0}")
        self.assertTrue(reconciliation.ok, reconciliation.diagnostics)
        self.assertEqual(
            reconciliation.lifecycle[0].kind, LIFECYCLE_INITIALIZATION
        )
        self.assertTrue(reconciliation.lifecycle[0].performable)
        self.assertNotIn("ctx", reconciliation.callable_helpers)

    def test_a_library_allocator_is_a_lifecycle_by_its_own_permission(self):
        """``init: "malloc(...)"`` is performable, and not a project function.

        Refusing it was the old rule: ``malloc`` has no row in this project, and
        a lifecycle that resolves to nothing was a hard error.  But the harness
        can call ``malloc`` -- the audit allows the whole standard-C set -- so
        the project's index is the wrong authority to ask.  It is recorded as a
        library name and stays out of the project's helper set, because the
        contract naming ``malloc`` is not the contract declaring a function of
        this project.
        """

        reconciliation = self.reconciled(
            init="malloc(sizeof(mp_context))",
            evidence=(
                "malloc(sizeof(mp_context)) is the context constructor",
                "mp_destroy(&ctx) releases the context",
            ),
        )
        self.assertTrue(reconciliation.ok, reconciliation.diagnostics)
        self.assertEqual(
            reconciliation.lifecycle[0].kind, LIFECYCLE_CALL
        )
        self.assertEqual(reconciliation.lifecycle[0].function, "malloc")
        self.assertTrue(reconciliation.lifecycle[0].standard_library)
        self.assertTrue(reconciliation.lifecycle[0].performable)
        self.assertFalse(reconciliation.lifecycle[0].callable)
        self.assertNotIn("malloc", reconciliation.callable_helpers)
        self.assertIn("malloc", reconciliation.standard_library_names)
        self.assertNotIn("malloc", reconciliation.unknown_names)

    def test_a_library_lifecycle_still_needs_the_miner_to_have_found_it(self):
        """The second permission is not an exemption from corroboration."""

        reconciliation = self.reconciled(
            init="malloc(sizeof(mp_context))",
            evidence=("mp_destroy(&ctx) releases the context",),
        )
        self.assertFalse(reconciliation.ok)
        self.assertIn("no context.evidence backs that name",
                      "; ".join(reconciliation.diagnostics))

    def test_a_context_the_ir_does_not_declare_reconciles_to_nothing(self):
        reconciliation = reconcile_protocol_ir(
            replace(mined_ir(), context=None), self.triplet, self.functions
        )
        self.assertTrue(reconciliation.ok)
        self.assertEqual(reconciliation.lifecycle, ())


class LifecycleExpressionTests(unittest.TestCase):
    """A slot is read as C: one call, one name, one declaration, or a refusal."""

    def read(self, expression):
        return read_lifecycle_expression(expression)

    def test_a_call_names_its_callee(self):
        for expression in ("mp_init(&ctx)", "mp_init ()", "  mp_init(&ctx)  ",
                           "mp_init(&ctx);"):
            with self.subTest(expression=expression):
                parsed = self.read(expression)
                self.assertEqual(parsed.kind, LIFECYCLE_CALL)
                self.assertEqual(parsed.function, "mp_init")

    def test_a_bare_identifier_names_itself(self):
        """The shape the miner's own convention sample writes."""

        parsed = self.read("mp_init")
        self.assertEqual(parsed.kind, LIFECYCLE_NAME)
        self.assertEqual(parsed.function, "mp_init")

    def test_an_allocation_expression_names_the_allocator(self):
        """Nested parentheses are still one call."""

        parsed = self.read("malloc(sizeof(mp_context))")
        self.assertEqual(parsed.kind, LIFECYCLE_CALL)
        self.assertEqual(parsed.function, "malloc")

    def test_a_declaration_is_neither_a_call_nor_prose(self):
        for expression in ("mp_context ctx = {0}", "struct mp_context ctx;",
                           "mp_context *ctx = NULL"):
            with self.subTest(expression=expression):
                parsed = self.read(expression)
                self.assertEqual(parsed.kind, LIFECYCLE_INITIALIZATION)
                self.assertIsNone(parsed.function)

    def test_a_second_statement_makes_the_slot_unreadable(self):
        """The counterexample: one slot must not authorize two calls.

        Reading the leading call is what let ``invented`` in -- the rest of the
        string then stood as evidence that the contract had asked for it.
        """

        for expression in (
            "mp_init(&ctx); invented(&ctx)",
            "mp_init(&ctx); invented(&ctx);",
            "mp_init(&ctx) invented(&ctx)",
            "mp_init(&ctx))",
        ):
            with self.subTest(expression=expression):
                parsed = self.read(expression)
                self.assertEqual(parsed.kind, LIFECYCLE_INVALID)
                self.assertIsNone(parsed.function)

    def test_prose_is_invalid_rather_than_unnamed(self):
        for expression in (
            "rebuilt for every frame", "zero initialize before the command loop",
            "one context per libFuzzer iteration", "mp_init then mp_parse",
            "&ctx", "", "   ", None, 7,
        ):
            with self.subTest(expression=expression):
                parsed = self.read(expression)
                self.assertEqual(parsed.kind, LIFECYCLE_INVALID)
                self.assertIsNone(parsed.function)

    def test_a_reserved_word_is_not_a_function(self):
        """``sizeof(mp_context)`` is an expression, not a call to make."""

        self.assertEqual(self.read("sizeof(mp_context)").kind, LIFECYCLE_INVALID)


class ConsumerAgreementTests(Stage4ProjectTests):
    """One reconciliation, four readers, and they have to read the same set.

    The projection a plan is held to, the plan validator's exempt list, Stage
    4's C audit, and the pipeline's own re-validation of the published harness
    all answer "may this harness call this name?" -- and a harness one accepts
    while another refuses is a run that publishes nothing and reports a failure
    about code it already checked.  Each of these used to compute its own
    answer; these tests pin that they now read one.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.reconciliation = reconcile_protocol_ir(
            recorded_ir(), cls.triplet, cls.functions
        )

    def setUp(self):
        # ``artifact_root`` refuses a name it has already made, so each test
        # gets its own root rather than sharing one across the class.
        self.root = self.artifact_root(f"agreement_{self.id().rsplit('.', 1)[-1]}")
        ArtifactStore(self.root).write_protocol_ir(recorded_ir())

    def test_the_projection_carries_the_reconciled_names_verbatim(self):
        projection = protocol_contract_projection(
            recorded_ir(),
            callable_helpers=self.reconciliation.callable_helpers,
        )
        self.assertEqual(
            projection.bindings["helpers"],
            sorted(self.reconciliation.callable_helpers),
        )

    def test_the_plan_validator_exempts_exactly_those_names(self):
        """Read off the refusal, which is the only place the set is observable."""

        with self.assertRaises(Stage4Error) as caught:
            parse_harness_plan(
                # ``mp_reset`` is a plausible mini_parser entry the IR never
                # evidences, so the refusal is the membership rule's and the
                # message has to say what would have been exempt.
                plan_json(self.triplet, calls=("mp_parse", "mp_reset")),
                triplet=self.triplet,
                isf_metadata={},
                declared_helpers=self.reconciliation.callable_helpers,
            )
        self.assertIn(
            "declared helpers are exempt: "
            + ", ".join(sorted(self.reconciliation.callable_helpers)),
            str(caught.exception),
        )

    def test_both_pipeline_layers_read_the_same_set_from_the_file(self):
        expected = self.reconciliation.callable_helpers
        self.assertEqual(
            declared_contract_helpers(self.root, self.triplet, self.functions),
            expected,
        )
        validator = PipelineStageValidator(
            self.triplet,
            artifacts=self.root,
            functions_json=self.root / "functions.json",
            project_root=self.phase1.parent / "project",
            config=PipelineValidationConfig(build_enabled=False, fuzz_smoke=None),
        )
        self.assertEqual(validator.contract_helpers(), expected)


class EntryIdentityTests(Stage4ProjectTests):
    """The IR has to be about this function, and the source name cannot say so.

    ``target.c`` is the same filename in every one of these benchmarks, so the
    IR's ``source`` field identifies the file it was mined from and nothing
    about which function that file's IR describes.
    """

    def test_a_matching_entry_reconciles(self):
        reconciliation = reconcile_protocol_ir(
            mined_ir(), self.triplet, self.functions
        )
        self.assertTrue(reconciliation.ok)
        self.assertEqual(reconciliation.entry_function, "mp_parse")
        self.assertEqual(reconciliation.isf_function, "mp_parse")

    def test_a_mismatched_entry_is_refused_before_anything_else(self):
        """``mp_destroy``'s IR is not ``mp_parse``'s, however it was mined.

        The source filenames are identical, so this is the only thing that
        distinguishes the two documents.
        """

        mismatched = replace(mined_ir(), entry_function="mp_destroy")
        reconciliation = reconcile_protocol_ir(
            mismatched, self.triplet, self.functions
        )
        self.assertFalse(reconciliation.ok)
        self.assertIn(
            "protocol_ir.json was mined for entry function 'mp_destroy', but "
            "this triplet's ISF is 'mp_parse'; the IR describes a different "
            "function",
            reconciliation.diagnostics,
        )

    def test_the_source_filename_is_not_used_as_identity(self):
        """Same filename, different function: still reconciled on the entry."""

        same_name = replace(mined_ir(), source_name="target.c")
        reconciliation = reconcile_protocol_ir(
            same_name, self.triplet, self.functions
        )
        self.assertTrue(reconciliation.ok, reconciliation.diagnostics)


class ReconciliationRecordTests(Stage4ProjectTests):
    """The record is what the attempt writes down, so it has to be complete."""

    def test_the_record_names_every_verdict_it_reached(self):
        reconciliation = reconcile_protocol_ir(
            mined_ir(), self.triplet, self.functions
        )
        document = json.loads(json.dumps(reconciliation.to_dict()))
        self.assertEqual(document["isf_function"], "mp_parse")
        self.assertEqual(document["entry_function"], "mp_parse")
        self.assertEqual(
            document["callable_helpers"],
            ["mp_checksum", "mp_destroy", "mp_init"],
        )
        self.assertEqual(document["reference_only_helpers"], ["le16"])
        self.assertEqual(document["diagnostics"], [])
        resolved = {item["name"]: item for item in document["helpers"]}
        self.assertEqual(resolved["le16"]["status"], INTERNAL_LINKAGE)
        self.assertEqual(resolved["le16"]["callable"], False)
        self.assertTrue(resolved["le16"]["evidence"])

    def test_the_verdicts_are_the_module_constants(self):
        """A reader of the record must not have to know a second vocabulary."""

        reconciliation = reconcile_protocol_ir(
            mined_ir(), self.triplet, self.functions
        )
        statuses = {item.resolution.status for item in reconciliation.helpers}
        self.assertLessEqual(statuses, {LINKABLE, INTERNAL_LINKAGE,
                                        DECLARED_ONLY, AMBIGUOUS, ABSENT})

    def test_the_empty_reconciliation_serialises(self):
        document = reconcile_protocol_ir(
            None, self.triplet, self.functions
        ).to_dict()
        self.assertEqual(json.loads(json.dumps(document))["callable_helpers"], [])


if __name__ == "__main__":
    unittest.main()
