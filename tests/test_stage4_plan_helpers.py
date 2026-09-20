"""A contract-declared helper may be planned without being an FT member.

A real DeepSeek run against a mined ``protocol_ir.json`` died three times out of
four on ``HarnessPlan references functions outside the FT: mp_init``.  The IR
declares ``context.init = mp_init`` and the plan prompt tells the model to name
it, but ``mp_init`` can never be in the FT: an FT is built from the structural
edges its ISF shares with other functions, and ``mp_init``'s body is a
whole-struct ``memset``, which yields no field-level evidence and therefore no
edge.  The C audit had always allowed the *call* (``stage4.py``'s
``declared_helpers``); only the plan validator did not.

These tests pin the plan half of that asymmetry, and -- just as important -- pin
that relaxing it did not turn into "any project function is allowed".  The rules
that survive are all here: a name must still be either an FT member or a
declared helper, a helper cannot satisfy FT completeness, and a helper cannot
make a duplicated FT function look unique.

``MinedMiniParserHelperTests`` runs the same shapes against the real extracted
FT and the real mined IR, so the load-bearing claim -- ``mp_init`` is a project
function outside the FT that the contract does declare -- is measured rather
than asserted.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
import unittest

from harness_generation.project_functions import ProjectFunctionIndex
from harness_generation.protocol_reconciliation import reconcile_protocol_ir
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.stage4 import (
    Stage4Error,
    parse_harness_plan,
)
from harness_generation.triplet import FunctionTriplet, TripletFunction
from harness_generation.triplet_extractor import extract_function_triplets
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer

from tests.test_stage4_protocol_ir import SOURCE, mined_ir


def build_ft(*, isf_name: str = "mp_parse",
             cleanup_name: str = "mp_destroy") -> FunctionTriplet:
    """A minimal FT shaped like the mined mini_parser one: ISF+PRF, pure HPF.

    Built by hand rather than mined: these tests are about the plan validator's
    membership rule, and a hand-built FT states that rule's inputs directly.
    """

    isf = TripletFunction(
        f"target.c:1:{isf_name}", isf_name, ("ISF", "PRF"), "target.c", 1
    )
    cleanup = TripletFunction(
        f"target.c:2:{cleanup_name}", cleanup_name, ("HPF",), "target.c", 2
    )
    return FunctionTriplet(
        isf=isf,
        prfs=(isf,),
        hpfs=(cleanup,),
        functions=(isf, cleanup),
        structures=("mp_context",),
        edges=(),
        id="ft_plan_helpers_test",
    )


def _step(name: str) -> dict[str, object]:
    return {
        "function": name,
        "arguments": ["&ctx", "data", "size"],
        "uses_fuzzer_data": True,
        "uses_fuzzer_size": True,
    }


def plan_json(triplet: FunctionTriplet, *,
              calls: tuple[str, ...],
              cleanup: tuple[str, ...] = ("mp_destroy",)) -> str:
    """A valid plan whose step names are exactly ``calls`` and ``cleanup``."""

    return json.dumps({
        "schema_version": 1,
        "triplet_id": triplet.id,
        "entrypoint": "LLVMFuzzerTestOneInput",
        "input_strategy": {
            "description": "Decode fuzzer bytes as mini_parser frames.",
            "data_identifier": "data",
            "size_identifier": "size",
        },
        "state_objects": [{
            "name": "ctx",
            "type": "mp_context",
            "initialization": "mp_init(&ctx)",
        }],
        "call_sequence": [_step(name) for name in calls],
        "cleanup_sequence": [_step(name) for name in cleanup],
        "constraints": [],
        "notes": [],
    })


class PlanHelperMembershipTests(unittest.TestCase):
    """The membership rule itself, on a hand-built FT of ``{mp_parse, mp_destroy}``."""

    def setUp(self):
        self.triplet = build_ft()
        self.helpers = ("mp_init", "mp_checksum")

    def parse(self, content: str, *, declared_helpers=()):
        return parse_harness_plan(
            content,
            triplet=self.triplet,
            isf_metadata={},
            declared_helpers=declared_helpers,
        )

    @staticmethod
    def names(plan) -> list[str]:
        return [step["function"] for step in plan.call_sequence]

    def test_a_declared_helper_may_be_called(self):
        # The mp_init case: without the relaxation this raises
        # "HarnessPlan references functions outside the FT: mp_init".
        plan = self.parse(
            plan_json(self.triplet, calls=("mp_parse", "mp_init")),
            declared_helpers=self.helpers,
        )
        self.assertEqual(self.names(plan), ["mp_parse", "mp_init"])

    def test_a_declared_helper_may_be_cleaned_up(self):
        plan = self.parse(
            plan_json(self.triplet, calls=("mp_parse",),
                      cleanup=("mp_destroy", "mp_checksum")),
            declared_helpers=self.helpers,
        )
        self.assertEqual(
            [step["function"] for step in plan.cleanup_sequence],
            ["mp_destroy", "mp_checksum"],
        )

    def test_without_the_ir_the_same_plan_is_refused(self):
        with self.assertRaisesRegex(
            Stage4Error, r"^HarnessPlan references functions outside the FT: mp_init$"
        ):
            self.parse(plan_json(self.triplet, calls=("mp_parse", "mp_init")))

    def test_a_project_function_the_contract_does_not_declare_is_refused(self):
        # The relaxation admits a *contracted* name, not any project function:
        # mp_reset is a plausible mini_parser entry the IR never evidenced.
        with self.assertRaisesRegex(Stage4Error, r"outside the FT: mp_reset \("):
            self.parse(
                plan_json(self.triplet, calls=("mp_parse", "mp_reset")),
                declared_helpers=self.helpers,
            )

    def test_an_unknown_name_is_refused(self):
        with self.assertRaisesRegex(Stage4Error, r"outside the FT: not_a_function \("):
            self.parse(
                plan_json(self.triplet, calls=("mp_parse", "not_a_function")),
                declared_helpers=self.helpers,
            )

    def test_a_helper_cannot_satisfy_ft_completeness(self):
        with self.assertRaisesRegex(Stage4Error, r"omits FT functions: mp_parse$"):
            self.parse(
                plan_json(self.triplet, calls=("mp_init",)),
                declared_helpers=self.helpers,
            )

    def test_a_duplicated_helper_is_not_an_ft_duplicate(self):
        plan = self.parse(
            plan_json(self.triplet, calls=("mp_parse", "mp_init", "mp_init")),
            declared_helpers=self.helpers,
        )
        self.assertEqual(self.names(plan).count("mp_init"), 2)

    def test_a_duplicated_ft_function_is_still_refused(self):
        with self.assertRaisesRegex(
            Stage4Error, r"duplicates FT functions: mp_parse$"
        ):
            self.parse(
                plan_json(self.triplet, calls=("mp_parse", "mp_parse")),
                declared_helpers=self.helpers,
            )

    def test_the_refusal_names_the_helpers_that_would_have_been_exempt(self):
        # The retry loop feeds this message back to the model, so a refusal
        # under a contract has to say what the contract already allows.
        with self.assertRaisesRegex(
            Stage4Error, r"outside the FT: mp_reset \(declared helpers are exempt: "
                         r"mp_checksum, mp_init\)$"
        ):
            self.parse(
                plan_json(self.triplet, calls=("mp_parse", "mp_reset")),
                declared_helpers=self.helpers,
            )

    def test_the_ft_only_refusal_carries_no_helper_clause(self):
        with self.assertRaises(Stage4Error) as caught:
            self.parse(plan_json(self.triplet, calls=("mp_parse", "mp_init")))
        self.assertNotIn("declared helpers are exempt", str(caught.exception))


class MinedMiniParserHelperTests(unittest.TestCase):
    """The same rule against the real FT and the real mined IR."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        project = Path(cls.temporary.name) / "project"
        project.mkdir()
        shutil.copy2(SOURCE, project / "target.c")
        cls.phase1 = Path(cls.temporary.name) / "phase1"
        SFGPipeline(
            MockSemanticAnalyzer(), ignored_directories=DEFAULT_IGNORES
        ).run(project, cls.phase1)
        cls.triplet = next(
            triplet
            for triplet in extract_function_triplets(load_sfg_artifacts(cls.phase1))
            if triplet.isf.function == "mp_parse"
        )
        cls.functions = ProjectFunctionIndex.from_document(
            json.loads((cls.phase1 / "functions.json").read_text(encoding="utf-8"))
        )
        cls.project_functions = cls.functions.names
        cls.reconciliation = reconcile_protocol_ir(
            mined_ir(), cls.triplet, cls.functions
        )
        cls.declared_helpers = cls.reconciliation.callable_helpers

    def test_mp_init_is_a_project_function_outside_the_ft_that_the_contract_declares(self):
        # This is why the plan validator and the C audit had to be brought into
        # agreement: the function is real, the contract names it, the FT cannot
        # contain it.  If the extractor ever learns to place it in the FT, this
        # test should be revisited rather than silently pass either way.
        self.assertIn("mp_init", self.project_functions)
        self.assertNotIn(
            "mp_init", {function.function for function in self.triplet.functions}
        )
        self.assertIn("mp_init", self.declared_helpers)

    def test_the_previously_fatal_plan_now_parses(self):
        plan = parse_harness_plan(
            plan_json(self.triplet, calls=("mp_parse", "mp_init")),
            triplet=self.triplet,
            isf_metadata={},
            declared_helpers=self.declared_helpers,
        )
        self.assertIn("mp_init", [step["function"] for step in plan.call_sequence])

    def test_the_same_plan_is_still_refused_without_the_ir(self):
        with self.assertRaisesRegex(Stage4Error, r"outside the FT: mp_init$"):
            parse_harness_plan(
                plan_json(self.triplet, calls=("mp_parse", "mp_init")),
                triplet=self.triplet,
                isf_metadata={},
            )

    def test_the_declared_set_never_exceeds_the_project_functions(self):
        self.assertLessEqual(self.declared_helpers, self.project_functions)

    def test_a_static_helper_the_contract_evidences_is_not_callable(self):
        """``le16`` is evidence, not an allowance: the call would not link.

        The contract's ``payload_length`` field says its value comes from
        ``le16() load``, which is true -- and ``le16`` is ``static`` in
        ``target.c``, so a plan that took the IR at its word and bound the name
        produced a harness the link step refused.  The name stays in the record
        as the algorithm behind the contract, and out of the allowance.
        """

        self.assertIn("le16", self.project_functions)
        self.assertIn("le16", self.reconciliation.reference_only_helpers)
        self.assertNotIn("le16", self.reconciliation.callable_helpers)
        # Refused for membership, not for linkage -- see the audit's own,
        # differently worded refusal in tests/test_stage4_structured_input.py.
        # The plan validator has no C to read, so "outside the FT" is as
        # specific as it can be, and the exempt list names the way out.
        with self.assertRaisesRegex(
            Stage4Error,
            r"outside the FT: le16 \(declared helpers are exempt: "
            r"mp_checksum, mp_destroy, mp_init\)$",
        ):
            parse_harness_plan(
                plan_json(self.triplet, calls=("mp_parse", "le16")),
                triplet=self.triplet,
                isf_metadata={},
                declared_helpers=self.declared_helpers,
            )


if __name__ == "__main__":
    unittest.main()
