"""The plan gate: a plan must declare the contract before any C is written.

Stage 4 renders two prompts.  The first asks for a HarnessPlan, the second for
the C harness that plan describes.  Between them sits
:func:`harness_generation.protocol_plan_validation.validate_plan_contract`,
which compares the plan's structured ``protocol_contract_bindings`` against a
typed projection of the mined IR and refuses the attempt on any disagreement.

Three properties are load-bearing, and each has its own class here:

``ProjectionTests``
    the projection carries exactly the contract facts a plan can be held to,
    and names the ones it deliberately cannot (prose values, requirements,
    mining limitations).  The literal in ``test_stage4_protocol_ir.py`` is
    pinned against it, so a projection that drifts fails loudly.

``ContractGateTests``
    every disagreement is refused *before the transform LLM is called*, and the
    refusal is recorded on the attempt.  A gate that ran after the harness audit
    would still let a corrupt plan shape the C source.

``FtOnlyTests``
    with no ``protocol_ir.json`` nothing changes: the plan artifact gains no
    key, no conformance record is written, and a plan that binds a contract it
    was never given is refused for inventing one.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.llm import MockLLM
from harness_generation.protocol_ir import ProtocolIR
from harness_generation.protocol_miner import mine_protocol_facts
from harness_generation.protocol_plan_validation import (
    LIFETIME_PER_FRAME,
    LIFETIME_PER_ITERATION,
    protocol_contract_projection,
    validate_plan_contract,
)
from harness_generation.stage4 import Stage4Error, Stage4Generator
from tests.test_stage4_protocol_ir import (
    CONTRACT_BINDINGS,
    PROJECT_FUNCTIONS,
    SOURCE,
    Stage4ProjectTests,
    mined_ir,
)


def deep_copy(value: Any) -> Any:
    """A JSON round trip, so a test cannot mutate the fixture it copies."""

    return json.loads(json.dumps(value))


def convention_free_ir() -> ProtocolIR:
    """The mined frame block with no convention vote: no context, no opcodes.

    A/B-only mining is a supported run, and it is the only way to get a
    projection whose ``context`` is ``None`` -- which is what the
    "invented a context" branch of the comparison needs.
    """

    facts = mine_protocol_facts(SOURCE.read_bytes(), "mp_parse", filename="target.c")
    return ProtocolIR.from_facts_and_conventions(facts, None)


class ProjectionTests(Stage4ProjectTests):
    """What a plan is held to, and what it deliberately is not."""

    def projection(self):
        return protocol_contract_projection(
            mined_ir(), project_functions=PROJECT_FUNCTIONS
        )

    def test_the_literal_fixture_is_exactly_the_projection(self):
        """The pinned literal and the code have to agree, or one is stale."""

        self.assertEqual(self.projection().renderable(), CONTRACT_BINDINGS)

    def test_the_projection_carries_only_source_constants_as_values(self):
        """Magic and version are literals; the rest are descriptions.

        ``payload_length.value`` is ``"le16() load"``.  Comparing that would be
        comparing prose, which is the thing this gate exists not to do -- so it
        is absent from the projection, not present and ignored.
        """

        fields = self.projection().renderable()["frame"]["fields"]
        # Indexed, not keyed by role: the two magic bytes share a role.
        self.assertEqual(fields[0]["value"], "'M'")
        self.assertEqual(fields[1]["value"], "'P'")
        self.assertEqual(fields[2]["value"], "1")
        for index in (3, 4, 5, 6):
            with self.subTest(index=index):
                self.assertNotIn("value", fields[index])

    def test_the_projection_names_what_it_does_not_check(self):
        """The blind spots are declared, not silently approximated."""

        warnings = " | ".join(self.projection().warnings)
        self.assertIn("descriptive, not literals", warnings)
        self.assertIn("harness policy", warnings)
        self.assertIn("mining limitation not checked here", warnings)
        self.assertIn("prose requirement not checked here", warnings)

    def test_the_context_projection_names_functions_and_an_enum_lifetime(self):
        context = self.projection().renderable()["context"]
        self.assertEqual(context, {
            "type": "mp_context",
            "init": "mp_init",
            "destroy": "mp_destroy",
            "lifetime": LIFETIME_PER_ITERATION,
        })

    def test_a_context_rebuilt_per_frame_projects_the_other_lifetime(self):
        ir = mined_ir()
        rebuilt = replace(ir, context=replace(ir.context, lifetime="rebuilt per frame"))
        projection = protocol_contract_projection(
            rebuilt, project_functions=PROJECT_FUNCTIONS
        )
        self.assertEqual(
            projection.renderable()["context"]["lifetime"], LIFETIME_PER_FRAME
        )

    def test_helpers_are_intersected_with_the_project(self):
        """A name the IR evidences but the project does not define is not a licence."""

        ir = mined_ir()
        ghost = protocol_contract_projection(ir, project_functions={"mp_parse"})
        self.assertEqual(ghost.renderable()["helpers"], [])
        self.assertEqual(
            self.projection().renderable()["helpers"],
            ["le16", "mp_checksum", "mp_destroy", "mp_init"],
        )

    def test_no_ir_projects_to_nothing(self):
        self.assertIsNone(protocol_contract_projection(None))


class ValidatorTests(unittest.TestCase):
    """The comparison itself, without a project or an LLM in the way."""

    def projection(self):
        return protocol_contract_projection(
            mined_ir(), project_functions=PROJECT_FUNCTIONS
        )

    def test_the_same_inputs_give_the_same_verdict(self):
        """Deterministic: the gate re-reads no source and asks no model."""

        projection = self.projection()
        bindings = deep_copy(projection.renderable())
        first = validate_plan_contract(
            bindings, projection=projection, input_strategy={"bounded_steps": 32}
        )
        second = validate_plan_contract(
            bindings, projection=projection, input_strategy={"bounded_steps": 32}
        )
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertTrue(first.ok)

    def test_warnings_are_not_violations(self):
        conformance = validate_plan_contract(
            deep_copy(self.projection().renderable()),
            projection=self.projection(),
            input_strategy={"bounded_steps": 32},
        )
        self.assertTrue(conformance.warnings)
        self.assertEqual(conformance.violations, ())
        self.assertTrue(conformance.ok)

    def test_no_projection_and_no_bindings_is_a_pass(self):
        conformance = validate_plan_contract(None, projection=None)
        self.assertTrue(conformance.ok)
        self.assertIsNone(conformance.projection)

    def test_an_empty_bindings_object_binds_nothing(self):
        """``{}`` is "declared nothing", which is the FT-only shape."""

        self.assertTrue(validate_plan_contract({}, projection=None).ok)
        self.assertFalse(
            validate_plan_contract({}, projection=self.projection()).ok
        )

    def test_a_context_the_contract_never_declared_is_refused(self):
        """An A/B-only contract states no lifecycle; a plan may not supply one."""

        projection = protocol_contract_projection(
            convention_free_ir(), project_functions=PROJECT_FUNCTIONS
        )
        self.assertIsNone(projection.renderable()["context"])
        bindings = deep_copy(projection.renderable())
        bindings["context"] = {
            "type": "mp_context", "init": "mp_init",
            "destroy": "mp_destroy", "lifetime": LIFETIME_PER_ITERATION,
        }

        conformance = validate_plan_contract(bindings, projection=projection)
        self.assertFalse(conformance.ok)
        self.assertIn("binds a context", conformance.violations[0])
        self.assertIn("init", conformance.violations[0])

    def test_the_verdict_is_json_serializable_for_the_attempt_record(self):
        conformance = validate_plan_contract(
            {"frame": {"payload_offset": 4}}, projection=self.projection()
        )
        document = json.loads(json.dumps(conformance.to_dict()))
        self.assertEqual(document["status"], "failed")
        self.assertTrue(document["violations"])
        self.assertEqual(
            document["protocol_contract"]["bindings"]["frame"]["payload_offset"], 8
        )


class ContractGateTests(Stage4ProjectTests):
    """Every disagreement is refused, and refused before the transform call."""

    def ir_root(self, name: str) -> Path:
        root = self.artifact_root(name)
        ArtifactStore(root).write_protocol_ir(mined_ir())
        return root

    def faithful(self, root: Path) -> dict:
        return deep_copy(self.bindings_in(root))

    def parsed(self, root: Path) -> dict:
        path = (
            root / "generation" / self.triplet.id / "stage4" / "attempt_001"
            / "parsed.json"
        )
        return json.loads(path.read_text(encoding="utf-8"))

    def plan_artifact(self, root: Path) -> dict:
        path = (
            root / "generation" / self.triplet.id / "stage4" / "attempt_001"
            / "plan.json"
        )
        return json.loads(path.read_text(encoding="utf-8"))

    def published(self, root: Path) -> Path:
        return ArtifactStore(root).for_triplet(self.triplet.id).harness

    def refused(self, root: Path, bindings, pattern: str,
                **plan_kwargs: Any) -> tuple[list, str]:
        """Run Stage 4 and insist the plan gate is what stopped it."""

        plan = self.harness_plan(bindings=bindings, **plan_kwargs)
        llm = MockLLM([plan, self.harness_code()])
        with self.assertRaisesRegex(Stage4Error, pattern) as caught:
            Stage4Generator(llm).run(
                self.triplet,
                rough_code=self.rough_code(),
                functions_json=root / "functions.json",
                artifacts=root,
            )
        # One call, not two: the gate runs before the transform prompt, so a
        # plan it refuses never reaches the model that writes C.
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(self.parsed(root)["phase"], "harness_plan")
        self.assertFalse(self.published(root).exists())
        return llm, str(caught.exception)

    def accepted(self, root: Path, bindings):
        llm = MockLLM([self.harness_plan(bindings=bindings), self.harness_code()])
        return llm, Stage4Generator(llm).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )

    # -- frame layout ------------------------------------------------------

    def test_a_moved_payload_offset_is_refused(self):
        root = self.ir_root("gate_offset")
        bindings = self.faithful(root)
        bindings["frame"]["payload_offset"] = 4

        _, message = self.refused(
            root, bindings, r"does not preserve the protocol contract"
        )
        self.assertIn(
            "frame.payload_offset is 4, the contract says 8", message
        )

    def test_a_widened_field_is_refused(self):
        root = self.ir_root("gate_width")
        bindings = self.faithful(root)
        bindings["frame"]["fields"][4]["width"] = 4

        _, message = self.refused(root, bindings, r"fields\[4\]\.width is 4")
        self.assertIn("the contract says 2", message)

    def test_a_dropped_endianness_is_refused(self):
        """The length is little-endian in the contract; a plan may not forget it."""

        root = self.ir_root("gate_endian")
        bindings = self.faithful(root)
        del bindings["frame"]["fields"][4]["endianness"]

        self.refused(root, bindings, r"fields\[4\]\.endianness is None")

    def test_a_wrong_magic_is_refused(self):
        root = self.ir_root("gate_magic")
        bindings = self.faithful(root)
        bindings["frame"]["fields"][0]["value"] = "'X'"

        _, message = self.refused(root, bindings, r"fields\[0\]\.value is \"'X'\"")
        self.assertIn("the contract says \"'M'\"", message)

    def test_an_invented_frame_field_is_refused(self):
        root = self.ir_root("gate_extra_field")
        bindings = self.faithful(root)
        bindings["frame"]["fields"].append(
            {"role": "reserved", "name": "reserved", "offset": 3, "width": 1}
        )

        _, message = self.refused(root, bindings, r"frame\.fields is ")
        self.assertIn("reserved", message)

    def test_a_dropped_frame_field_is_refused(self):
        root = self.ir_root("gate_missing_field")
        bindings = self.faithful(root)
        bindings["frame"]["fields"].pop(5)

        _, message = self.refused(root, bindings, r"frame\.fields is ")
        self.assertIn("checksum", message)

    def test_a_wrong_payload_cap_symbol_is_refused(self):
        """The cap is whatever the miner measured, not a remembered name."""

        root = self.ir_root("gate_symbol")
        bindings = self.faithful(root)
        bindings["frame"]["max_payload_symbol"] = "MP_MAX_PAYLOAD_OLD"

        self.refused(root, bindings, r"max_payload_symbol is 'MP_MAX_PAYLOAD_OLD'")

    # -- input-construction policy -----------------------------------------

    def test_a_missing_checksum_repair_is_refused(self):
        root = self.ir_root("gate_checksum")
        bindings = self.faithful(root)
        bindings["input_model"]["repair_checksum"] = False

        self.refused(root, bindings, r"has a checksum field the harness has to fill in")

    def test_a_missing_length_repair_is_refused(self):
        root = self.ir_root("gate_length")
        bindings = self.faithful(root)
        bindings["input_model"]["repair_length"] = False

        self.refused(root, bindings, r"has a payload_length field the harness has to fill in")

    def test_a_payload_taken_away_from_the_fuzzer_is_refused(self):
        root = self.ir_root("gate_payload_constant")
        bindings = self.faithful(root)
        bindings["input_model"]["payload_fuzzer_controlled"] = False

        self.refused(root, bindings, r"payload comes from fuzz bytes")

    def test_a_missing_bounded_loop_is_refused(self):
        root = self.ir_root("gate_loop")
        bindings = self.faithful(root)
        bindings["input_model"]["bounded_multi_frame"] = False

        self.refused(root, bindings, r"bounded multi-frame command loop")

    def test_a_non_positive_loop_cap_is_refused(self):
        """Zero in both places: the plan agrees with itself and still loops forever."""

        root = self.ir_root("gate_zero_steps")
        bindings = self.faithful(root)
        bindings["input_model"]["bounded_steps"] = 0

        self.refused(
            root, bindings, r"bounded_steps must be a positive integer",
            bounded_steps=0,
        )

    def test_two_disagreeing_loop_caps_are_refused(self):
        """The plan's own two statements about the cap have to agree."""

        root = self.ir_root("gate_split_steps")
        bindings = self.faithful(root)
        bindings["input_model"]["bounded_steps"] = 16

        _, message = self.refused(root, bindings, r"two different loop caps")
        self.assertIn("input_strategy.bounded_steps is 32", message)
        self.assertIn("bounded_steps is 16", message)

    # -- context lifetime --------------------------------------------------

    def test_a_missing_context_is_refused(self):
        root = self.ir_root("gate_no_context")
        bindings = self.faithful(root)
        bindings["context"] = None

        self.refused(
            root, bindings,
            r"declares a context lifecycle, but protocol_contract_bindings\.context is missing",
        )

    def test_a_context_rebuilt_per_frame_is_refused(self):
        root = self.ir_root("gate_per_frame")
        bindings = self.faithful(root)
        bindings["context"]["lifetime"] = LIFETIME_PER_FRAME

        self.refused(root, bindings, r"context\.lifetime is 'per_frame'")

    def test_a_context_naming_the_wrong_lifecycle_helper_is_refused(self):
        root = self.ir_root("gate_wrong_init")
        bindings = self.faithful(root)
        bindings["context"]["init"] = "ctx_new"

        self.refused(root, bindings, r"context\.init is 'ctx_new', the contract says 'mp_init'")

    # -- opcodes and helpers -----------------------------------------------

    def test_a_dropped_stateful_opcode_is_refused(self):
        root = self.ir_root("gate_dropped_opcode")
        bindings = self.faithful(root)
        bindings["stateful_operations"].remove("MP_STORE")

        self.refused(root, bindings, r"drops stateful opcodes the contract names: MP_STORE")

    def test_an_invented_stateful_opcode_is_refused(self):
        root = self.ir_root("gate_invented_opcode")
        bindings = self.faithful(root)
        bindings["stateful_operations"].append("MP_FORMAT")

        self.refused(root, bindings, r"does not name: MP_FORMAT")

    def test_an_unevidenced_helper_is_refused(self):
        root = self.ir_root("gate_invented_helper")
        bindings = self.faithful(root)
        bindings["helpers"].append("invented_checksum")

        _, message = self.refused(root, bindings, r"does not evidence as project functions")
        self.assertIn("invented_checksum", message)

    def test_the_gate_refuses_before_the_transform_prompt_is_rendered(self):
        """The refusal is a *plan* failure: no prompt.txt, no response.txt."""

        root = self.ir_root("gate_early")
        bindings = self.faithful(root)
        del bindings["context"]

        self.refused(root, bindings, r"does not preserve the protocol contract")
        attempt = (
            root / "generation" / self.triplet.id / "stage4" / "attempt_001"
        )
        # The plan response is recorded -- this is a plan failure -- but nothing
        # downstream of the gate exists, because the gate is upstream of it.
        self.assertTrue((attempt / "plan_response.txt").is_file())
        self.assertFalse((attempt / "plan.json").exists())
        self.assertFalse((attempt / "prompt.txt").exists())
        self.assertFalse((attempt / "harness.c").exists())
        self.assertEqual(self.parsed(root)["status"], "failed")
        self.assertEqual(self.parsed(root)["error_type"], "Stage4Error")

    # -- the accepted path -------------------------------------------------

    def test_a_faithful_plan_publishes_and_records_what_it_was_measured_against(self):
        root = self.ir_root("gate_faithful")
        bindings = self.faithful(root)
        llm, result = self.accepted(root, bindings)

        self.assertEqual(len(llm.calls), 2)
        self.assertTrue(self.published(root).is_file())

        conformance = self.parsed(root)["protocol_contract_conformance"]
        self.assertEqual(conformance["status"], "passed")
        self.assertEqual(conformance["violations"], [])
        self.assertTrue(conformance["warnings"])
        # The record and the artifact agree about the bindings, or one of them
        # is a second opinion about what the gate decided.
        self.assertEqual(conformance["protocol_contract_bindings"], bindings)
        self.assertEqual(
            self.plan_artifact(root)["protocol_contract_bindings"], bindings
        )

    def test_the_published_plan_json_carries_the_bindings_it_was_gated_on(self):
        root = self.ir_root("gate_plan_artifact")
        bindings = self.faithful(root)
        self.accepted(root, bindings)

        stable = json.loads((
            root / "generation" / self.triplet.id / "stage4_harness_plan.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(stable["protocol_contract_bindings"], bindings)


class FtOnlyTests(Stage4ProjectTests):
    """With no ``protocol_ir.json``, the attempt record is what it always was."""

    PLAN_KEYS = {
        "schema_version", "triplet_id", "entrypoint", "input_strategy",
        "state_objects", "call_sequence", "cleanup_sequence", "constraints",
        "notes", "generation_metadata",
    }

    def generate(self, root: Path, bindings):
        llm = MockLLM([self.harness_plan(bindings=bindings), self.harness_code()])
        return llm, Stage4Generator(llm).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )

    def attempt(self, root: Path, name: str) -> Path:
        return (
            root / "generation" / self.triplet.id / "stage4" / "attempt_001" / name
        )

    def test_a_plan_with_no_bindings_gains_no_key_without_an_ir(self):
        root = self.artifact_root("ft_only")
        self.generate(root, None)

        plan = json.loads(self.attempt(root, "plan.json").read_text(encoding="utf-8"))
        self.assertEqual(set(plan), self.PLAN_KEYS)
        self.assertNotIn("protocol_contract_bindings", plan)

    def test_a_plan_with_no_bindings_records_no_conformance_without_an_ir(self):
        root = self.artifact_root("ft_only_record")
        self.generate(root, None)

        parsed = json.loads(self.attempt(root, "parsed.json").read_text(encoding="utf-8"))
        self.assertEqual(parsed["status"], "passed")
        self.assertNotIn("protocol_contract_conformance", parsed)

    def test_a_plan_that_binds_a_contract_it_was_not_given_is_refused(self):
        """Inventing a framed protocol is exactly what the fallback forbids."""

        root = self.artifact_root("ft_only_invented")
        llm = MockLLM([self.harness_plan(bindings=CONTRACT_BINDINGS), self.harness_code()])
        with self.assertRaisesRegex(Stage4Error, r"no protocol IR was supplied"):
            Stage4Generator(llm).run(
                self.triplet,
                rough_code=self.rough_code(),
                functions_json=root / "functions.json",
                artifacts=root,
            )
        self.assertEqual(len(llm.calls), 1)
        self.assertFalse(ArtifactStore(root).for_triplet(self.triplet.id).harness.exists())

    def test_a_plan_that_binds_nothing_while_an_ir_exists_is_refused(self):
        """The other half: a supplied contract must be declared, not ignored."""

        root = self.artifact_root("with_ir_unbound")
        ArtifactStore(root).write_protocol_ir(mined_ir())
        llm = MockLLM([self.harness_plan(bindings=None), self.harness_code()])
        with self.assertRaisesRegex(Stage4Error, r"omits protocol_contract_bindings"):
            Stage4Generator(llm).run(
                self.triplet,
                rough_code=self.rough_code(),
                functions_json=root / "functions.json",
                artifacts=root,
            )
        self.assertEqual(len(llm.calls), 1)

    def test_bindings_that_are_not_an_object_are_refused_by_the_parser(self):
        """A gate needs a shape to compare; the parser owns the type error."""

        root = self.artifact_root("with_ir_wrong_type")
        ArtifactStore(root).write_protocol_ir(mined_ir())
        llm = MockLLM([self.harness_plan(bindings="yes"), self.harness_code()])
        with self.assertRaisesRegex(
            Stage4Error, r"protocol_contract_bindings must be an object"
        ):
            Stage4Generator(llm).run(
                self.triplet,
                rough_code=self.rough_code(),
                functions_json=root / "functions.json",
                artifacts=root,
            )
        self.assertEqual(len(llm.calls), 1)


if __name__ == "__main__":
    unittest.main()
