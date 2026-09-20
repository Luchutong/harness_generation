"""Typed relations must reject the recorded one-frame regression."""

from __future__ import annotations

import json
from pathlib import Path

from harness_generation.artifacts import ArtifactStore
from harness_generation.llm import MockLLM
from harness_generation.protocol_ir import (
    FieldRelation, ProtocolEvidence, ProtocolIR, ProtocolIRError,
)
from harness_generation.protocol_conventions import _state_accesses
from harness_generation.protocol_miner import ProtocolMinerError
from harness_generation.protocol_plan_validation import (
    protocol_contract_projection, validate_plan_contract,
)
from harness_generation.stage4 import (
    Stage4Error, Stage4Generator, _analyze_c, _samples_payload_length,
)
from tests.test_stage4_protocol_ir import Stage4ProjectTests, mined_ir


ROOT = Path(__file__).resolve().parents[1]
DEGRADED = ROOT / "tests/fixtures/coverage_arms/contracted_published.c"
REFERENCE = ROOT / "benchmarks/mini_parser/harnesses/structured.c"
HISTORICAL = ROOT / "tests/fixtures/stage4_recorded_attempts/protocol_ir.json"


class TypedFactTests(Stage4ProjectTests):
    def test_mined_size_relation_is_typed_and_source_backed(self):
        ir = mined_ir()
        payload = ir.fields_by_role("payload")[0]
        self.assertEqual(payload.width, "payload_length")
        self.assertEqual(payload.size, FieldRelation(
            "size_of", "payload", "parse", evidence=payload.relation.evidence,
        ))
        self.assertTrue(payload.relation.evidence)
        self.assertEqual(
            ProtocolIR.from_json(ir.to_json()).frame.fields, ir.frame.fields
        )
        projected = protocol_contract_projection(
            ir, callable_helpers=self.callable_helpers_for(ir)
        )
        self.assertEqual(
            projected.bindings["frame"]["fields"][-1]["relation"],
            {"kind": "size_of", "target": "payload", "direction": "parse"},
        )

    def test_old_ir_remains_a_lossless_round_trip(self):
        document = json.loads(HISTORICAL.read_text(encoding="utf-8"))
        self.assertEqual(ProtocolIR.from_json(document).to_json(), document)

    def test_loader_rejects_unevidenced_typed_state(self):
        document = mined_ir().to_json()
        document["stateful_operations"][0]["writes"] = ["ctx->invented"]
        with self.assertRaisesRegex(ProtocolIRError, "has no evidence"):
            ProtocolIR.from_json(document)

    def test_strict_mining_does_not_promote_evidence_free_relation(self):
        from harness_generation.protocol_miner import mine_protocol_facts
        from tests.test_stage4_protocol_ir import SOURCE
        facts = mine_protocol_facts(SOURCE.read_bytes(), "mp_parse", filename="target.c")
        length = next(field for field in facts.fields if field.role == "payload_length")
        length.evidence.clear()
        with self.assertRaises(ProtocolMinerError):
            ProtocolIR.from_facts_and_conventions(facts, strict=True)
        with self.assertRaisesRegex(ProtocolIRError, "requires source evidence"):
            FieldRelation("size_of", "payload", "parse")

    def test_state_reads_writes_and_order_are_structured(self):
        ir = mined_ir()
        operations = {item.opcode: item for item in ir.stateful_operations}
        self.assertIn("ctx->saved", operations["MP_STORE"].writes)
        self.assertIn("ctx->saved", operations["MP_USE"].reads)
        self.assertIn("ctx->saved", {item.name for item in ir.state_variables})
        self.assertTrue(all(item.evidence for item in ir.state_variables))
        self.assertTrue(all(
            isinstance(entry, ProtocolEvidence)
            for variable in ir.state_variables for entry in variable.evidence
        ))

        projection = protocol_contract_projection(
            ir, callable_helpers=self.callable_helpers_for(ir)
        )
        bindings = json.loads(json.dumps(projection.renderable()))
        strategy = {
            "bounded_steps": 32,
            "payload_length_strategy": "fuzz_byte_bounded",
            "payload_length_expression": "data[pos++] % (MP_MAX_PAYLOAD + 1u)",
        }
        self.assertTrue(validate_plan_contract(
            bindings, projection=projection, input_strategy=strategy
        ).ok)
        bindings["stateful_operations"] = ["MP_USE", "MP_STORE", "MP_RELEASE"]
        verdict = validate_plan_contract(
            bindings, projection=projection, input_strategy=strategy
        )
        self.assertIn("MP_USE must follow MP_STORE", " ".join(verdict.violations))

    def test_recorded_source_snippets_yield_guard_symbols(self):
        document = json.loads(HISTORICAL.read_text(encoding="utf-8"))
        operations = {item["opcode"]: item for item in document["stateful_operations"]}
        store_writes, _, store_guards = _state_accesses(
            operations["MP_STORE"]["evidence"]
        )
        _, use_reads, use_guards = _state_accesses(
            operations["MP_USE"]["evidence"]
        )
        self.assertIn("ctx->saved", store_writes)
        self.assertIn("ctx->saved_len", store_writes)
        self.assertIn("ctx->owns_saved", store_guards)
        self.assertIn("ctx->saved", use_reads)
        self.assertIn("ctx->saved_len", use_guards)

    def test_recorded_degradation_is_rejected_by_stage4(self):
        root = self.artifact_root("p1_recorded_regression")
        ArtifactStore(root).write_protocol_ir(mined_ir())
        llm = MockLLM([self.plan_for(root), DEGRADED.read_text(encoding="utf-8")])
        with self.assertRaisesRegex(Stage4Error, "payload length is not sampled"):
            Stage4Generator(llm).run(
                self.triplet, rough_code=self.rough_code(),
                functions_json=root / "functions.json", artifacts=root,
            )
        self.assertEqual(len(llm.calls), 2)

    def test_reference_length_sampling_passes_and_opcode_only_does_not(self):
        source = REFERENCE.read_text(encoding="utf-8")
        self.assertTrue(_samples_payload_length(_analyze_c(source)))
        degraded = DEGRADED.read_text(encoding="utf-8")
        self.assertFalse(_samples_payload_length(_analyze_c(degraded)))
        unrelated_helper = (
            "static unsigned sample(const unsigned char *data) { "
            "unsigned requested = data[0] % 4; return requested; }\n"
        )
        self.assertFalse(_samples_payload_length(
            _analyze_c(unrelated_helper + degraded)
        ))
        commented = degraded.replace(
            "size_t payload_len = remaining;",
            "size_t payload_len = remaining; /* size_t requested = "
            "data[offset++] % MP_MAX_PAYLOAD; payload_len = requested; */",
        )
        self.assertFalse(_samples_payload_length(_analyze_c(commented)))

    def test_a_sampled_but_undeclared_expression_is_refused(self):
        from tests.test_protocol_ir_e2e import structured_harness

        root = self.artifact_root("p1_expression_mismatch")
        ir = mined_ir()
        ArtifactStore(root).write_protocol_ir(ir)
        harness = structured_harness(ir).replace(
            "data[pos++] % (MP_MAX_PAYLOAD + 1u)",
            "data[pos++] & MP_MAX_PAYLOAD",
        )
        self.assertTrue(_samples_payload_length(_analyze_c(harness)))
        llm = MockLLM([self.plan_for(root), harness])
        with self.assertRaisesRegex(Stage4Error, "declared payload length expression"):
            Stage4Generator(llm).run(
                self.triplet, rough_code=self.rough_code(),
                functions_json=root / "functions.json", artifacts=root,
            )
