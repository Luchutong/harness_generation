import json
from pathlib import Path

import pytest

from harness_generation.artifacts import ArtifactStore
from harness_generation.protocol_ir import ProtocolIR
from harness_generation.target_contract import (
    InputContract,
    ResourceContract,
    TargetContract,
    TargetContractError,
)
from harness_generation.triplet import TripletOwnershipRelation
from harness_generation.stage4 import Stage4Error, parse_harness_plan
from harness_generation.triplet import load_triplets_json
from tests.test_generation_cli import harness_plan


ROOT = Path(__file__).resolve().parents[1]
MINI_PARSER = ROOT / "benchmarks" / "mini_parser"


def test_missing_protocol_facts_use_explicit_raw_unknown_contract():
    contract = TargetContract(
        entry_function="parse",
        input=InputContract.raw_passthrough("parse"),
    )

    assert contract.input.mode == "raw_bytes"
    assert contract.input.status == "unknown"
    assert contract.input.source == "absence_of_protocol_contract"
    assert "length prefix" not in json.dumps(contract.to_dict())
    assert TargetContract.from_json(contract.to_json()).to_json() == contract.to_json()


def test_contract_identity_includes_fact_content_not_only_ids():
    original = TargetContract(
        entry_function="parse",
        input=InputContract(
            id="input-1", mode="raw_bytes", status="unknown",
            source="test", evidence=("source",),
        ),
    )
    changed = TargetContract(
        entry_function="parse",
        input=InputContract(
            id="input-1", mode="raw_bytes", status="known",
            source="test", evidence=("source",), confidence=1.0,
        ),
    )
    assert original.contract_id != changed.contract_id


def test_resource_contract_keeps_usage_lifecycle_constraints():
    relation = TripletOwnershipRelation(
        "own_usage", "f_create", "create", "Handle", "f_free", "free",
        consumers=("parse",), evidence=("tests/a.c:4",), confidence=0.9,
        source="usage_mining+llm", producer_binding="out_parameter",
        producer_argument_index=1, lifecycle_kind="owned_resource",
        conditions=("$value != 0",), path_kind="error", support_total=2,
        support_by_source={"test": 2}, usage_pattern_id="usg_one",
        observed_sequence=("create", "parse", "parse", "free"),
    )
    resource = ResourceContract.from_ownership(relation)
    assert resource.metadata["producer_binding"] == "out_parameter"
    assert resource.metadata["producer_argument_index"] == 1
    assert resource.metadata["observed_sequence"] == [
        "create", "parse", "parse", "free",
    ]


def test_legacy_protocol_document_is_adapted_without_inventing_fields():
    document = json.loads((MINI_PARSER / "protocol.json").read_text(encoding="utf-8"))
    contract = TargetContract.from_protocol_document(document)

    assert contract.entry_function == document["entry_function"]
    assert contract.input.mode == "framed"
    assert contract.input.status == "known"
    assert contract.input.source == "legacy_protocol_document"
    assert contract.input.frame == document["contract"]["frame"]


def test_contract_artifact_persists_and_rejects_counterfeit_aggregate_id(tmp_path):
    contract = TargetContract(
        entry_function="parse",
        input=InputContract.raw_passthrough("parse"),
    )
    store = ArtifactStore(tmp_path)
    assert store.write_target_contract(contract) == store.contract
    assert store.load_target_contract().to_json() == contract.to_json()

    document = contract.to_json()
    document["id"] = "contract_forged"
    store.contract.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(TargetContractError, match="id"):
        store.load_target_contract()


def test_protocol_ir_adapter_keeps_frame_and_sequence_components():
    source = (MINI_PARSER / "target.c").read_bytes()
    from harness_generation.protocol_miner import mine_protocol_facts

    facts = mine_protocol_facts(source, "mp_parse", filename="target.c")
    ir = ProtocolIR.from_facts_and_conventions(facts, None, strict=True)
    contract = TargetContract.from_protocol_ir(ir)

    assert contract.entry_function == "mp_parse"
    assert contract.input.frame is not None
    assert contract.input.source == "protocol_ir"
    assert contract.input.status == "known"


def test_explicit_recursive_grammar_is_typed_and_required_by_plan():
    triplet = load_triplets_json(ROOT / "artifacts" / "simple" / "triplets.json")[0]
    functions = json.loads((ROOT / "artifacts" / "simple" / "functions.json").read_text())
    isf = next(item for item in functions["functions"]
               if item["id"] == triplet.isf.function_id)
    contract = TargetContract.from_protocol_document({
        "entry_function": triplet.isf.function,
        "contract": {"grammar": {
            "start": "value",
            "rules": {"value": "object | string", "object": "'{' value? '}'",
                      "string": "'\\\"' character* '\\\"'"},
        }},
    })
    assert contract.input.mode == "grammar"
    assert contract.input.status == "known"
    plan = json.loads(harness_plan(triplet.id))
    with pytest.raises(Stage4Error, match="grammar input mode"):
        parse_harness_plan(json.dumps(plan), triplet=triplet,
                           isf_metadata=isf, target_contract=contract)
    plan["input_strategy"].update(
        mode="grammar", start_symbol="value", max_depth=4,
        max_output_bytes=4096,
    )
    accepted = parse_harness_plan(json.dumps(plan), triplet=triplet,
                                  isf_metadata=isf, target_contract=contract)
    assert accepted.input_strategy["mode"] == "grammar"
