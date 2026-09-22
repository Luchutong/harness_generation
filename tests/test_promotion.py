import hashlib
import json

from harness_generation.artifacts import ArtifactStore
from harness_generation.promotion import promote_harness


def test_promotion_requires_every_formal_component_and_binds_the_pair(tmp_path):
    layout = ArtifactStore(tmp_path).for_triplet("ft_parse").ensure_generation()
    source = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }"
    plan = {"schema_version": 1, "triplet_id": "ft_parse"}

    assert not promote_harness(
        layout, harness_code=source, harness_plan=plan,
        validation_summary={"overall": "passed", "intermediate": "passed"},
    )
    assert not layout.harness.exists()
    assert not layout.stable_harness_plan.exists()

    statuses = {name: "passed" for name in ("intermediate", "compiler", "linker", "runtime")}
    layout.write_text(layout.stage4_harness, source + "\n")
    layout.write_json(layout.stage4_harness_plan, plan)
    for name in statuses:
        layout.write_validation(name, {
            "validator": name, "status": "passed", "success": True,
            "errors": [], "warnings": [], "metadata": {},
        })
    assert promote_harness(
        layout, harness_code=source, harness_plan=plan,
        validation_summary={"overall": "passed", **statuses},
    )
    assert layout.harness.read_text(encoding="utf-8") == source + "\n"
    assert json.loads(layout.stable_harness_plan.read_text()) == plan
    manifest = json.loads(layout.promotion.read_text())
    assert manifest["status"] == "stable_promoted"
    assert manifest["source_sha256"] == hashlib.sha256((source + "\n").encode()).hexdigest()


def test_partial_validation_summary_is_not_a_pass(tmp_path):
    layout = ArtifactStore(tmp_path).for_triplet("ft_parse").ensure_generation()
    layout.write_validation("intermediate", {
        "validator": "intermediate", "status": "passed", "success": True,
        "errors": [], "warnings": [], "metadata": {},
    })
    assert json.loads(layout.validation_summary.read_text())["overall"] != "passed"
