"""Generation is the outer sample; seeds are repeated runs within it."""

import json
from copy import deepcopy
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from harness_generation.artifacts import ArtifactStore
from harness_generation.coverage_arms import (
    CoverageArmsConfig, DEFAULT_MANIFEST, TARGET_LAYER, digest, load_manifest,
)
from harness_generation.generation_variance import (
    _input_digests, render_report, run_campaign, summarize,
)
from harness_generation.llm import MockLLM
from harness_generation.triplet import load_triplets_json


ROOT = Path(__file__).resolve().parents[1]
FT_ID = load_triplets_json(ROOT / "artifacts" / "simple" / "triplets.json")[0].id
RECORDED = ROOT / "tests" / "fixtures" / "generation_variance"


class GenerationVarianceTests(unittest.TestCase):
    def test_three_isolated_requests_keep_failures_and_separate_variances(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "template"
            template.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copyfile(ROOT / "artifacts" / "simple" / name,
                                template / name)
            (template / "protocol_ir.json").write_text("{}", encoding="utf-8")
            clients = []
            roots = []

            def client_factory(_number):
                client = MockLLM([])
                clients.append(client)
                return client

            def generate(argv, *, llm, run_command):
                self.assertTrue(run_command)
                self.assertIn(llm, clients)
                trial_root = Path(argv[argv.index("--artifacts") + 1])
                roots.append(trial_root)
                self.assertEqual(
                    (trial_root / "functions.json").read_bytes(),
                    (template / "functions.json").read_bytes(),
                )
                self.assertFalse((trial_root / "generation").exists())
                layout = ArtifactStore(trial_root).for_triplet(FT_ID)
                layout.pipeline_result.parent.mkdir(parents=True)
                failed = len(roots) == 2
                layout.pipeline_result.write_text(json.dumps({
                    "success": not failed,
                    "failure_reason": "plan rejected" if failed else None,
                }), encoding="utf-8")
                if not failed:
                    layout.harness.parent.mkdir(parents=True)
                    layout.harness.write_text(
                        "int LLVMFuzzerTestOneInput(const unsigned char *data, "
                        "unsigned long size) { return 0; }\n", encoding="utf-8"
                    )
                return 1 if failed else 0

            def measure(spec, _source, _target, config, *, root, corpus, seed):
                self.assertTrue(corpus.is_dir())
                self.assertEqual(config.runs, 20_000)
                value = (
                    70 if spec.name == "reference"
                    else (30 if spec.name == "generation_001" else 50)
                ) + (seed - 1)
                return {
                    "scope": TARGET_LAYER, "arm": spec.name, "seed": seed,
                    "seed_recorded": seed, "status": "passed", "runs": 20_000,
                    "totals": {
                        metric: {"percent": value}
                        for metric in ("lines", "regions", "branches")
                    },
                }

            with patch("harness_generation.generation_variance.generation_main",
                       side_effect=generate), patch(
                "harness_generation.generation_variance.measure_target_arm",
                side_effect=measure,
            ):
                document = run_campaign(
                    template=template, ft_id=FT_ID,
                    project_root=ROOT / "benchmarks" / "mini_parser",
                    manifest=load_manifest(DEFAULT_MANIFEST),
                    output=root / "campaign", trials=3,
                    config=CoverageArmsConfig(seeds=(1, 2)),
                    llm_factory=client_factory,
                )

            self.assertEqual(len(clients), 3)
            self.assertEqual(len(set(roots)), 3)
            self.assertEqual(document["status"], "incomplete")
            self.assertEqual(
                [item["generation_status"] for item in document["generations"]],
                ["published", "failed", "published"],
            )
            row = document["summary"]["branches"]
            self.assertEqual(row["requested_generations"], 3)
            self.assertEqual(row["measured_generations"], 2)
            self.assertEqual(row["between_generation_sample_variance"], 200)
            self.assertEqual(row["within_generation_sample_variance"], 0.5)
            self.assertIn("2/3", render_report(document))
            self.assertTrue((root / "campaign" / "report.md").is_file())
            recorded = json.loads(
                (root / "campaign" / "measurements.json").read_text()
            )
            self.assertEqual(
                (root / "campaign" / "report.md").read_text(),
                render_report(recorded),
            )

    def test_requires_three_independent_generations(self):
        with self.assertRaisesRegex(ValueError, "at least three"):
            run_campaign(
                template=Path("unused"), ft_id="ft_trial",
                project_root=Path("unused"),
                manifest=load_manifest(DEFAULT_MANIFEST),
                output=Path("unused"), trials=2,
            )

    def test_duplicate_seed_cannot_replace_a_missing_seed(self):
        document = json.loads((RECORDED / "measurements.json").read_text())
        tampered = deepcopy(document)
        runs = tampered["generations"][0]["coverage_runs"]
        runs[1] = deepcopy(runs[0])
        row = summarize(tampered)["branches"]
        self.assertEqual(row["measured_generations"], 2)
        self.assertFalse(row["per_generation"][0]["complete"])

    def test_missing_provider_configuration_creates_no_campaign(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "template"
            template.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copyfile(ROOT / "artifacts" / "simple" / name,
                                template / name)
            (template / "protocol_ir.json").write_text("{}", encoding="utf-8")
            output = root / "campaign"
            with patch("harness_generation.generation_variance.resolve_llm",
                       side_effect=ValueError("missing LLM configuration")):
                with self.assertRaisesRegex(ValueError, "missing LLM"):
                    run_campaign(
                        template=template, ft_id=FT_ID,
                        project_root=ROOT / "benchmarks" / "mini_parser",
                        manifest=load_manifest(DEFAULT_MANIFEST),
                        output=output,
                    )
            self.assertFalse(output.exists())


class RecordedGenerationEvidenceTests(unittest.TestCase):
    def test_recorded_inputs_harnesses_statistics_and_report_agree(self):
        document = json.loads((RECORDED / "measurements.json").read_text())
        manifest = load_manifest(DEFAULT_MANIFEST)
        pinned = _input_digests(
            RECORDED / "template", manifest, RECORDED / "project"
        )

        for key, value in pinned.items():
            self.assertEqual(document["inputs"][key], value, key)
        self.assertEqual(document["requested_generations"], 3)
        self.assertTrue(document["reference_complete"])
        self.assertEqual(document["status"], "complete")
        self.assertEqual(document["summary"], summarize(document))

        hashes = []
        response_ids = []
        for trial, entry in enumerate(document["generations"], 1):
            self.assertEqual(entry["trial"], trial)
            self.assertEqual(entry["generation_status"], "published")
            harness = RECORDED / "harnesses" / f"generation_{trial:03d}.c"
            self.assertEqual(digest(harness), entry["harness_sha256"])
            hashes.append(entry["harness_sha256"])
            response_ids.extend(entry["plan_response_ids"])
            self.assertEqual(len(entry["coverage_runs"]), 3)
            for seed, run in zip((1, 2, 3), entry["coverage_runs"]):
                self.assertEqual(run["seed"], seed)
                self.assertEqual(run["seed_recorded"], seed)
                self.assertEqual(run["runs"], 20_000)
                self.assertEqual(run["status"], "passed")
                self.assertEqual(run["scope"], TARGET_LAYER)
        self.assertEqual(len(set(hashes)), 3)
        self.assertEqual(len(response_ids), 4)
        self.assertEqual(len(set(response_ids)), 4)
        self.assertEqual(
            [entry["stage4_attempts"] for entry in document["generations"]],
            [1, 2, 1],
        )
        self.assertEqual(
            (ROOT / "docs" / "GENERATION_VARIANCE.md").read_text(),
            render_report(document),
        )


if __name__ == "__main__":
    unittest.main()
