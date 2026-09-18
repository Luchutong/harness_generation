"""The coverage-equivalence measurement, checked against its own evidence.

``docs/PROTOCOL_FORMAT_MINING.md`` §5.3 asks whether a spec-driven generic
harness reaches the hand-written reference's coverage.  The answer is a
measurement, not an assertion, so it cannot be a pass/fail test: what these
tests do instead is hold the committed evidence to the claims the report makes
about it.  Every one of them runs offline -- no compiler, no LLVM, no LLM --
because the arms and the measurements are committed.

The load-bearing ones are the negatives.  A digest that no longer matches its
arm, a verdict recomputed into something else, a refused attempt quietly
becoming the gate's subject, a budget that is not the same for every arm:
each of those turns the report into a claim about something nobody measured.
"""

import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.coverage_arms import (
    CANDIDATE_ROLES,
    DEFAULT_MANIFEST,
    DEFAULT_REPORT,
    ENGINE_LAYER,
    GATE_METRICS,
    ROLE_REJECTED,
    TARGET_LAYER,
    ArmSpec,
    CoverageArmsConfig,
    CoverageArmsError,
    check_measurements,
    evaluate_gate,
    load_manifest,
    percent_range,
    rejected_arm,
    render_report,
    seed_spread,
    verify_manifest,
)
from harness_generation.llm import MockLLM
from harness_generation.stage4 import Stage4Generator
from tests.test_stage4_protocol_ir import Stage4ProjectTests
from tests.toolchain_probe import (
    LIBFUZZER_AVAILABLE,
    LIBFUZZER_SKIP_REASON,
    LLVM_COVERAGE_AVAILABLE,
    LLVM_COVERAGE_SKIP_REASON,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "coverage_arms"
MEASUREMENTS = FIXTURES / "measurements.json"


#: The FT-only arm as a generator would have handed it over.  The store writes
#: exactly one trailing newline, so the fixture's own is taken back off here.
FT_ONLY_SOURCE = (FIXTURES / "ft_only_published.c").read_text(
    encoding="utf-8"
).removesuffix("\n")


def evidence() -> dict:
    return json.loads(MEASUREMENTS.read_text(encoding="utf-8"))


class CommittedEvidenceTests(unittest.TestCase):
    """Offline.  The manifest, the arms and the measurement must agree."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = load_manifest(DEFAULT_MANIFEST)
        cls.document = evidence()

    def test_every_arm_file_matches_its_pinned_digest(self):
        self.assertEqual(verify_manifest(self.manifest), ())

    def test_a_swapped_arm_is_refused(self):
        """The digest is the only thing tying the bytes to the run.

        These arms were published by a run whose artifacts are gone, so if an
        arm could be swapped silently, the report would describe a file that
        nothing measured.
        """

        document = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        document["arms"][1]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(CoverageArmsError) as raised:
                load_manifest(path)
        self.assertIn("contracted", str(raised.exception))

    def test_the_recipe_is_derived_from_the_source_not_trusted(self):
        """A manifest edit cannot turn a two-TU arm into a single-TU one."""

        document = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        for arm in document["arms"]:
            if arm["name"] != "contracted":
                continue
            arm["recipe"] = "single_tu"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(CoverageArmsError) as raised:
                load_manifest(path)
        self.assertIn("include", str(raised.exception))

    def test_the_arms_are_measured_with_the_flags_the_evidence_records(self):
        """The recipe has to be in the evidence, or the numbers have no context."""

        recipe = self.document["config"]["recipe"]
        self.assertIn("-fsanitize=fuzzer-no-link", recipe["target_coverage"]["target"])
        self.assertIn("-fsanitize=fuzzer-no-link", recipe["target_coverage"]["harness"])
        self.assertIn("-x", recipe["target_coverage"]["harness"])
        self.assertIn("-fsanitize=fuzzer,address,undefined",
                      recipe["engine_sanitized"]["link"])
        # The coverage layer's whole point: no sanitizer may abort it early.
        for flag in recipe["target_coverage"]["link"]:
            self.assertNotIn("address", flag)
            self.assertNotIn("undefined", flag)

    def test_the_gate_verdict_is_recomputed_not_trusted(self):
        self.assertEqual(evaluate_gate(self.document), self.document["gate"])

    def test_a_rejected_arm_cannot_be_the_gate_subject(self):
        """The negative half: the refusal has to bind on the measurement too."""

        self.assertIn(
            "rejected_attempt_003",
            {arm["name"] for arm in self.document["arms"]},
        )
        verdict = evaluate_gate(self.document, candidate="rejected_attempt_003")
        self.assertFalse(verdict["admissible"])
        self.assertEqual(verdict["verdict"], "not_admissible")
        self.assertNotIn(ROLE_REJECTED, CANDIDATE_ROLES)

    def test_the_refused_arm_is_reported_as_a_diagnostic_not_a_candidate(self):
        refused = rejected_arm(self.document)
        self.assertIsNotNone(refused)
        report = DEFAULT_REPORT.read_text(encoding="utf-8")
        self.assertIn("### The refused attempt", report)
        self.assertIn(refused, report)
        self.assertEqual(
            evaluate_gate(self.document, candidate=refused)["verdict"],
            "not_admissible",
        )

    def test_the_diagnostic_comparison_is_computed_not_asserted(self):
        """The claim about the refused arm follows the data either way.

        It says something a reader would otherwise assume the other way -- that
        the audit is a coverage filter -- so if the numbers ever move it has to
        move with them rather than keep the flattering sentence.
        """

        target = self.document["layers"][TARGET_LAYER]["runs"]
        refused = rejected_arm(self.document)
        published = self.document["gate"]["candidate"]
        report = DEFAULT_REPORT.read_text(encoding="utf-8")
        self.assertEqual(
            "Target coverage does not separate them." in report,
            percent_range(target, refused) == percent_range(target, published),
        )

    def test_percent_range_reads_only_the_arm_it_was_asked_about(self):
        runs = [
            {"arm": "a", "seed": 1, "totals": {"lines": {"percent": 1.0}}},
            {"arm": "a", "seed": 2, "totals": {"lines": {"percent": 3.0}}},
            {"arm": "b", "seed": 1, "totals": {"lines": {"percent": 9.0}}},
        ]
        self.assertEqual(percent_range(runs, "a"), {"lines": (1.0, 3.0)})
        self.assertEqual(percent_range(runs, "missing"), {})

    def test_only_a_published_arm_may_be_the_candidate(self):
        for arm in self.manifest.arms:
            with self.subTest(arm=arm.name):
                self.assertEqual(
                    evaluate_gate(self.document, candidate=arm.name)["admissible"],
                    arm.role in CANDIDATE_ROLES,
                )

    def test_the_budget_is_equal_across_arms_and_seeds(self):
        runs = self.document["config"]["runs"]
        seeds = self.document["config"]["seeds"]
        engine = self.document["layers"][ENGINE_LAYER]["runs"]
        target = self.document["layers"][TARGET_LAYER]["runs"]
        for run in engine:
            self.assertEqual(run["requested_runs"], runs)
        for run in target:
            self.assertEqual(run["runs"], runs)
        names = {arm["name"] for arm in self.document["arms"]}
        for layer in (engine, target):
            self.assertEqual(
                {(run["arm"], run["seed"]) for run in layer},
                {(name, seed) for name in names for seed in seeds},
            )

    def test_the_repeats_are_a_seed_sweep_not_a_repeat(self):
        """Three runs at one seed are one sample three times."""

        seeds = self.document["config"]["seeds"]
        self.assertEqual(len(set(seeds)), len(seeds))
        self.assertGreaterEqual(len(seeds), 2)
        determinism = self.document["determinism"]
        self.assertEqual(determinism["arm"], "reference")
        self.assertIn(determinism["seed"], seeds)
        self.assertTrue(determinism["identical"])
        self.assertEqual(determinism["first"], determinism["repeat"])

    def test_the_seed_spread_claim_matches_the_evidence(self):
        """The report may only say the seeds agree if they actually do.

        Identical per-seed rows are what a saturated budget looks like, and a
        reader who is not told will read them as three confirmations.
        """

        target = self.document["layers"][TARGET_LAYER]["runs"]
        varying = seed_spread(target)
        report = DEFAULT_REPORT.read_text(encoding="utf-8")
        if varying:
            self.assertNotIn("the seeds do not separate the arms", report)
            for name in varying:
                self.assertIn(name, report)
        else:
            self.assertIn("the seeds do not separate the arms", report)

    def test_a_seed_that_moves_is_reported_as_moving(self):
        runs = [
            {"arm": "a", "seed": 1, "totals": {"lines": {"percent": 1.0}}},
            {"arm": "a", "seed": 2, "totals": {"lines": {"percent": 2.0}}},
            {"arm": "b", "seed": 1, "totals": {"lines": {"percent": 1.0}}},
            {"arm": "b", "seed": 2, "totals": {"lines": {"percent": 1.0}}},
        ]
        self.assertEqual(seed_spread(runs), ("a",))

    def test_a_campaign_may_not_run_one_seed_twice(self):
        with self.assertRaises(ValueError):
            CoverageArmsConfig(seeds=(1, 1))
        with self.assertRaises(ValueError):
            CoverageArmsConfig(runs=100, sensitivity_runs=(100,))

    def test_the_layers_are_labelled_and_disjoint(self):
        """cov/ft are the instrumented program; only one layer is target code."""

        engine = self.document["layers"][ENGINE_LAYER]["runs"]
        target = self.document["layers"][TARGET_LAYER]["runs"]
        self.assertEqual({run["scope"] for run in engine}, {ENGINE_LAYER})
        self.assertEqual({run["scope"] for run in target}, {TARGET_LAYER})
        for run in engine:
            self.assertNotIn("totals", run)
        for run in target:
            self.assertNotIn("coverage_edges_or_blocks", run)
            self.assertNotIn("features", run)
            self.assertTrue(run["totals"], run["arm"])
        # The gate reads the target layer only, so a metric it reports has to
        # be one the target layer actually produced.
        for metric in GATE_METRICS:
            self.assertIn(metric, target[0]["totals"])

    def test_a_finding_truncates_the_sanitized_layer_and_says_so(self):
        """The reason cov/ft are telemetry: an arm that crashed stopped early."""

        engine = self.document["layers"][ENGINE_LAYER]["runs"]
        runs = self.document["config"]["runs"]
        for run in engine:
            self.assertEqual(
                run["truncated_by_finding"],
                run["status"] == "finding",
            )
            if run["truncated_by_finding"]:
                self.assertLess(run["executed_units"], runs)
                self.assertTrue(run["findings"])

    def test_the_budget_sensitivity_is_measured_at_other_budgets(self):
        sensitivity = self.document["budget_sensitivity"]
        self.assertTrue(sensitivity)
        budget = self.document["config"]["runs"]
        for recorded, block in sensitivity.items():
            self.assertNotEqual(block["runs"], budget)
            self.assertEqual(int(recorded), block["runs"])
            for run in block["runs_records"]:
                self.assertEqual(run["runs"], block["runs"])
                self.assertEqual(run["scope"], TARGET_LAYER)
            self.assertEqual(
                evaluate_gate(
                    self.document, records=block["runs_records"],
                    budget=block["runs"],
                ),
                block["gate"],
            )

    def test_the_gate_says_which_budget_it_is_about(self):
        self.assertEqual(
            self.document["gate"]["budget"], self.document["config"]["runs"]
        )

    def test_the_recipe_control_bounds_the_recipe_effect(self):
        control = self.document["recipe_control"]
        self.assertEqual(control["pair"], ["pass_through", "ft_only"])
        for metric in GATE_METRICS:
            self.assertEqual(
                len(control["delta_percent"][metric]),
                len(self.document["config"]["seeds"]),
            )

    def test_the_whole_check_passes_against_the_committed_evidence(self):
        self.assertEqual(check_measurements(DEFAULT_MANIFEST, self.document), ())

    def test_the_report_is_rendered_from_the_evidence_and_nothing_else(self):
        """The document is generated, so a hand-edit is drift, not an edit."""

        self.assertEqual(
            DEFAULT_REPORT.read_text(encoding="utf-8"),
            render_report(self.document),
        )

    def test_a_hand_edited_verdict_fails_the_check(self):
        document = evidence()
        document["gate"]["verdict"] = "equivalent_strict"
        problems = check_measurements(DEFAULT_MANIFEST, document)
        self.assertTrue(
            any("gate verdict" in problem for problem in problems), problems
        )

    def test_a_report_that_disagrees_with_the_evidence_fails_the_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.md"
            path.write_text("the arms are equivalent\n", encoding="utf-8")
            problems = check_measurements(
                DEFAULT_MANIFEST, self.document, doc_path=path
            )
        self.assertTrue(any("renders" in problem for problem in problems), problems)

    def test_the_report_carries_the_caveats_it_must(self):
        """Each of these is a way the numbers could be over-read.

        A report that dropped one would not be wrong about the measurement, it
        would be wrong about what the measurement is -- which is worse, because
        nothing else in the document contradicts it.
        """

        report = DEFAULT_REPORT.read_text(encoding="utf-8")
        for claim in (
            "coverage-at-first-crash",          # (a)/(e): the engine layer
            "instrumented_program",             # (a): scope label, not "the target"
            "No sentence here may read",        # (a): the rule stated as a rule
            "bounds the recipe effect",         # (b): the control is a bound
            "seed sweep, not a robustness claim",   # (c)
            "not controlled",                   # (d): FT-only provenance
            "not bug-set equivalence",          # (f)
            "budget-relative",                  # (i)
            "Not that the contract path outperforms",   # (j)
        ):
            with self.subTest(claim=claim):
                self.assertIn(claim, report)


class FtOnlyArmTests(Stage4ProjectTests):
    """The FT-only arm is a product of today's gate, not a refusal.

    The report calls it a "no contract given" baseline, and that reading only
    holds if the same generation path, given no ``protocol_ir.json``, still
    publishes exactly these bytes today -- otherwise the arm is a rejected
    attempt wearing a baseline's label, and the comparison is against the
    wrong thing.
    """

    def test_the_committed_ft_only_arm_publishes_with_no_contract(self):
        root = self.artifact_root("ft_only_arm")
        self.assertFalse((root / "protocol_ir.json").exists())
        llm = MockLLM([self.plan_for(root), FT_ONLY_SOURCE])
        result = Stage4Generator(llm).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )

        published = ArtifactStore(root).for_triplet(self.triplet.id).harness
        self.assertTrue(published.is_file())
        self.assertEqual(
            published.read_text(encoding="utf-8"),
            result.harness_code + "\n",
        )
        # The committed arm and the freshly published one are the same bytes:
        # this is what makes the measured object the pipeline's own output.
        self.assertEqual(
            published.read_bytes(),
            (FIXTURES / "ft_only_published.c").read_bytes(),
        )


class CampaignWiringTests(unittest.TestCase):
    """The campaign itself, at a budget small enough to run in a test.

    This proves the code paths, not the numbers: the recorded measurement is
    the deliverable, and a five-arm, three-seed campaign is far too slow and
    far too dependent on a toolchain to be a test.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def arm(self, name: str) -> ArmSpec:
        manifest = load_manifest(DEFAULT_MANIFEST)
        return manifest.arm(name)

    @unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
    def test_both_recipes_build_and_run_at_a_small_budget(self):
        from harness_generation.coverage_arms import measure_engine_arm

        manifest = load_manifest(DEFAULT_MANIFEST)
        target_source = manifest.root / manifest.target_source["path"]
        corpus = manifest.root / manifest.corpus["path"]
        config = CoverageArmsConfig(
            runs=200, seeds=(1,), seconds_cap=60, determinism_check=False,
        )
        for name in ("reference", "ft_only"):
            with self.subTest(arm=name):
                spec = self.arm(name)
                record = measure_engine_arm(
                    spec, manifest.resolve(spec), target_source, config,
                    root=self.directory, corpus=corpus, seed=1,
                )
                self.assertEqual(record["build_status"], "passed", record)
                self.assertIn(record["status"], {"completed", "finding"})
                self.assertGreater(record["executed_units"], 0)
                # The tracked arms are C and the published ones are C++; both
                # end up compiled as C++, and this is where that shows.
                self.assertIsInstance(record["harness_normalized"], bool)

    @unittest.skipUnless(LLVM_COVERAGE_AVAILABLE, LLVM_COVERAGE_SKIP_REASON)
    def test_the_coverage_layer_measures_every_arm(self):
        from harness_generation.coverage_arms import measure_target_arm

        manifest = load_manifest(DEFAULT_MANIFEST)
        target_source = manifest.root / manifest.target_source["path"]
        corpus = manifest.root / manifest.corpus["path"]
        config = CoverageArmsConfig(
            runs=200, seeds=(3,), seconds_cap=60, determinism_check=False,
        )
        for name in ("reference", "contracted", "ft_only", "pass_through"):
            with self.subTest(arm=name):
                spec = self.arm(name)
                record = measure_target_arm(
                    spec, manifest.resolve(spec), target_source, config,
                    root=self.directory, corpus=corpus, seed=3,
                )
                self.assertEqual(record["status"], "passed", record["errors"])
                self.assertEqual(record["seed_recorded"], 3)
                self.assertEqual(record["runs"], 200)
                self.assertEqual(record["scope"], TARGET_LAYER)
                # Every arm reaches the target's parser entry point, which is
                # the floor: an arm that only links has measured nothing.
                self.assertTrue(record["totals"]["lines"]["covered"] > 0)

    @unittest.skipUnless(LLVM_COVERAGE_AVAILABLE, LLVM_COVERAGE_SKIP_REASON)
    def test_the_harness_compiler_is_what_makes_a_cpp_arm_measurable(self):
        """The gap this driver had to close: the collector compiled C only.

        A generated harness declares ``extern "C"`` and its libFuzzer entry
        point; compiled as C that is a syntax error, and compiled as C++
        without the declaration the link has no entry point.
        """

        from harness_generation.target_build import TargetBuildConfig
        from harness_generation.target_coverage import (
            TargetCoverageCollector,
            TargetCoverageConfig,
        )

        manifest = load_manifest(DEFAULT_MANIFEST)
        spec = self.arm("ft_only")
        work = self.directory / "work"
        work.mkdir()
        (work / "harness.c").write_bytes(manifest.resolve(spec).read_bytes())
        (work / "target.c").write_bytes(
            (manifest.root / manifest.target_source["path"]).read_bytes()
        )
        target = TargetBuildConfig(
            project_root=work,
            source_files=(work / "target.c",),
            header_files=(),
            include_paths=(work,),
            compiler_flags=("-std=c11",),
        )

        without = TargetCoverageCollector(
            TargetCoverageConfig(runs=8)
        ).measure(
            work / "harness.c", target,
            artifacts=work / "without", ft_id="ft_without_cpp",
        )
        self.assertEqual(without.status, "failed")

        with_cpp = TargetCoverageCollector(TargetCoverageConfig(
            runs=8,
            harness_compiler="clang++",
            harness_compiler_flags=(
                "-x", "c++", "-std=c++17", "-g", "-O1", "-fsanitize=fuzzer-no-link",
            ),
        )).measure(
            work / "harness.c", target,
            artifacts=work / "with", ft_id="ft_with_cpp",
        )
        self.assertEqual(with_cpp.status, "passed", with_cpp.errors)
        self.assertEqual(with_cpp.summary["harness_compiler"], "clang++")


if __name__ == "__main__":
    unittest.main()
