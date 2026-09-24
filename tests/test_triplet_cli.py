from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from harness_generation.cli import main
from harness_generation.triplet_cli import triplet_statistics


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ARTIFACTS = ROOT / "artifacts" / "simple"
INPUT_FILES = ("functions.json", "annotations.json", "flows.json", "sfg.json")


class TripletCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.artifacts = Path(temporary.name) / "custom-project"
        self.artifacts.mkdir()
        for name in INPUT_FILES:
            shutil.copy2(SOURCE_ARTIFACTS / name, self.artifacts / name)

    def test_module_cli_writes_canonical_output_and_statistics(self):
        completed = subprocess.run(
            [sys.executable, "-m", "harness_generation", "triplets",
             "--artifacts", str(self.artifacts)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = json.loads((self.artifacts / "triplets.json").read_text())
        self.assertEqual(document["schema_version"], 5)
        self.assertEqual(len(document["triplets"]), 1)
        triplet = document["triplets"][0]
        self.assertTrue(triplet["id"].startswith("ft_parser_from_memory_"))
        self.assertEqual(triplet["isf"]["function"], "parser_from_memory")
        self.assertEqual([item["function"] for item in triplet["prfs"]],
                         ["parser_next", "node_process"])
        self.assertEqual([item["function"] for item in triplet["hpfs"]],
                         ["parser_from_memory", "parser_free"])
        self.assertEqual(triplet["structures"], ["Node", "Parser"])
        self.assertEqual(triplet["metadata"]["data_chain"]["structures"],
                         ["Parser", "Node"])
        self.assertTrue(triplet["bypass_semantics"])
        for expected in (
            "Unique functions: 4", "ISF: 1", "PRF: 2", "HPF: 2",
            "Multi-role functions: 1", "FTs: 1",
            "Average functions per FT: 4.00", "Max FT size: 4",
        ):
            self.assertIn(expected, completed.stdout)

    def test_show_prints_roles_flows_structures_and_data_chain(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main([
                "triplets", "--artifacts", str(self.artifacts)
            ]), 0)
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main([
                "triplets", "show", "--artifacts", str(self.artifacts),
                "--id", self._triplet_id(),
            ])
        self.assertEqual(code, 0)
        output = stdout.getvalue()
        for expected in (
            f"Function Triplet: {self._triplet_id()}", "ISF:", "parser_from_memory",
            "PRFs:", "parser_next", "node_process", "HPFs:", "parser_free",
            "Structures:", "Parser", "Edges:",
            "(null) --parser_from_memory [ISF,HPF]--> Parser",
            "Data chain:", "fuzz_input -> Parser -> Node",
            "Bypass semantics:", "fuzzer_input_binding",
        ):
            self.assertIn(expected, output)

    def test_individual_output_is_optional(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main([
                "triplets", "--artifacts", str(self.artifacts), "--individual"
            ]), 0)
        item = self.artifacts / "triplets" / f"{self._triplet_id()}.json"
        self.assertTrue(item.is_file())
        self.assertEqual(json.loads(item.read_text())["triplet"]["id"], self._triplet_id())

    def test_oversized_ft_is_excluded_with_report(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main([
                "triplets", "--artifacts", str(self.artifacts),
                "--max-functions-per-ft", "3",
            ])
        self.assertEqual(code, 0)
        report = json.loads((self.artifacts / "triplet_exclusions.json").read_text())
        self.assertEqual(report["excluded"][0]["function_count"], 4)
        self.assertEqual(report["excluded"][0]["reason"], "too_many_functions")
        self.assertEqual(json.loads((self.artifacts / "triplets.json").read_text())[
            "triplets"
        ], [])

    def test_rank_writes_auditable_budgeted_selection_manifest(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main([
                "triplets", "--artifacts", str(self.artifacts)
            ]), 0)
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main([
                "triplets", "rank", "--artifacts", str(self.artifacts),
                "--max-ft", "1", "--max-calls", "20",
            ])
        self.assertEqual(code, 0)
        document = json.loads(
            (self.artifacts / "ft_selection.json").read_text(encoding="utf-8")
        )
        self.assertEqual(document["schema_version"], 2)
        self.assertEqual(document["policy_version"], "ft-priority-v4")
        self.assertEqual(document["summary"]["selected_count"], 1)
        self.assertEqual(
            document["selection"][0]["triplet_id"], self._triplet_id()
        )
        self.assertEqual(
            {item["name"] for item in document["ranking"][0]["metrics"]},
            {
                "input_evidence", "structural_confidence",
                "structural_opportunity", "harness_readiness", "usage_support",
            },
        )
        self.assertIn("estimated_calls=", stdout.getvalue())

    def test_statistics_count_memberships_and_multi_role_functions(self):
        annotations = (
            {"function_id": "a", "labels": ["ISF", "HPF"]},
            {"function_id": "b", "labels": ["PRF"]},
            {"function_id": "c", "labels": ["PRF", "HPF"]},
        )
        functions = ({"id": "a"}, {"id": "b"}, {"id": "c"})
        stats = triplet_statistics(annotations, functions, ())
        self.assertEqual(stats["unique_functions"], 3)
        self.assertEqual(
            stats["role_memberships"], {"isf": 1, "prf": 2, "hpf": 2}
        )
        self.assertEqual(stats["multi_role_functions"], 2)

    def _triplet_id(self):
        document = json.loads((self.artifacts / "triplets.json").read_text())
        return document["triplets"][0]["id"]

    def test_show_unknown_id_is_nonzero(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main([
                "triplets", "--artifacts", str(self.artifacts)
            ]), 0)
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            code = main([
                "triplets", "show", "--artifacts", str(self.artifacts),
                "--id", "ft_9999",
            ])
        self.assertEqual(code, 1)
        self.assertIn("unknown Function Triplet", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
