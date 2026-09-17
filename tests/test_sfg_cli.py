from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sfg_builder.cli import main


PROJECT = Path(__file__).parent / "fixtures/simple_project"
EXPECTED_ARTIFACTS = {
    "functions.json",
    "candidates.json",
    "annotations.json",
    "flows.json",
    "sfg.json",
    "sfg.dot",
}


class SFGCLITests(unittest.TestCase):
    def test_python_module_cli_writes_all_artifacts_and_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts" / "sfg"
            completed = subprocess.run(
                [sys.executable, "-m", "sfg_builder", "--project", str(PROJECT),
                 "--output", str(output)],
                cwd=Path(__file__).parents[1], capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual({path.name for path in output.iterdir()}, EXPECTED_ARTIFACTS)
            graph = json.loads((output / "sfg.json").read_text())
            dot = (output / "sfg.dot").read_text()

        self.assertIn("Parsed functions: 4", completed.stdout)
        self.assertIn("Struct types: 2", completed.stdout)
        for heading in ("ISF:", "PRF:", "HPF:", "SFG:"):
            self.assertIn(heading, completed.stdout)
        self.assertIn("(null) --parser_from_memory--> Parser", completed.stdout)
        self.assertEqual(len(graph["edges"]), 4)
        self.assertTrue(dot.startswith("digraph SFG {"))
        self.assertIn('label="parser_from_memory [ISF,HPF]"', dot)
        self.assertIn('label="parser_next [PRF]"', dot)

    @patch("sfg_builder.cli.shutil.which", return_value=None)
    def test_render_without_graphviz_is_nonfatal(self, _which):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "sfg"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(["--project", str(PROJECT), "--output", str(output), "--render"])
            self.assertEqual(code, 0)
            self.assertEqual({path.name for path in output.iterdir()}, EXPECTED_ARTIFACTS)
            self.assertFalse((output / "sfg.svg").exists())
        self.assertIn("Parsed functions: 4", stdout.getvalue())
        self.assertIn("Graphviz 'dot' is unavailable", stderr.getvalue())

    @patch("sfg_builder.cli.shutil.which", return_value="/usr/bin/dot")
    @patch("sfg_builder.cli.subprocess.run")
    def test_render_invokes_graphviz_and_creates_svg(self, run, _which):
        def render(command, *, cwd, **_kwargs):
            (Path(cwd) / "sfg.svg").write_text("<svg/>\n")
            return subprocess.CompletedProcess(command, 0, "", "")

        run.side_effect = render
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "sfg"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = main(["--project", str(PROJECT), "--output", str(output), "--render"])
            self.assertEqual(code, 0)
            self.assertTrue((output / "sfg.svg").exists())
        run.assert_called_once_with(
            ["/usr/bin/dot", "-Tsvg", "sfg.dot", "-o", "sfg.svg"], cwd=output,
            capture_output=True, text=True, timeout=30,
        )


if __name__ == "__main__":
    unittest.main()
