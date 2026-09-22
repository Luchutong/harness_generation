import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.triplet import (FunctionTriplet, TripletBypassSemantic,
    TripletEdge, TripletFunction, TripletOwnershipRelation, load_triplets_json,
    stable_triplet_id, triplets_document, write_triplets_json)


def function(function_id, name, roles, line):
    return TripletFunction(function_id, name, roles, "src/parser.c", line)


class FunctionTripletSerializationTests(unittest.TestCase):
    def setUp(self):
        self.isf = function("src/parser.c:3:parse", "parse", ("HPF", "ISF"), 3)
        self.prf = function("src/parser.c:13:process", "process", ("HPF", "PRF"), 13)
        self.hpf = function("src/parser.c:25:destroy", "destroy", ("HPF",), 25)
        self.parse_edge = TripletEdge(
            self.isf.function_id, self.isf.function, "(null)", "Context",
            self.isf.roles, self.isf.file, self.isf.line,
        )
        self.process_edge = TripletEdge(
            self.prf.function_id, self.prf.function, "Context", "Result",
            self.prf.roles, self.prf.file, self.prf.line, True,
            "engineering choice, not specified by SynapseFlow Phase 1",
        )
        self.destroy_edge = TripletEdge(
            self.hpf.function_id, self.hpf.function, "Context", "(null)",
            self.hpf.roles, self.hpf.file, self.hpf.line,
        )
        self.semantic = TripletBypassSemantic(
            "bs_scalar_parameter_0001",
            "scalar_parameter",
            self.isf.function_id,
            self.isf.function,
            "parse has scalar parameter size.",
            ("parameter: unsigned long size",),
            {"parameter": "size", "type": "unsigned long"},
        )

    def make_triplet(self, *, reverse=False):
        functions = (self.isf, self.prf, self.hpf)
        structures = ("Context", "Result")
        edges = (self.parse_edge, self.process_edge, self.destroy_edge)
        if reverse:
            functions = tuple(reversed(functions))
            structures = tuple(reversed(structures))
            edges = tuple(reversed(edges))
        return FunctionTriplet(
            self.isf,
            (self.prf,),
            (self.hpf,),
            functions,
            structures,
            edges,
            {"source_schema_versions": {"sfg": 1, "functions": 1}, "anchor": "parse"},
            bypass_semantics=(self.semantic,),
        )

    def test_required_fields_retain_function_and_structural_metadata(self):
        triplet = self.make_triplet()
        value = triplet.to_dict()
        self.assertEqual(
            set(value),
            {
                "id", "isf", "prfs", "hpfs", "functions", "structures",
                "edges", "bypass_semantics", "ownership_relations", "metadata",
            },
        )
        self.assertEqual(value["isf"]["function_id"], self.isf.function_id)
        self.assertEqual(value["isf"]["roles"], ["ISF", "HPF"])
        self.assertEqual(value["prfs"][0]["roles"], ["PRF", "HPF"])
        self.assertEqual(
            set(value["edges"][0]),
            {"function_id", "function", "src", "dst", "roles", "file", "line",
             "inferred", "inference_reason"},
        )
        self.assertEqual(value["bypass_semantics"][0]["kind"], "scalar_parameter")
        self.assertEqual(
            set(value["bypass_semantics"][0]),
            {
                "id", "kind", "function_id", "function", "summary",
                "evidence", "metadata",
            },
        )

    def test_id_and_serialized_bytes_are_stable_across_input_order(self):
        first = self.make_triplet()
        second = self.make_triplet(reverse=True)
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.id, stable_triplet_id(self.isf.function_id))
        self.assertEqual(first.to_dict(), second.to_dict())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_path = write_triplets_json((first,), root / "first.json")
            second_path = write_triplets_json((second,), root / "second.json")
            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            document = json.loads(first_path.read_text(encoding="utf-8"))
        self.assertEqual(document, triplets_document((first,)))
        self.assertEqual(document["schema_version"], 4)

    def test_zero_prfs_and_hpfs_are_valid(self):
        triplet = FunctionTriplet(
            self.isf, (), (), (self.isf,), ("Context",), (self.parse_edge,), {}
        )
        self.assertEqual(triplet.prfs, ())
        self.assertEqual(triplet.hpfs, ())

    def test_multiple_owned_producers_may_share_cleanup_function(self):
        alternate = function("src/parser.c:30:parse_alt", "parse_alt", ("PRF",), 30)
        first = TripletOwnershipRelation(
            "own_1",
            self.isf.function_id,
            self.isf.function,
            "Context",
            self.hpf.function_id,
            self.hpf.function,
            evidence=("parse returns owned Context",),
        )
        second = TripletOwnershipRelation(
            "own_2",
            alternate.function_id,
            alternate.function,
            "Context",
            self.hpf.function_id,
            self.hpf.function,
            evidence=("parse_alt returns owned Context",),
        )
        triplet = FunctionTriplet(
            self.isf,
            (alternate,),
            (self.hpf,),
            (self.isf, alternate, self.hpf),
            ("Context",),
            (self.parse_edge, self.destroy_edge),
            {},
            ownership_relations=(second, first),
        )
        self.assertEqual(
            [relation.cleanup_function for relation in triplet.ownership_relations],
            ["destroy", "destroy"],
        )

    def test_schema_v1_triplets_remain_loadable(self):
        document = triplets_document((self.make_triplet(),))
        document["schema_version"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy-triplets.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded = load_triplets_json(path)
        expected = dict(document["triplets"][0])
        expected.setdefault("bypass_semantics", [])
        self.assertEqual(loaded[0].to_dict(), expected)

    def test_schema_v2_without_bypass_semantics_remains_loadable(self):
        document = triplets_document((self.make_triplet(),))
        document["schema_version"] = 2
        document["triplets"][0].pop("bypass_semantics")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy-v2-triplets.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded = load_triplets_json(path)

        self.assertEqual(loaded[0].bypass_semantics, ())
        self.assertEqual(loaded[0].to_dict()["bypass_semantics"], [])

    def test_role_and_reference_invariants_are_checked(self):
        not_isf = function("src/parser.c:4:not_isf", "not_isf", ("PRF",), 4)
        with self.assertRaises(ValueError):
            FunctionTriplet(not_isf, (), (), (not_isf,), (), (), {})
        with self.assertRaises(ValueError):
            FunctionTriplet(self.isf, (self.prf,), (), (self.isf,), (), (), {})
        with self.assertRaises(ValueError):
            FunctionTriplet(
                self.isf, (), (), (self.isf,), (), (), {},
                bypass_semantics=(TripletBypassSemantic(
                    "bs_bad_0001", "scalar_parameter", self.prf.function_id,
                    self.prf.function, "bad", (), {},
                ),),
            )


if __name__ == "__main__":
    unittest.main()
