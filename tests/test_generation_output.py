import unittest

from harness_generation.generation_output import normalize_c_response


class GeneratedOutputTests(unittest.TestCase):
    def test_removes_only_one_complete_outer_c_fence(self):
        source = "int f(void) { return 0; }"
        self.assertEqual(normalize_c_response(f"```c\n{source}\n```"), source)
        self.assertEqual(normalize_c_response(f"```cpp\n{source}\n```"), source)
        self.assertEqual(normalize_c_response(f"```c++\n{source}\n```"), source)
        self.assertEqual(normalize_c_response(f"```\n{source}\n```"), source)

    def test_does_not_hide_prose_or_nested_fences(self):
        with_prose = "Here is C:\n```c\nint f(void) { return 0; }\n```"
        nested = "```c\n```c\nint f(void) { return 0; }\n```\n```"
        self.assertEqual(normalize_c_response(with_prose), with_prose)
        self.assertEqual(normalize_c_response(nested), nested)

    def test_drops_a_trailing_echoed_transport_delimiter(self):
        source = "int f(void) { return 0; }"
        for tag in (
            "</stdin>", "<stdout>", "</answer>", "</code>",
            "</｜｜DSML｜｜ parameter>", "</stddef.h></stdint.h>",
        ):
            with self.subTest(tag=tag):
                self.assertEqual(
                    normalize_c_response(f"{source}\n{tag}"), source
                )
                self.assertEqual(
                    normalize_c_response(f"```c\n{source}\n```\n{tag}"), source
                )

    def test_keeps_a_tag_that_is_not_a_trailing_delimiter(self):
        source = "int f(void) { return 0; }\n</stdin>\nint g(void) { return 1; }"
        self.assertEqual(normalize_c_response(source), source)
        self.assertEqual(normalize_c_response("</stdin>"), "</stdin>")


if __name__ == "__main__":
    unittest.main()
