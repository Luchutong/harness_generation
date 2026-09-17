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


if __name__ == "__main__":
    unittest.main()
