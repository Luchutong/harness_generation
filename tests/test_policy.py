"""The policy sets are written down once, and these tests hold that line.

Two audits refuse a harness for the same reasons: the intermediate validator in
:mod:`harness_generation.validation` and the Stage 4 audit in
:mod:`harness_generation.stage4`.  Each used to carry its own copy of the sets,
and the copies drifted -- the logging set was seven names in one file and two in
the other, so ``puts`` was a refusal in one audit and invisible in the next.

Contents are pinned item by item rather than counted, because a set that can
change silently is the whole problem: widening or narrowing one is a policy
decision, and a policy decision should have to be typed into a test.
"""

import unittest

from harness_generation import policy, stage4, validation


class SingleAuthorityTests(unittest.TestCase):
    """One object, however many modules read it."""

    def test_both_audits_read_the_same_objects(self):
        """A re-added local copy fails here rather than drifting quietly.

        ``is`` and not ``==``: an equal copy is exactly the thing that drifts
        later, and equality would not notice it being introduced.
        """

        for name in (
            "DEFAULT_ALLOWED_FUNCTIONS",
            "FORBIDDEN_IO_FUNCTIONS",
            "FORBIDDEN_LOGGING_FUNCTIONS",
        ):
            with self.subTest(name=name):
                published = getattr(policy, name)
                self.assertIs(getattr(validation, name), published)
                self.assertIs(getattr(stage4, name), published)

    def test_stage4_keeps_no_private_copy_of_the_shared_sets(self):
        """The names the drifted copies lived under are gone, not shadowed."""

        for name in ("_LOGGING_CALLS", "_FILE_IO_CALLS", "_STANDARD_C_CALLS"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(stage4, name))


class PolicyContentTests(unittest.TestCase):
    """What each set contains, spelled out."""

    def test_the_logging_set_is_these_seven(self):
        """The wider of the two drifted copies, and the one that is enforced.

        ``validation`` refused all seven and ``stage4`` refused two; the seven
        is the set that was meant, so it is the one that survived.
        """

        self.assertEqual(policy.FORBIDDEN_LOGGING_FUNCTIONS, frozenset({
            "fprintf", "perror", "printf", "putchar", "puts", "vfprintf",
            "vprintf",
        }))

    def test_the_io_set_is_these_twelve(self):
        self.assertEqual(policy.FORBIDDEN_IO_FUNCTIONS, frozenset({
            "fclose", "fdopen", "fgetpos", "fopen", "fread", "freopen",
            "fseek", "fsetpos", "ftell", "fwrite", "rewind", "tmpfile",
        }))

    def test_the_allowed_set_is_these_sixteen(self):
        self.assertEqual(policy.DEFAULT_ALLOWED_FUNCTIONS, frozenset({
            "abort", "assert", "calloc", "free", "malloc", "memcmp", "memcpy",
            "memmove", "memset", "realloc", "strchr", "strcmp", "strlen",
            "strncmp", "strnlen", "strrchr",
        }))


class PolicyInvariantTests(unittest.TestCase):
    """Properties that hold whatever the sets are."""

    def test_a_call_cannot_be_both_allowed_and_refused(self):
        """Overlap would make the verdict depend on which check ran first."""

        allowed = policy.DEFAULT_ALLOWED_FUNCTIONS
        for name, forbidden in (
            ("logging", policy.FORBIDDEN_LOGGING_FUNCTIONS),
            ("io", policy.FORBIDDEN_IO_FUNCTIONS),
        ):
            with self.subTest(policy=name):
                self.assertEqual(allowed & forbidden, frozenset())

    def test_the_logging_and_io_sets_are_disjoint(self):
        self.assertEqual(
            policy.FORBIDDEN_LOGGING_FUNCTIONS & policy.FORBIDDEN_IO_FUNCTIONS,
            frozenset(),
        )


if __name__ == "__main__":
    unittest.main()
