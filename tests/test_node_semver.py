import unittest

from tapio_build_tools.ecosystems.node.semver import satisfies


class SemverRangeTests(unittest.TestCase):
    def test_comparator_sets_as_github_writes_npm_ranges(self) -> None:
        cases = [
            ("4.2.2", "<4.3.1", True),
            ("4.3.1", "<4.3.1", False),
            ("1.15.5", ">=1.0.0 <1.15.6", True),
            ("0.9.0", ">=1.0.0 <1.15.6", False),
            ("3.0.5", ">=2.0.0 <2.2.2 || >=3.0.0 <3.1.1", True),
            ("2.5.0", ">=2.0.0 <2.2.2 || >=3.0.0 <3.1.1", False),
            ("1.2.3", "<=1.2.3", True),
            ("1.2.4", ">1.2.3", True),
            ("1.2.3", "=1.2.3", True),
            ("1.2.3", "1.2.3", True),
            ("9.9.9", "*", True),
            ("9.9.9", "", True),
        ]
        for version, vulnerable, expected in cases:
            with self.subTest(version=version, range=vulnerable):
                self.assertIs(satisfies(version, vulnerable), expected)

    def test_prereleases_rank_below_their_release(self) -> None:
        self.assertIs(satisfies("2.0.0-beta.2", "<2.0.0"), True)
        self.assertIs(satisfies("2.0.0-beta.10", ">2.0.0-beta.2"), True)
        self.assertIs(satisfies("2.0.0-alpha", "<2.0.0-1"), False)
        self.assertIs(satisfies("2.0.0+build.5", "<=2.0.0"), True)

    def test_what_it_cannot_read_it_does_not_guess(self) -> None:
        for version, vulnerable in [("1.2.3", "^1.0.0"), ("1.2.3", "1.0.0 - 2.0.0"),
                                    ("1.2.3", "<2"), ("latest", "<2.0.0")]:
            with self.subTest(version=version, range=vulnerable):
                self.assertIsNone(satisfies(version, vulnerable))


if __name__ == "__main__":
    unittest.main()
