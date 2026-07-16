from pathlib import Path
import re
import unittest


ROOT = Path(__file__).parents[1]


class ActionTests(unittest.TestCase):
    def test_nested_actions_use_full_commit_shas(self) -> None:
        files = [
            ROOT / ".github/workflows/ci.yml",
            ROOT / ".github/workflows/supply-chain.yml",
            ROOT / "actions/python-supply-chain/action.yml",
            ROOT / "actions/python-release-evidence/action.yml",
        ]
        uses = []
        for path in files:
            uses.extend(re.findall(r"uses:\s+([^\s]+)", path.read_text(encoding="utf-8")))
        self.assertTrue(uses)
        for value in uses:
            with self.subTest(value=value):
                self.assertRegex(value, r"^[^@]+@[0-9a-f]{40}$")

    def test_ci_has_least_privilege_permissions(self) -> None:
        for name in ["ci.yml", "supply-chain.yml"]:
            with self.subTest(workflow=name):
                workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
                self.assertIn("permissions:\n  contents: read", workflow)
                self.assertIn("persist-credentials: false", workflow)


if __name__ == "__main__":
    unittest.main()
