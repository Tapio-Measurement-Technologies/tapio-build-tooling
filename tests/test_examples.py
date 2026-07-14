from pathlib import Path
import os
import unittest

from tapio_build_tools.config import load_config


ROOT = Path(__file__).parents[1]


class ExampleCompatibilityTests(unittest.TestCase):
    def test_examples_validate_against_local_repositories(self) -> None:
        repositories_root = Path(os.environ.get("TAPIO_REPOSITORIES_ROOT", ROOT.parent))
        targets = {
            "tapio-analysis": "tapio-analysis.toml",
        }
        missing = [name for name in targets if not (repositories_root / name).is_dir()]
        if missing:
            self.skipTest(f"local compatibility repositories unavailable: {', '.join(missing)}")
        for repository, example in targets.items():
            with self.subTest(repository=repository):
                config = load_config(repositories_root / repository, ROOT / "examples" / example)
                self.assertTrue(config.python.requirements)


if __name__ == "__main__":
    unittest.main()
