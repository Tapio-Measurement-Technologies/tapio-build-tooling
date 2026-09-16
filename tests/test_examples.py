from pathlib import Path
import os
import re
import unittest

from tapio_build_tools.config import load_config


ROOT = Path(__file__).parents[1]


class ExampleCompatibilityTests(unittest.TestCase):
    def test_examples_validate_against_local_repositories(self) -> None:
        repositories_root = Path(os.environ.get("TAPIO_REPOSITORIES_ROOT", ROOT.parent))
        targets = {
            "tapio-analysis": ("tapio-analysis.toml", "python"),
            "tapio-papeye": ("tapio-papeye.toml", "python"),
            "rqp-configurator": ("rqp-configurator.toml", "node"),
        }
        missing = [name for name in targets if not (repositories_root / name).is_dir()]
        if missing:
            self.skipTest(f"local compatibility repositories unavailable: {', '.join(missing)}")
        for repository, (example, ecosystem) in targets.items():
            with self.subTest(repository=repository):
                config = load_config(repositories_root / repository, ROOT / "examples" / example)
                self.assertIsNotNone(getattr(config, ecosystem))
                if "[downloads]" in (ROOT / "examples" / example).read_text(encoding="utf-8"):
                    self.assertIsNotNone(config.downloads)


    def test_examples_name_nobody_in_particular(self) -> None:
        """The repository is public: contacts in examples are placeholders."""
        for example in (ROOT / "examples").glob("*.toml"):
            with self.subTest(example=example.name):
                text = example.read_text(encoding="utf-8")
                for address in re.findall(r"[\w.-]+@[\w.-]+", text):
                    self.assertTrue(address.endswith("@example.com"), address)


if __name__ == "__main__":
    unittest.main()
