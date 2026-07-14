from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tapio_build_tools.config import load_config
from tapio_build_tools.ecosystems.python.audit import audit


class AuditTests(unittest.TestCase):
    @patch("tapio_build_tools.ecosystems.python.audit.subprocess.run")
    def test_audits_exact_lock_without_dependency_resolution(self, run) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("example==1\n", encoding="utf-8")
            (root / "build-tooling.toml").write_text(
                f"""schema-version = 1
[organization]
name = "Tapio"
[products.demo]
name = "Demo"
[ecosystems.python]
version = "{sys.version_info.major}.{sys.version_info.minor}"
[[ecosystems.python.requirements]]
name = "runtime"
lock = "requirements.txt"
""",
                encoding="utf-8",
            )
            audit(load_config(root), "runtime")
            command = run.call_args.args[0]
            self.assertIn("--no-deps", command)
            self.assertIn("--disable-pip", command)
            self.assertIn(str(root / "requirements.txt"), command)


if __name__ == "__main__":
    unittest.main()

