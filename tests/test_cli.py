from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tapio_build_tools.cli import main


class CliTests(unittest.TestCase):
    def test_invalid_config_returns_failure_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build-tooling.toml").write_text("schema-version = 99\n", encoding="utf-8")
            stderr = StringIO()
            with redirect_stderr(stderr):
                result = main(["--project", str(root), "config", "validate"])
            self.assertEqual(result, 2)
            self.assertIn("unsupported schema-version", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    @patch("tapio_build_tools.cli.audit_node")
    def test_dispatches_node_audit(self, audit_node) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text("{}\n", encoding="utf-8")
            (root / "package-lock.json").write_text("{}\n", encoding="utf-8")
            (root / "build-tooling.toml").write_text(
                """schema-version = 1
[organization]
name = "Tapio"
[products.demo]
name = "Demo"
[ecosystems.node]
version = "24"
package = "package.json"
lock = "package-lock.json"
""",
                encoding="utf-8",
            )
            self.assertEqual(main(["--project", str(root), "node", "audit"]), 0)
            audit_node.assert_called_once()


if __name__ == "__main__":
    unittest.main()
