from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
