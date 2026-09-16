from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tapio_build_tools.cli import main
from tests.downloads_support import write_project


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


    @patch("tapio_build_tools.cli.publish_downloads")
    def test_dispatches_downloads_publish(self, publish_downloads) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_project(root)
            publish_downloads.return_value = SimpleNamespace(version="v1.2.0", programs={})
            with redirect_stdout(StringIO()):
                result = main([
                    "--project", str(root), "downloads", "publish", "--version", "v1.2.0",
                    "--bucket", "bucket", "--base-url", "https://example.invalid",
                    "--output-dir", str(root / "site"), "--program", "demo", "--dry-run", "--aws-region", "eu-north-1",
                ])
            self.assertEqual(result, 0)
            options = publish_downloads.call_args.kwargs
            self.assertEqual(options["version"], "v1.2.0")
            self.assertEqual(options["programs"], ["demo"])
            self.assertTrue(options["dry_run"])
            self.assertEqual(options["aws_region"], "eu-north-1")

    def test_a_prerelease_fails_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_project(root)
            stderr = StringIO()
            with redirect_stderr(stderr):
                result = main([
                    "--project", str(root), "downloads", "publish", "--version", "v1.2.0-beta.1",
                    "--bucket", "bucket", "--base-url", "https://example.invalid", "--dry-run",
                    "--existing-manifest", "/dev/null", "--output-dir", str(root / "site"),
                ])
            self.assertEqual(result, 2)
            self.assertIn("is a pre-release; not published", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
