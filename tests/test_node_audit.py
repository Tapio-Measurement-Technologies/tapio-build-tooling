from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tapio_build_tools.config import load_config
from tapio_build_tools.ecosystems.node.audit import AuditError, audit


CONFIG = """schema-version = 1
[organization]
name = "Tapio"
[products.demo]
name = "Demo"
[ecosystems.node]
version = "24"
package = "package.json"
lock = "package-lock.json"
"""


class NodeAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
        (self.root / "package-lock.json").write_text(
            '{"name":"demo","lockfileVersion":3}\n', encoding="utf-8"
        )
        (self.root / "build-tooling.toml").write_text(CONFIG, encoding="utf-8")
        self.config = load_config(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @patch("tapio_build_tools.ecosystems.node.audit.subprocess.run")
    def test_audits_complete_lock_without_severity_filter(self, run) -> None:
        audit(self.config)
        self.assertEqual(run.call_args.args[0], ["npm", "audit", "--package-lock-only"])
        self.assertEqual(run.call_args.kwargs["cwd"], self.root)
        self.assertTrue(run.call_args.kwargs["check"])

    @patch("tapio_build_tools.ecosystems.node.audit.subprocess.run")
    def test_wraps_failed_audit(self, run) -> None:
        run.side_effect = subprocess.CalledProcessError(1, ["npm", "audit"])
        with self.assertRaisesRegex(AuditError, "npm audit failed"):
            audit(self.config)


if __name__ == "__main__":
    unittest.main()
