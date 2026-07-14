from pathlib import Path
from subprocess import CompletedProcess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tapio_build_tools.config import ConfigError, load_config
from tapio_build_tools.ecosystems.python.requirements import (
    RequirementsError,
    compile_requirements,
)


def config_text(version: str, *, with_input: bool = True) -> str:
    input_line = 'input = "requirements.in"\n' if with_input else ""
    return f"""\
schema-version = 1
[organization]
name = "Tapio"
[products.demo]
name = "Demo"
[ecosystems.python]
version = "{version}"
[[ecosystems.python.requirements]]
name = "runtime"
{input_line}lock = "requirements.txt"
"""


class RequirementsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "requirements.in").write_text("example==1\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text("old\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def config(self, *, with_input: bool = True):
        version = f"{sys.version_info.major}.{sys.version_info.minor}"
        path = self.root / "build-tooling.toml"
        path.write_text(config_text(version, with_input=with_input), encoding="utf-8")
        return load_config(self.root)

    @staticmethod
    def fake_compile(command, **kwargs):
        output = Path(command[command.index("--output-file") + 1])
        if not output.read_text(encoding="utf-8"):
            raise AssertionError("existing lock was not copied to temporary output")
        output.write_text("generated\n", encoding="utf-8")
        return CompletedProcess(command, 0)

    @patch("tapio_build_tools.ecosystems.python.requirements.subprocess.run")
    def test_compiles_atomically_with_expected_flags(self, run) -> None:
        run.side_effect = self.fake_compile
        result = compile_requirements(self.config())
        self.assertEqual((self.root / "requirements.txt").read_text(), "generated\n")
        self.assertEqual(result[0].status, "updated")
        command = run.call_args.args[0]
        self.assertIn("--generate-hashes", command)
        self.assertIn("--annotation-style=split", command)
        self.assertIn("--cache-dir", command)
        self.assertEqual(command[-1], "requirements.in")

    @patch("tapio_build_tools.ecosystems.python.requirements.subprocess.run")
    def test_check_reports_stale_lock_without_replacing_it(self, run) -> None:
        run.side_effect = self.fake_compile
        with self.assertRaisesRegex(RequirementsError, "stale requirement lock"):
            compile_requirements(self.config(), check=True)
        self.assertEqual((self.root / "requirements.txt").read_text(), "old\n")

    @patch("tapio_build_tools.ecosystems.python.requirements.subprocess.run")
    def test_upgrade_flag_is_forwarded(self, run) -> None:
        run.side_effect = self.fake_compile
        compile_requirements(self.config(), upgrade=True)
        self.assertIn("--upgrade", run.call_args.args[0])

    @patch("tapio_build_tools.ecosystems.python.requirements.subprocess.run")
    def test_lock_only_group_is_skipped(self, run) -> None:
        result = compile_requirements(self.config(with_input=False))
        run.assert_not_called()
        self.assertEqual(result[0].status, "skipped (lock-only)")

    def test_rejects_check_with_upgrade(self) -> None:
        with self.assertRaisesRegex(ConfigError, "cannot be combined"):
            compile_requirements(self.config(), check=True, upgrade=True)

    def test_rejects_wrong_python_version(self) -> None:
        (self.root / "build-tooling.toml").write_text(
            config_text("1.2"), encoding="utf-8"
        )
        with self.assertRaisesRegex(RequirementsError, "Python 1.2"):
            compile_requirements(load_config(self.root))


if __name__ == "__main__":
    unittest.main()
