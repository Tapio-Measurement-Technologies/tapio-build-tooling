from contextlib import redirect_stdout
from datetime import date
from io import StringIO
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tapio_build_tools.config import load_config
from tapio_build_tools.ecosystems.python.audit import AuditError, audit
from tests.audit_support import dependency, pip_audit


CONFIG = f"""schema-version = 1
[organization]
name = "Tapio"
[products.demo]
name = "Demo"
[ecosystems.python]
version = "{sys.version_info.major}.{sys.version_info.minor}"
[[ecosystems.python.requirements]]
name = "runtime"
lock = "requirements.txt"
"""

SETUPTOOLS = dependency(
    "setuptools", "79.0.1",
    ("PYSEC-2026-3447", ["CVE-2026-1001"], ["80.0.0"]),
    ("GHSA-h35f-9h28-mq5c", ["CVE-2026-1002"], ["80.1.0"]),
)

ACCEPT_SETUPTOOLS = """
[[ecosystems.python.accepted-risks]]
id = "PYSEC-2026-3447"
package = "setuptools"
reason = "Held below 80 by zappa; build-time only, see R-08."
review-by = 2027-01-31

[[ecosystems.python.accepted-risks]]
id = "CVE-2026-1002"
package = "Setuptools"
reason = "The same hold, the second advisory."
review-by = "2027-01-31"
"""

TODAY = date(2026, 11, 12)


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "requirements.txt").write_text("setuptools==79.0.1\n", encoding="utf-8")
        environment = patch.dict(os.environ, {"GITHUB_ACTIONS": ""})
        environment.start()
        self.addCleanup(environment.stop)

    def config(self, extra: str = ""):
        (self.root / "build-tooling.toml").write_text(CONFIG + extra, encoding="utf-8")
        return load_config(self.root)

    def run_audit(self, run, extra: str = "", *, today: date = TODAY) -> str:
        stdout = StringIO()
        with patch("tapio_build_tools.ecosystems.python.audit.subprocess.run", side_effect=run), \
                redirect_stdout(stdout):
            try:
                audit(self.config(extra), "runtime", today=today)
            finally:
                self.output = stdout.getvalue()
        return self.output

    def test_audits_exact_lock_strictly_for_a_json_report(self) -> None:
        calls = []
        self.run_audit(pip_audit(dependency("setuptools", "79.0.1"), calls=calls))
        [command] = calls
        for option in ["--no-deps", "--disable-pip", "--strict"]:
            self.assertIn(option, command)
        self.assertEqual(command[command.index("--format") + 1], "json")
        self.assertEqual(command[command.index("--aliases") + 1], "on")
        self.assertIn(str(self.root / "requirements.txt"), command)
        self.assertNotIn("--ignore-vuln", command)

    def test_a_vulnerability_nobody_accepted_fails_the_audit(self) -> None:
        with self.assertRaisesRegex(AuditError, "setuptools 79.0.1 PYSEC-2026-3447 is not accepted"):
            self.run_audit(pip_audit(SETUPTOOLS))
        self.assertIn("vulnerable: setuptools 79.0.1 PYSEC-2026-3447 (CVE-2026-1001): fixed in 80.0.0",
                      self.output)

    def test_accepted_by_id_or_by_alias_passes_and_says_so(self) -> None:
        output = self.run_audit(pip_audit(SETUPTOOLS), ACCEPT_SETUPTOOLS)
        self.assertIn("accepted: setuptools 79.0.1 PYSEC-2026-3447", output)
        self.assertIn("ecosystems.python.accepted-risks[0], review by 2027-01-31: Held below 80",
                      output)
        self.assertIn("accepted: setuptools 79.0.1 GHSA-h35f-9h28-mq5c (CVE-2026-1002)", output)
        self.assertIn("2 finding(s), 2 accepted, 0 not accepted", output)
        self.assertNotIn("warning", output)

    def test_an_entry_accepts_only_the_package_it_names(self) -> None:
        other = dependency("wheel", "0.40.0", ("PYSEC-2026-3447", [], ["0.41.0"]))
        with self.assertRaisesRegex(AuditError, "wheel 0.40.0 PYSEC-2026-3447 is not accepted"):
            self.run_audit(pip_audit(SETUPTOOLS, other), ACCEPT_SETUPTOOLS)

    def test_an_entry_applies_through_its_review_by_date_and_not_after(self) -> None:
        self.run_audit(pip_audit(SETUPTOOLS), ACCEPT_SETUPTOOLS, today=date(2027, 1, 31))
        with self.assertRaises(AuditError) as caught:
            self.run_audit(pip_audit(SETUPTOOLS), ACCEPT_SETUPTOOLS, today=date(2027, 2, 1))
        message = str(caught.exception)
        self.assertIn("setuptools 79.0.1 PYSEC-2026-3447 was accepted by "
                      "ecosystems.python.accepted-risks[0] until 2027-01-31, which has passed", message)
        self.assertIn("move review-by, or take the fix", message)
        self.assertIn("no longer accepted: setuptools 79.0.1 PYSEC-2026-3447", self.output)

    def test_an_entry_nothing_matches_is_flagged_for_removal(self) -> None:
        output = self.run_audit(pip_audit(dependency("setuptools", "80.1.0")), ACCEPT_SETUPTOOLS)
        self.assertIn("warning: requirement group 'runtime': ecosystems.python.accepted-risks[0] "
                      "accepts PYSEC-2026-3447 for setuptools, which no finding matches any more; "
                      "remove the entry", output)
        self.assertIn("accepted-risks[1] accepts CVE-2026-1002", output)

    def test_a_stale_entry_is_a_warning_annotation_inside_github_actions(self) -> None:
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            output = self.run_audit(pip_audit(dependency("setuptools", "80.1.0")), ACCEPT_SETUPTOOLS)
        self.assertIn("::warning title=tapio-build::requirement group 'runtime': "
                      "ecosystems.python.accepted-risks[0]", output)

    def test_with_several_groups_an_entry_for_another_groups_package_is_not_stale(self) -> None:
        (self.root / "dev.txt").write_text("pytest==9.0.0\n", encoding="utf-8")
        groups = '\n[[ecosystems.python.requirements]]\nname = "dev"\nlock = "dev.txt"\n'
        (self.root / "build-tooling.toml").write_text(CONFIG + groups + ACCEPT_SETUPTOOLS,
                                                       encoding="utf-8")
        stdout = StringIO()
        run = pip_audit(dependency("pytest", "9.0.0"))
        with patch("tapio_build_tools.ecosystems.python.audit.subprocess.run", side_effect=run), \
                redirect_stdout(stdout):
            audit(load_config(self.root), "dev", today=TODAY)
        self.assertNotIn("warning", stdout.getvalue())

        stdout = StringIO()
        run = pip_audit(dependency("setuptools", "80.1.0"))
        with patch("tapio_build_tools.ecosystems.python.audit.subprocess.run", side_effect=run), \
                redirect_stdout(stdout):
            audit(load_config(self.root), "runtime", today=TODAY)
        self.assertIn("accepts PYSEC-2026-3447 for setuptools, which no finding matches",
                      stdout.getvalue())

    def test_pip_audit_failing_without_a_report_fails_the_audit(self) -> None:
        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 1)

        with self.assertRaisesRegex(AuditError, "pip-audit exited 1 without a report"):
            self.run_audit(run)

    def test_pip_audit_failing_with_an_empty_report_fails_the_audit(self) -> None:
        with self.assertRaisesRegex(AuditError, "exited 1 and reported no vulnerability"):
            self.run_audit(pip_audit(dependency("setuptools", "80.1.0"), returncode=1))


if __name__ == "__main__":
    unittest.main()
