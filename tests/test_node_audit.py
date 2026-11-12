from contextlib import redirect_stdout
from datetime import date
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tapio_build_tools.config import load_config
from tapio_build_tools.ecosystems.node.audit import AuditError, audit
from tests.audit_support import npm_audit, npm_report


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

ACCEPT_DEEPMERGE = """
[[ecosystems.node.accepted-risks]]
id = "GHSA-gcqx-w48m-w2h4"
package = "deepmerge"
reason = "Pulled in by react-data-table-component 7.x; merges only our own column config."
review-by = 2027-03-31
"""

LOCK = {
    "name": "demo",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "demo"},
        "node_modules/deepmerge": {"version": "4.2.2"},
        "node_modules/react-data-table-component": {"version": "7.6.2"},
        "node_modules/left-pad": {"version": "1.3.0"},
    },
}

TODAY = date(2026, 11, 12)

# PapEye's two low findings: deepmerge's advisory, and the table component
# that is vulnerable only because it depends on deepmerge.
PAPEYE = npm_report(("deepmerge", "GHSA-gcqx-w48m-w2h4", "low"),
                    effects={"react-data-table-component": ["deepmerge"]})


class NodeAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
        (self.root / "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")
        environment = patch.dict(os.environ, {"GITHUB_ACTIONS": ""})
        environment.start()
        self.addCleanup(environment.stop)

    def run_audit(self, run, extra: str = "", *, today: date = TODAY) -> str:
        (self.root / "build-tooling.toml").write_text(CONFIG + extra, encoding="utf-8")
        stdout = StringIO()
        with patch("tapio_build_tools.ecosystems.node.audit.subprocess.run", side_effect=run), \
                redirect_stdout(stdout):
            try:
                audit(load_config(self.root), today=today)
            finally:
                self.output = stdout.getvalue()
        return self.output

    def test_audits_the_complete_lock_for_a_json_report(self) -> None:
        calls = []
        self.run_audit(npm_audit(npm_report(), calls=calls))
        [(command, kwargs)] = calls
        self.assertEqual(command, ["npm", "audit", "--package-lock-only", "--json"])
        self.assertEqual(kwargs["cwd"], self.root)
        self.assertNotIn("--audit-level", " ".join(command))

    def test_any_advisory_nobody_accepted_fails_whatever_its_severity(self) -> None:
        with self.assertRaisesRegex(AuditError, "deepmerge 4.2.2 GHSA-gcqx-w48m-w2h4 is not accepted"):
            self.run_audit(npm_audit(PAPEYE))
        self.assertIn("vulnerable: deepmerge 4.2.2 GHSA-gcqx-w48m-w2h4: low", self.output)

    def test_accepting_an_advisory_accepts_what_is_vulnerable_only_through_it(self) -> None:
        output = self.run_audit(npm_audit(PAPEYE), ACCEPT_DEEPMERGE)
        self.assertIn("accepted: deepmerge 4.2.2 GHSA-gcqx-w48m-w2h4: low", output)
        self.assertIn("ecosystems.node.accepted-risks[0], review by 2027-03-31: Pulled in", output)
        self.assertIn("1 finding(s), 1 accepted, 0 not accepted", output)

    def test_another_advisory_still_fails(self) -> None:
        report = npm_report(("deepmerge", "GHSA-gcqx-w48m-w2h4", "low"),
                            ("left-pad", "GHSA-2222-3333-4444", "high"))
        with self.assertRaisesRegex(AuditError, "left-pad 1.3.0 GHSA-2222-3333-4444 is not accepted"):
            self.run_audit(npm_audit(report), ACCEPT_DEEPMERGE)

    def test_an_expired_acceptance_fails_and_says_why(self) -> None:
        with self.assertRaisesRegex(AuditError, "until 2027-03-31, which has passed"):
            self.run_audit(npm_audit(PAPEYE), ACCEPT_DEEPMERGE, today=date(2027, 4, 1))

    def test_an_acceptance_nothing_matches_is_flagged(self) -> None:
        output = self.run_audit(npm_audit(npm_report()), ACCEPT_DEEPMERGE)
        self.assertIn("warning: package-lock.json: ecosystems.node.accepted-risks[0] accepts "
                      "GHSA-gcqx-w48m-w2h4 for deepmerge, which no finding matches any more", output)

    def test_an_advisory_without_a_github_id_cannot_be_accepted(self) -> None:
        report = npm_report(("left-pad", "GHSA-2222-3333-4444", "high"))
        report["vulnerabilities"]["left-pad"]["via"][0]["url"] = "https://npmjs.com/advisories/118"
        with self.assertRaisesRegex(AuditError, "https://npmjs.com/advisories/118 is not accepted"):
            self.run_audit(npm_audit(report))

    def test_an_npm_error_report_fails_the_audit(self) -> None:
        report = {"error": {"code": "ENOLOCK", "summary": "This command requires an existing lockfile."}}
        with self.assertRaisesRegex(AuditError, "requires an existing lockfile"):
            self.run_audit(npm_audit(report, returncode=1))

    def test_output_that_is_not_json_fails_the_audit(self) -> None:
        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, stdout="npm ERR! network")

        with self.assertRaisesRegex(AuditError, "exited 1 without a JSON report"):
            self.run_audit(run)

    def test_npm_missing_fails_the_audit(self) -> None:
        with self.assertRaisesRegex(AuditError, "npm audit failed"):
            self.run_audit(OSError("npm"))


if __name__ == "__main__":
    unittest.main()
