"""npm lock vulnerability audits.

npm audit has no way to ignore one advisory: its only knob is a severity
floor, which would let every finding below it through unread. So it is run
for its JSON report, each advisory in it is named by its GitHub id, and the
audit fails on any the configuration does not accept - whatever its severity.
"""

from __future__ import annotations

from datetime import date
import json
import re
import subprocess

from tapio_build_tools import risks
from tapio_build_tools.config import Config
from tapio_build_tools.ecosystems.node.semver import satisfies


class AuditError(RuntimeError):
    """npm audit invocation failed."""


# npm names an advisory only by its page on GitHub.
_ADVISORY_URL = re.compile(r"^https://github\.com/advisories/(GHSA(?:-[a-z0-9]{4}){3})$")


def _versions(lock: dict, nodes: list) -> list[str]:
    """The versions the lock installs at *nodes*, the paths npm audit reports."""
    packages = lock.get("packages") if isinstance(lock.get("packages"), dict) else {}
    versions = {
        packages[node]["version"]
        for node in nodes
        if isinstance(packages.get(node), dict) and isinstance(packages[node].get("version"), str)
    }
    return sorted(versions)


def _in_range(installed: list[str], vulnerable: str) -> list[str]:
    """The installed versions the advisory's range covers.

    npm lists every installed copy of a vulnerable package, a patched one
    beside an old one included. A version the range does not cover is left
    out; one that cannot be checked against it is kept, and if that leaves
    nothing, every installed version is - npm did find the package
    vulnerable, so something it installs must be.
    """
    kept = [version for version in installed if satisfies(version, vulnerable) is not False]
    return kept or installed


def findings(report: dict, lock: dict) -> list[risks.Finding]:
    """Every advisory against a locked package in npm audit's JSON report.

    A vulnerable package lists an advisory of its own as an object under
    `via`; a package that is vulnerable only because it depends on one lists
    that package's name instead, and adds no advisory of its own. Accepting
    the advisory accepts both.
    """
    if "error" in report:
        error = report["error"]
        summary = error.get("summary") if isinstance(error, dict) else error
        raise AuditError(f"npm audit failed: {summary}")
    if report.get("auditReportVersion") != 2:
        raise AuditError("npm audit did not write a version 2 report; npm 7 or later is needed")
    vulnerabilities = report.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        raise AuditError("npm audit's report has no vulnerabilities table")
    found: list[risks.Finding] = []
    for name, entry in vulnerabilities.items():
        installed = _versions(lock, entry.get("nodes") or []) or ["(version not in lock)"]
        for via in entry.get("via") or []:
            if not isinstance(via, dict):
                continue
            url = str(via.get("url", ""))
            matched = _ADVISORY_URL.match(url)
            # An advisory npm does not name by GitHub id cannot be accepted by
            # one: it is reported by its URL, and fails like any other.
            advisory = matched.group(1) if matched else (url or f"npm advisory {via.get('source')}")
            for version in _in_range(installed, str(via.get("range") or "*")):
                found.append(risks.Finding(
                    package=str(via.get("name") or name),
                    version=version,
                    id=advisory,
                    ecosystem="node",
                    severity=via.get("severity"),
                ))
    return found


def audit(config: Config, *, today: date | None = None) -> None:
    node = config.require_node()
    command = ["npm", "audit", "--package-lock-only", "--json"]
    try:
        # npm exits 1 for a vulnerability and for a failure alike; the report
        # tells them apart. Its warnings still reach the log on stderr.
        completed = subprocess.run(command, cwd=node.package.parent, stdout=subprocess.PIPE,
                                   text=True)
    except OSError as exc:
        raise AuditError("npm audit failed") from exc
    try:
        report = json.loads(completed.stdout)
    except ValueError as exc:
        raise AuditError(f"npm audit failed: exited {completed.returncode} without a JSON report") from exc
    if not isinstance(report, dict):
        raise AuditError("npm audit failed: its report is not a JSON object")
    try:
        lock = json.loads(node.lock.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise AuditError(f"{node.lock.name} is not valid JSON: {exc}") from exc

    found = findings(report, lock if isinstance(lock, dict) else {})
    if completed.returncode != 0 and not found:
        raise AuditError(f"npm audit failed: exited {completed.returncode} and reported no vulnerability")
    assessment = risks.assess(found, node.accepted_risks, on=today or risks.today())
    risks.report(assessment, subject=node.lock.name)
    if assessment.failed:
        raise AuditError(f"npm audit failed: {assessment.failure()}")
