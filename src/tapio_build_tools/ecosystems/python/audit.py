"""Python lock vulnerability audits."""

from __future__ import annotations

from datetime import date
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from tapio_build_tools import risks
from tapio_build_tools.config import Config
from tapio_build_tools.ecosystems.python.pins import LockError, read_pins, without_url_pins


class AuditError(RuntimeError):
    """Python audit invocation failed."""


def findings(document: dict) -> tuple[list[risks.Finding], set[str]]:
    """The vulnerabilities in pip-audit's JSON report, and every package it audited."""
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        raise AuditError("pip-audit's report has no dependencies list")
    found: list[risks.Finding] = []
    audited: set[str] = set()
    for dependency in dependencies:
        name = dependency.get("name")
        if not isinstance(name, str):
            raise AuditError(f"pip-audit's report names a dependency without a name: {dependency!r}")
        audited.add(risks.package_key(name, "python"))
        if "skip_reason" in dependency:
            raise AuditError(f"pip-audit did not audit {name}: {dependency['skip_reason']}")
        for vulnerability in dependency.get("vulns") or []:
            found.append(risks.Finding(
                package=name,
                version=str(dependency.get("version")),
                id=vulnerability["id"],
                ecosystem="python",
                aliases=frozenset(vulnerability.get("aliases") or ()),
                fixed_in=tuple(vulnerability.get("fix_versions") or ()),
            ))
    return found, audited


def audit(config: Config, group_name: str, *, today: date | None = None) -> None:
    """Audit every release the group's lock pins, or say which it could not.

    pip-audit looks releases up on PyPI, where a wheel pinned by URL is not, so
    it would skip one and say so only in passing. Those pins are taken out of
    what it is given - each named here instead, as not audited - and what is
    left is audited strictly: anything else it cannot audit fails the run.
    The URL wheel's own dependencies are pins of their own in the lock, and
    are audited like any other.

    Accepted risks are applied here rather than handed to pip-audit as
    --ignore-vuln, which drops an id from every package and does not say what
    it dropped: an entry must name the package it accepts an advisory for,
    every suppression is printed, and an entry nothing matches is flagged.
    """
    python = config.require_python()
    group = python.requirement(group_name)
    try:
        url_pins = [pin for pin in read_pins(group.lock) if pin.url]
    except LockError as exc:
        raise AuditError(str(exc)) from exc

    with tempfile.TemporaryDirectory(prefix="tapio-audit-") as work:
        lock = group.lock
        if url_pins:
            lock = Path(work) / group.lock.name
            lock.write_text(without_url_pins(group.lock.read_text(encoding="utf-8")),
                            encoding="utf-8")
        report = Path(work) / "pip-audit.json"
        command = [
            sys.executable,
            "-m",
            "pip_audit",
            "--requirement",
            str(lock),
            "--no-deps",
            "--disable-pip",
            "--strict",
            "--format",
            "json",
            "--aliases",
            "on",
            "--desc",
            "off",
            "--output",
            str(report),
        ]
        # pip-audit exits 1 for a vulnerability and for a failure alike; a
        # report it wrote is what tells them apart.
        completed = subprocess.run(command, cwd=config.project)
        try:
            document = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AuditError(
                f"audit failed for requirement group {group_name!r}: pip-audit exited "
                f"{completed.returncode} without a report"
            ) from exc

    found, audited = findings(document)
    if completed.returncode != 0 and not found:
        raise AuditError(f"audit failed for requirement group {group_name!r}: pip-audit exited "
                         f"{completed.returncode} and reported no vulnerability")
    # Every group's audit reads the ecosystem's entries. With more than one
    # group, an entry is stale only if no other group's lock pins its package:
    # this group pinning a fixed release says nothing about another's.
    pinned = elsewhere = None
    if len(python.requirements) > 1:
        pinned = audited | {risks.package_key(pin.name, "python") for pin in url_pins}
        try:
            elsewhere = {pin.name for other in python.requirements if other.name != group_name
                         for pin in read_pins(other.lock)}
        except LockError as exc:
            raise AuditError(str(exc)) from exc
    assessment = risks.assess(found, python.accepted_risks, on=today or risks.today(),
                              pinned=pinned, elsewhere=elsewhere)
    risks.report(assessment, subject=f"requirement group {group_name!r}")

    for pin in url_pins:
        print(f"not audited: {pin.name} {pin.version} ({pin.url}), "
              f"a GitHub release wheel; its dependencies are audited")
    if assessment.failed:
        raise AuditError(f"audit failed for requirement group {group_name!r}: {assessment.failure()}")
