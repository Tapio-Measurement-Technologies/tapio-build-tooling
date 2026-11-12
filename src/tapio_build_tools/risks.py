"""Accepted risks: known advisories a product carries on purpose, until a date.

An audit reports findings, each a package release and the advisory ids that
name one vulnerability in it. A finding is accepted when a configured entry
names its package and one of its ids, and the entry's review-by date has not
passed. A finding no entry accepts fails the audit, and so does one whose only
entries are past their review-by date: the acceptance was for a while, and the
message says which entry ran out.

An entry that matches no finding is stale - the package was upgraded past the
fix, or the advisory withdrawn - and is flagged, so it is removed rather than
left to accept some later advisory nobody has looked at.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
import os
from typing import Callable, Iterable

from tapio_build_tools.config import AcceptedRisk, package_key

__all__ = ["Assessment", "Finding", "assess", "matches", "package_key", "report", "today", "warn"]


def today() -> date:
    """The UTC date review-by dates are compared against."""
    return datetime.now(timezone.utc).date()


@dataclass(frozen=True)
class Finding:
    """One advisory against one installed release, as an audit reports it.

    *id* is the audit's own name for the advisory; *aliases* are the other ids
    it gives for the same vulnerability, any of which an entry may name.
    """

    package: str
    version: str
    id: str
    ecosystem: str
    aliases: frozenset[str] = frozenset()
    severity: str | None = None
    # None where the audit does not say: npm audit names no fixed version.
    fixed_in: tuple[str, ...] | None = None

    @property
    def ids(self) -> frozenset[str]:
        return self.aliases | {self.id}

    @property
    def key(self) -> str:
        return package_key(self.package, self.ecosystem)

    @property
    def label(self) -> str:
        return f"{self.package} {self.version} {self.id}"

    def describe(self) -> str:
        details = []
        if self.severity:
            details.append(self.severity.lower())
        if self.fixed_in is not None:
            details.append(f"fixed in {', '.join(self.fixed_in)}" if self.fixed_in else "no fix released")
        aliases = sorted(self.aliases - {self.id})
        named = f" ({', '.join(aliases)})" if aliases else ""
        return f"{self.label}{named}" + (f": {'; '.join(details)}" if details else "")


def matches(risk: AcceptedRisk, finding: Finding) -> bool:
    """Whether *risk* names *finding*'s package and one of its ids.

    An ecosystem's entry covers that ecosystem's packages only; a container
    entry covers a package of any kind in an image, its name compared as the
    package's own ecosystem compares names.
    """
    return (
        risk.ecosystem in (finding.ecosystem, "container")
        and package_key(risk.package, finding.ecosystem) == finding.key
        and risk.id in finding.ids
    )


@dataclass(frozen=True)
class Assessment:
    """What an audit's findings come to against the configured entries."""

    accepted: tuple[tuple[Finding, AcceptedRisk], ...]
    expired: tuple[tuple[Finding, AcceptedRisk], ...]
    open: tuple[Finding, ...]
    stale: tuple[AcceptedRisk, ...]
    # Entries this lock matches nothing for, whose package another lock also
    # pins: that lock may need them, so they are not called stale here.
    unmatched: tuple[AcceptedRisk, ...] = ()
    # Findings no current entry accepts that do not fail the audit anyway -
    # below an image scan's threshold, say.
    passed: tuple[Finding, ...] = ()

    @property
    def failed(self) -> bool:
        return bool(self.open or self.expired)

    def failure(self) -> str:
        """Why the audit fails, one clause per finding."""
        reasons = [f"{finding.label} is not accepted" for finding in self.open]
        reasons += [
            f"{finding.label} was accepted by {risk.source} until {risk.review_by.isoformat()}, "
            f"which has passed: review the risk and move review-by, or take the fix"
            for finding, risk in self.expired
        ]
        return "; ".join(reasons)


def assess(
    findings: Iterable[Finding],
    risks: Iterable[AcceptedRisk],
    *,
    on: date,
    pinned: set[str] | None = None,
    elsewhere: set[str] | None = None,
    fails: Callable[[Finding], bool] = lambda finding: True,
    judges: Callable[[AcceptedRisk], bool] = lambda risk: True,
) -> Assessment:
    """Sort *findings* by whether an entry in *risks* accepts them *on* that date.

    A finding no current entry accepts fails if *fails* says so, and passes
    otherwise. Only entries *judges* picks are called stale or unmatched; the
    rest are another check's to judge.

    Where several locks share the entries, *pinned* is the package keys the
    audited lock holds and *elsewhere* those the other locks hold. An entry
    that matches nothing here is stale only if no other lock pins its package:
    one this lock pins at a fixed release may still be needed by a lock that
    pins a vulnerable one, and is reported as unmatched instead; one only
    another lock pins is that lock's to judge. Without *pinned*, every entry
    that matches nothing is stale.
    """
    risks = tuple(risks)
    used: set[AcceptedRisk] = set()
    accepted: list[tuple[Finding, AcceptedRisk]] = []
    expired: list[tuple[Finding, AcceptedRisk]] = []
    unaccepted: list[Finding] = []
    passed: list[Finding] = []
    for finding in sorted(set(findings), key=lambda item: (item.key, item.version, item.id)):
        matching = [risk for risk in risks if matches(risk, finding)]
        used.update(matching)
        current = [risk for risk in matching if risk.active(on)]
        if current:
            accepted.append((finding, current[0]))
        elif not fails(finding):
            passed.append(finding)
        elif matching:
            expired.append((finding, matching[0]))
        else:
            unaccepted.append(finding)
    stale: list[AcceptedRisk] = []
    unmatched: list[AcceptedRisk] = []
    for risk in risks:
        if risk in used or not judges(risk):
            continue
        key = package_key(risk.package, risk.ecosystem)
        if pinned is None or key not in (elsewhere or set()):
            stale.append(risk)
        elif key in pinned:
            unmatched.append(risk)
    return Assessment(tuple(accepted), tuple(expired), tuple(unaccepted), tuple(stale),
                      tuple(unmatched), tuple(passed))


def warn(message: str) -> None:
    """*message* on standard output, as a warning annotation inside GitHub Actions.

    A job that passes shows nothing of its log unless it is opened; the
    annotation puts a stale entry on the run's summary page instead.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::warning title=tapio-build::{message}")
    else:
        print(f"warning: {message}")


def report(assessment: Assessment, *, subject: str, summary: bool = True) -> None:
    """Print every finding and how it was judged, and flag each stale entry."""
    for finding, risk in assessment.accepted:
        print(f"accepted: {finding.describe()} - {risk.source}, review by "
              f"{risk.review_by.isoformat()}: {risk.reason}")
    for finding, risk in assessment.expired:
        print(f"no longer accepted: {finding.describe()} - {risk.source} was to be reviewed by "
              f"{risk.review_by.isoformat()}")
    for finding in assessment.open:
        print(f"vulnerable: {finding.describe()}")
    for risk in assessment.stale:
        warn(f"{subject}: {risk.source} accepts {risk.id} for {risk.package}, which no finding "
             f"matches any more; remove the entry")
    for risk in assessment.unmatched:
        print(f"not matched in {subject}: {risk.source} accepts {risk.id} for {risk.package}, "
              f"which another group's lock also pins; that group's audit judges it")
    if not summary:
        return
    total = len(assessment.accepted) + len(assessment.expired) + len(assessment.open)
    print(f"{subject}: {total} finding(s), {len(assessment.accepted)} accepted, "
          f"{len(assessment.open) + len(assessment.expired)} not accepted")
