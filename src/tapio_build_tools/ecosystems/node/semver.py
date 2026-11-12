"""Just enough npm semver to tell whether an installed version is in an advisory's range.

npm audit gives each advisory its vulnerable range the way GitHub's advisory
database writes npm ranges: comparator sets of full versions, such as
`<4.3.1` or `>=2.0.0 <2.2.2 || >=3.0.0 <3.1.1`. That is what is read here.
Anything else - a partial version, a hyphen range, `^` or `~` - is not
guessed at: `satisfies` says it cannot tell, and the caller keeps the version.

Versions compare by semver precedence, prereleases included. npm's rule that
a prerelease satisfies a range only beside a comparator with the same
release is not applied, so a prerelease is reported if anything - for an
audit, the safe side.
"""

from __future__ import annotations

import re

_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_COMPARATOR = re.compile(r"^(<=|>=|<|>|=)?(.+)$")


def _key(version: str) -> tuple | None:
    match = _VERSION.match(version)
    if match is None:
        return None
    release = tuple(int(part) for part in match.group(1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        # A release ranks above every prerelease of itself.
        return release + ((1,),)
    identifiers = tuple((0, int(part), "") if part.isdigit() else (1, 0, part)
                        for part in prerelease.split("."))
    return release + ((0, identifiers),)


def _holds(operator: str, found: tuple, bound: tuple) -> bool:
    return {
        "<": found < bound, "<=": found <= bound, ">": found > bound,
        ">=": found >= bound, "=": found == bound,
    }[operator]


def satisfies(version: str, vulnerable: str) -> bool | None:
    """Whether *version* is in the range *vulnerable*; None when either cannot be read."""
    found = _key(version)
    if found is None:
        return None
    for comparator_set in vulnerable.split("||"):
        comparators = comparator_set.split()
        if not comparators or comparators == ["*"]:
            return True
        holds = True
        for comparator in comparators:
            match = _COMPARATOR.match(comparator)
            bound = _key(match.group(2)) if match else None
            if bound is None:
                return None
            holds = holds and _holds(match.group(1) or "=", found, bound)
        if holds:
            return True
    return False
