"""Release ages, read back from the index for a lock that is already written.

Compiling with a cooldown keeps a fresh release out of a lock this tooling
writes. A lock can reach the repository another way - npm writes its own, and
any lock can be edited by hand - so the ages are asked of the index again,
from the lock itself, whatever wrote it.

A release taken inside the window on purpose - a security fix, say - is named
in the configuration as a cooldown exception: that release, at that version,
with the reason. It is let through while it is younger than the window and
until its review-by date, if it has one. Once the release is older than the
window the entry does nothing, and is flagged so that it is removed.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import json
from typing import Callable, Iterable, Mapping, Sequence, TypeVar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from tapio_build_tools import risks
from tapio_build_tools.config import CooldownException, release_key


class CooldownError(RuntimeError):
    """A lock holds a release younger than the cooldown, or one that cannot be dated."""


USER_AGENT = "tapio-build-tooling"
TIMEOUT_SECONDS = 30
WORKERS = 8


def cutoff(days: int, *, now: datetime | None = None) -> datetime:
    """The instant a release has to predate to be allowed into a lock."""
    return (now or datetime.now(timezone.utc)) - timedelta(days=days)


def timestamp(moment: datetime) -> str:
    """*moment* as the RFC 3339 UTC string uv reads and this tooling prints."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def published(value: str) -> datetime:
    """An index's ISO 8601 publication time, as an aware UTC moment."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class _SameHostRedirects(HTTPRedirectHandler):
    """Follows a redirect only to the host the request was made to.

    urllib carries a request's headers across a redirect, so a token sent to
    one host would otherwise be handed to whichever host it redirected to.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).hostname != urlsplit(req.full_url).hostname:
            raise HTTPError(req.full_url, code, f"refused a redirect to {newurl}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_json(url: str, *, missing: str, headers: Mapping[str, str] | None = None) -> dict:
    """The JSON document at *url*; *missing* is the error raised for a 404.

    *headers* are added to the request: a token, for an API that takes one.
    A request carrying any is not followed to another host.
    """
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json",
                                    **(headers or {})})
    opener = build_opener(_SameHostRedirects).open if headers else urlopen
    try:
        with opener(request, timeout=TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            raise CooldownError(missing) from exc
        raise CooldownError(f"reading {url} failed: {exc}") from exc
    except (URLError, OSError, ValueError) as exc:
        raise CooldownError(f"reading {url} failed: {exc}") from exc


Item = TypeVar("Item")
Result = TypeVar("Result")


def gather(work: Callable[[Item], Result], items: Iterable[Item]) -> list[Result]:
    """*work* over *items*, several at a time; the first failure is raised."""
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        return list(pool.map(work, items))


@dataclass(frozen=True)
class Pinned:
    """One release a lock pins, named the way its ecosystem names it.

    *package* and *version* are what a cooldown exception is matched by.
    """

    label: str
    published: datetime
    package: str = ""
    version: str = ""


def refuse_young(
    pinned: Iterable[Pinned],
    moment: datetime,
    exceptions: Sequence[CooldownException] = (),
    *,
    ecosystem: str = "python",
    on: date | None = None,
    elsewhere: set[tuple[str, object]] | None = None,
    subject: str = "lock",
) -> list[Pinned]:
    """*pinned* as a list, or an error naming everything newer than *moment*.

    A young release a current entry in *exceptions* names is let through and
    printed with its reason. An entry that lets nothing through is flagged:
    its release is older than the window, which is so for every lock, or no
    lock pins it. *elsewhere* is the releases the other locks sharing the
    entries pin, as release keys; an entry for one of those is that lock's
    to judge, and is not flagged here.
    """
    releases = list(pinned)
    on = on or risks.today()
    by_key: dict[tuple[str, object], CooldownException] = {}
    for exception in exceptions:
        by_key.setdefault(exception.key, exception)

    young: list[Pinned] = []
    lapsed: dict[Pinned, CooldownException] = {}
    excused: list[tuple[Pinned, CooldownException]] = []
    used: set[CooldownException] = set()
    for release in sorted(releases, key=lambda item: item.published, reverse=True):
        exception = by_key.get(release_key(release.package, release.version, ecosystem))
        if exception is not None:
            used.add(exception)
        if release.published <= moment:
            if exception is not None:
                risks.warn(f"{subject}: {exception.source} excepts {exception.label} from the "
                           f"cooldown, and it was released {timestamp(release.published)}, before "
                           f"the window; remove the entry")
            continue
        if exception is not None and exception.active(on):
            excused.append((release, exception))
        else:
            if exception is not None:
                lapsed[release] = exception
            young.append(release)

    for release, exception in excused:
        print(f"accepted inside the cooldown: {release.label} ({timestamp(release.published)}) - "
              f"{exception.source}: {exception.reason}")
    for exception in exceptions:
        if exception in used or (elsewhere is not None and exception.key in elsewhere):
            continue
        pinning = "the lock does not pin it" if elsewhere is None else "no group's lock pins it"
        risks.warn(f"{subject}: {exception.source} excepts {exception.label} from the cooldown, "
                   f"and {pinning}; remove the entry")
    if young:
        named = ", ".join(
            f"{release.label} ({timestamp(release.published)})"
            + (f", whose exception in {lapsed[release].source} lapsed after "
               f"{lapsed[release].review_by.isoformat()}" if release in lapsed else "")
            for release in young
        )
        raise CooldownError(f"released after {timestamp(moment)}: {named}")
    return releases
