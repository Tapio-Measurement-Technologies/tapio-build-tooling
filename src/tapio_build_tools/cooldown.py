"""Release ages, read back from the index for a lock that is already written.

Compiling with a cooldown keeps a fresh release out of a lock this tooling
writes. A lock can reach the repository another way - npm writes its own, and
any lock can be edited by hand - so the ages are asked of the index again,
from the lock itself, whatever wrote it.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from typing import Callable, Iterable, Mapping, TypeVar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


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
    """One release a lock pins, named the way its ecosystem names it."""

    label: str
    published: datetime


def refuse_young(pinned: Iterable[Pinned], moment: datetime) -> list[Pinned]:
    """*pinned* as a list, or an error naming everything newer than *moment*."""
    releases = list(pinned)
    young = sorted(
        (release for release in releases if release.published > moment),
        key=lambda release: release.published,
        reverse=True,
    )
    if young:
        named = ", ".join(f"{release.label} ({timestamp(release.published)})" for release in young)
        raise CooldownError(f"released after {timestamp(moment)}: {named}")
    return releases
