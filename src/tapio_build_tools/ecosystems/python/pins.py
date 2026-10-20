"""What a Python requirement lock pins: `name==version`, or a wheel by URL.

Cooldown, audit and the SBOM each walk a lock. They read it here, so that a
line one of them understands is a line all of them understand.

A URL pin is a wheel attached to a GitHub release - a first-party library
published from a public repository, say - and is written in requirements.in
as ``name @ https://github.com/<owner>/<repo>/releases/download/<tag>/<wheel>``,
without a hash; the compiled lock carries the hash. Any other URL is refused:
a lock that may name any address is a lock that may fetch from anywhere, and
nothing could date or check what it fetched.

Which owner a pin names is not checked here. The hash fixes the file; which
repository it comes from is a line in requirements.in, and is reviewed there
like any other dependency.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import quote, unquote, urlsplit

from packaging.utils import (
    InvalidWheelFilename,
    canonicalize_name,
    parse_wheel_filename,
)

# A pin, up to the marker or the continuation that may follow it.
_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\s*==\s*(?P<version>[^\s;\\]+)")
_URL_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\s*@\s*(?P<url>[^\s;\\]+)")
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")
# pip reads a `#` as a comment at the start of a line or after whitespace.
_COMMENT = re.compile(r"(?:^|\s)#.*$")
# GitHub's own rules: an owner is letters, digits and single hyphens; a
# repository name may also hold dots and underscores, but is never . or ..,
# which the API would read as a path step to some other resource.
_RELEASE_ASSET = re.compile(
    r"/(?P<owner>[A-Za-z0-9](?:-?[A-Za-z0-9])*)/(?P<repository>(?!\.\.?/)[A-Za-z0-9_.-]+)"
    r"/releases/download/(?P<tag>[^/]+)/(?P<name>[^/]+)"
)
# What may follow the URL in a URL pin's entry: a marker, and its hashes.
_URL_PIN_REST = re.compile(r"(?:\s*;(?:(?!--hash=).)*?)?(?:\s+--hash=sha256:[0-9a-f]{64})*\s*")


class LockError(ValueError):
    """A lock holds a line that is not a pin this tooling can account for."""


@dataclass(frozen=True)
class ReleaseAsset:
    """A file attached to a GitHub release, as a URL pin names it."""

    owner: str
    repository: str
    tag: str
    name: str

    @property
    def api_url(self) -> str:
        """The release, as the GitHub REST API describes it."""
        return (f"https://api.github.com/repos/{self.owner}/{self.repository}"
                f"/releases/tags/{quote(self.tag, safe='')}")


@dataclass(frozen=True)
class Pin:
    """One release a lock pins, with the file hashes it allows.

    A URL pin's version is its wheel's, read from the file name.
    """

    name: str
    version: str
    hashes: frozenset[str]
    url: str = ""

    @property
    def label(self) -> str:
        if self.url:
            return f"{self.name} {self.version} ({self.url})"
        return f"{self.name}=={self.version}"

    @property
    def asset(self) -> ReleaseAsset | None:
        return release_asset(self.url) if self.url else None


def release_asset(url: str) -> ReleaseAsset | None:
    """The GitHub release asset *url* names, or None if it names none."""
    try:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname != "github.com" or parts.port \
                or parts.username or parts.password or parts.query or parts.fragment:
            return None
    except ValueError:  # an unreadable port, an unbalanced bracket
        return None
    match = _RELEASE_ASSET.fullmatch(parts.path)
    if match is None:
        return None
    return ReleaseAsset(
        owner=match["owner"], repository=match["repository"],
        tag=unquote(match["tag"]), name=unquote(match["name"]),
    )


def entries(text: str) -> Iterator[str]:
    """The lock's logical lines: comments dropped, continuations joined.

    A blank or comment-only line ends a continuation, as it does for pip, so
    what is read here as one requirement is what pip installs as one.
    """
    entry = ""
    for line in text.splitlines():
        stripped = _COMMENT.sub("", line).strip()
        if not stripped:
            if entry.strip():
                yield entry.strip()
            entry = ""
            continue
        if stripped.endswith("\\"):
            entry += stripped[:-1] + " "
            continue
        entry += stripped
        yield entry
        entry = ""
    if entry.strip():
        yield entry.strip()


def _url_pin(lock: Path, name: str, url: str, hashes: set[str]) -> Pin:
    asset = release_asset(url)
    if asset is None:
        raise LockError(
            f"{lock.name} pins {name} from {url}, which is not a GitHub release asset")
    try:
        wheel_name, version, _build, _tags = parse_wheel_filename(asset.name)
    except InvalidWheelFilename as exc:
        raise LockError(f"{lock.name} pins {name} from {url}, which is not a wheel") from exc
    if wheel_name != canonicalize_name(name):
        raise LockError(f"{lock.name} pins {name} from {url}, a wheel of {wheel_name}")
    if len(hashes) != 1:
        raise LockError(
            f"{lock.name} pins {name} from {url} with {len(hashes)} hashes; "
            f"a URL names one file and needs exactly one")
    return Pin(canonicalize_name(name), str(version), frozenset(hashes), url)


def read_pins(lock: Path) -> list[Pin]:
    """Every release *lock* pins, each with the hashes pip is allowed to install.

    A group compiled by this tooling carries hashes, and the files behind them
    are what gets dated. A lock-only group may carry none, and then the whole
    release is dated instead - except for a URL pin, which always needs its
    one hash.
    """
    hashes: dict[tuple[str, str, str], set[str]] = {}
    for entry in entries(lock.read_text(encoding="utf-8")):
        if entry.startswith("-"):  # --only-binary, --index-url, -r, -c
            continue
        found = _HASH.findall(entry)
        match = _PIN.match(entry)
        if match is not None:
            key = (canonicalize_name(match["name"]), match["version"], "")
            hashes.setdefault(key, set()).update(found)
            continue
        match = _URL_PIN.match(entry)
        if match is None:
            raise LockError(f"{lock.name} holds a requirement that is not pinned: {entry}")
        if not _URL_PIN_REST.fullmatch(entry[match.end():]):
            raise LockError(f"{lock.name} holds more than one URL pin in one entry: {entry}")
        pin = _url_pin(lock, match["name"], match["url"], set(found))
        hashes.setdefault((pin.name, pin.version, pin.url), set()).update(pin.hashes)
    pins = [Pin(name, version, frozenset(allowed), url)
            for (name, version, url), allowed in hashes.items()]
    for pin in pins:
        if pin.url and len(pin.hashes) != 1:
            raise LockError(f"{lock.name} pins {pin.label} with more than one hash")
    return pins


def _is_url_pin(entry: str) -> bool:
    """Whether *entry* is a URL pin, and nothing but; LockError if it starts as one only."""
    match = _URL_PIN.match(entry)
    if match is None:
        return False
    if not _URL_PIN_REST.fullmatch(entry[match.end():]):
        raise LockError(f"a lock holds more than a URL pin in one entry: {entry}")
    return True


def without_url_pins(text: str) -> str:
    """*text*, a lock, with each URL pin's lines taken out and the rest as it was.

    Lines are grouped the way :func:`entries` joins them, so what is taken out
    is exactly the entries read as URL pins.
    """
    kept: list[str] = []
    group: list[str] = []

    def close() -> None:
        joined = " ".join(_COMMENT.sub("", part).strip().removesuffix("\\") for part in group)
        if not _is_url_pin(joined.strip()):
            kept.extend(group)
        group.clear()

    for line in text.splitlines(keepends=True):
        content = _COMMENT.sub("", line).strip()
        if not content:
            if group:
                close()
            kept.append(line)
            continue
        group.append(line)
        if not content.endswith("\\"):
            close()
    if group:
        close()
    return "".join(kept)
