"""Ages of the releases a Python requirement lock pins."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
from urllib.parse import quote

from packaging.utils import canonicalize_name

from tapio_build_tools.config import Config
from tapio_build_tools.cooldown import (
    CooldownError,
    Pinned,
    fetch_json,
    gather,
    published,
    refuse_young,
)

INDEX = "https://pypi.org/pypi"

# A pin, up to the marker or the continuation that may follow it.
_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\s*==\s*(?P<version>[^\s;\\]+)")
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")
# pip reads a `#` as a comment at the start of a line or after whitespace.
_COMMENT = re.compile(r"(?:^|\s)#.*$")


@dataclass(frozen=True)
class Pin:
    """One `name==version` in a lock, with the file hashes it allows."""

    name: str
    version: str
    hashes: frozenset[str]

    @property
    def label(self) -> str:
        return f"{self.name}=={self.version}"


def _entries(text: str):
    """The lock's logical lines: comments dropped, continuations joined."""
    entry = ""
    for line in text.splitlines():
        stripped = _COMMENT.sub("", line).strip()
        if not stripped:
            continue
        if stripped.endswith("\\"):
            entry += stripped[:-1] + " "
            continue
        entry += stripped
        yield entry
        entry = ""
    if entry.strip():
        yield entry.strip()


def read_pins(lock: Path) -> list[Pin]:
    """Every release *lock* pins, each with the hashes pip is allowed to install.

    A group compiled by this tooling carries hashes, and the files behind them
    are what gets dated. A lock-only group may carry none, and then the whole
    release is dated instead.
    """
    hashes: dict[tuple[str, str], set[str]] = {}
    for entry in _entries(lock.read_text(encoding="utf-8")):
        if entry.startswith("-"):  # --only-binary, --index-url, -r, -c
            continue
        match = _PIN.match(entry)
        if match is None:
            raise CooldownError(f"{lock.name} holds a requirement that is not pinned: {entry}")
        key = (canonicalize_name(match["name"]), match["version"])
        hashes.setdefault(key, set()).update(_HASH.findall(entry))
    return [
        Pin(name, version, frozenset(allowed)) for (name, version), allowed in hashes.items()
    ]


def _dated(pin: Pin) -> Pinned:
    """*pin* with the upload time of the newest file it allows."""
    document = fetch_json(
        f"{INDEX}/{quote(pin.name, safe='')}/{quote(pin.version, safe='')}/json",
        missing=f"{pin.label} is not on PyPI",
    )
    files = document.get("urls") or []
    if not files:
        raise CooldownError(f"{pin.label} has no files on PyPI")
    if pin.hashes:
        available = {file.get("digests", {}).get("sha256") for file in files}
        unknown = sorted(pin.hashes - available)
        if unknown:
            raise CooldownError(
                f"{pin.label} pins {len(unknown)} hash(es) that no file on PyPI has: "
                + ", ".join(unknown)
            )
        files = [file for file in files if file.get("digests", {}).get("sha256") in pin.hashes]
    return Pinned(pin.label, max(published(file["upload_time_iso_8601"]) for file in files))


def check(config: Config, group_name: str, moment: datetime) -> list[Pinned]:
    """Every release the group's lock pins, or an error naming the young ones."""
    group = config.require_python().requirement(group_name)
    return refuse_young(gather(_dated, read_pins(group.lock)), moment)
