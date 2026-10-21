"""Ages of the releases a Python requirement lock pins."""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
from urllib.parse import quote

from tapio_build_tools.config import Config
from tapio_build_tools.cooldown import (
    CooldownError,
    Pinned,
    fetch_json,
    gather,
    published,
    refuse_young,
)
from tapio_build_tools.ecosystems.python import pins
from tapio_build_tools.ecosystems.python.pins import Pin

INDEX = "https://pypi.org/pypi"

__all__ = ["INDEX", "Pin", "check", "read_pins"]


def read_pins(lock: Path) -> list[Pin]:
    """Every release *lock* pins; see :func:`pins.read_pins`."""
    try:
        return pins.read_pins(lock)
    except pins.LockError as exc:
        raise CooldownError(str(exc)) from exc


def _github_headers() -> dict[str, str]:
    """A token for the GitHub API, when the job has one.

    Unauthenticated, the API allows sixty requests an hour per address, which
    a shared runner can spend before this asks. Sent to api.github.com only.
    """
    token = os.environ.get("GITHUB_TOKEN", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _dated_from_pypi(pin: Pin) -> Pinned:
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


def _dated_from_github(pin: Pin) -> Pinned:
    """*pin*, a GitHub release asset, with the later of its upload and its release.

    The asset GitHub holds must be the file the lock pins: an asset replaced
    after the lock was compiled is refused here, as a PyPI hash no file has
    is, rather than dated as though it were the one pinned.
    """
    asset = pin.asset
    assert asset is not None
    document = fetch_json(
        asset.api_url,
        missing=f"{pin.label}: {asset.owner}/{asset.repository} has no published release {asset.tag}",
        headers=_github_headers(),
    )
    if document.get("draft") or not document.get("published_at"):
        raise CooldownError(f"{pin.label} is from a release that is not published")
    found = [item for item in document.get("assets") or [] if item.get("name") == asset.name]
    if not found:
        raise CooldownError(f"{pin.label}: release {asset.tag} has no asset {asset.name}")
    [item] = found
    [expected] = pin.hashes
    digest = item.get("digest")
    if not digest:
        raise CooldownError(f"{pin.label}: GitHub gives no digest for the asset, so the "
                            f"file it dates cannot be tied to the file pinned")
    if digest != f"sha256:{expected}":
        raise CooldownError(f"{pin.label} pins sha256:{expected}, and the release asset is {digest}")
    moments = [published(document["published_at"]), published(item["updated_at"])]
    return Pinned(pin.label, max(moments))


def _dated(pin: Pin) -> Pinned:
    return _dated_from_github(pin) if pin.url else _dated_from_pypi(pin)


def check(config: Config, group_name: str, moment: datetime) -> list[Pinned]:
    """Every release the group's lock pins, or an error naming the young ones."""
    group = config.require_python().requirement(group_name)
    return refuse_young(gather(_dated, read_pins(group.lock)), moment)
