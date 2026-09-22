"""Ages of the releases an npm package lock pins."""

from __future__ import annotations

from datetime import datetime
import json
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

REGISTRY = "https://registry.npmjs.org"


def read_pins(lock: Path) -> dict[str, set[str]]:
    """The versions the lock pins, by package name.

    Everything with a tarball is read, development and optional dependencies
    included, because npm installs them all and a build runs whatever it
    installs. The project itself and its workspace links have no tarball.
    """
    try:
        document = json.loads(lock.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CooldownError(f"{lock.name} is not valid JSON: {exc}") from exc
    packages = document.get("packages")
    if not isinstance(packages, dict):
        raise CooldownError(f"{lock.name} has no packages table; npm lockfileVersion 2 or 3 is needed")
    pins: dict[str, set[str]] = {}
    for path, entry in packages.items():
        if not path or not isinstance(entry, dict) or entry.get("link"):
            continue
        resolved = entry.get("resolved")
        if not isinstance(resolved, str):
            continue
        name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise CooldownError(f"{lock.name} holds an entry without a name and version: {path}")
        if not resolved.startswith(f"{REGISTRY}/"):
            raise CooldownError(f"{name}@{version} does not come from {REGISTRY}: {resolved}")
        pins.setdefault(name, set()).add(version)
    return pins


def _dated(pin: tuple[str, set[str]]) -> list[Pinned]:
    """Every pinned version of one package, with the time the registry gives it."""
    name, versions = pin
    document = fetch_json(
        f"{REGISTRY}/{quote(name, safe='@/')}",
        missing=f"{name} is not on the npm registry",
    )
    times = document.get("time")
    if not isinstance(times, dict):
        raise CooldownError(f"the npm registry gives no publication times for {name}")
    dated = []
    for version in sorted(versions):
        moment = times.get(version)
        if not isinstance(moment, str):
            raise CooldownError(f"the npm registry gives no publication time for {name}@{version}")
        dated.append(Pinned(f"{name}@{version}", published(moment)))
    return dated


def check(config: Config, moment: datetime) -> list[Pinned]:
    """Every release the package lock pins, or an error naming the young ones."""
    pins = read_pins(config.require_node().lock)
    dated = gather(_dated, sorted(pins.items()))
    return refuse_young([release for package in dated for release in package], moment)
