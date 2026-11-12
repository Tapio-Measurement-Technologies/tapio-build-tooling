"""Hashed Python requirement lock generation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from tapio_build_tools import cooldown, risks
from tapio_build_tools.config import Config, ConfigError, RequirementGroup
from tapio_build_tools.cooldown import CooldownError
from tapio_build_tools.ecosystems.python.cooldown import published_release
from tapio_build_tools.ecosystems.python.pins import url_requirements


class RequirementsError(RuntimeError):
    """Requirement compilation failed or found stale output."""


@dataclass(frozen=True)
class CompileResult:
    group: str
    status: str


def _check_python(config: Config) -> None:
    python = config.require_python()
    configured = tuple(int(part) for part in python.version.split(".")[:2])
    running = sys.version_info[:2]
    if configured != running:
        raise RequirementsError(
            f"Python {python.version} is configured, but compiler runs on "
            f"{running[0]}.{running[1]}"
        )


def _cutoff(days: int, *, now: datetime | None = None) -> str:
    """The instant a release has to predate to be a candidate, as RFC 3339 UTC.

    uv compares this against the upload time of each distribution file, so a
    version that appeared on the index today is invisible to the resolver
    until the cooldown has passed.
    """
    return cooldown.timestamp(cooldown.cutoff(days, now=now))


def _url_required(config: Config) -> set[str]:
    """The packages any group's input or lock requires by URL."""
    names: set[str] = set()
    for group in config.require_python().requirements:
        for path in (group.input, group.lock):
            if path is not None and path.is_file():
                names |= url_requirements(path.read_text(encoding="utf-8"))
    return names


def _excepted(config: Config, cutoff: str, *, today: date | None = None) -> dict[str, str]:
    """A cutoff of its own for each release excepted from the cooldown.

    Without one, uv's cutoff makes a release younger than the window
    unsatisfiable, so a lock that pins it fails `compile --check` as well as
    `cooldown`. Each current exception moves its package's cutoff to just
    after the release it names - not to now, which would let a newer release
    of the package in unexcepted. An exception whose release is older than
    the window gets none: the global cutoff already allows it, and an earlier
    one of its own would hold the package back.

    Nor does a package required by URL - a wheel from a GitHub release. uv
    takes a URL requirement as written: --exclude-newer filters the
    candidates an index offers, and a URL offers none to filter, so the
    cutoff never holds such a wheel back (uv 0.13.4 resolves one released
    after its --exclude-newer). It is not on PyPI to be dated
    either; `python cooldown` dates it through GitHub, which needs a token
    and is no help to uv. So it gets no cutoff, and nothing is looked up.

    Every other exception is dated on PyPI, so with exceptions configured a
    compile needs PyPI reachable even with `--check`.
    """
    moment = cooldown.published(cutoff)
    on = today or risks.today()
    by_url = _url_required(config)
    cutoffs: dict[str, str] = {}
    for exception in config.require_python().cooldown_exceptions:
        name = risks.package_key(exception.package, "python")
        if not exception.active(on) or name in by_url:
            continue
        try:
            released = published_release(exception.package, exception.version)
        except CooldownError as exc:
            raise RequirementsError(
                f"{exception.source} excepts {exception.label} from the cooldown, and it could "
                f"not be dated on PyPI: {exc}") from exc
        if released <= moment:
            continue
        cutoffs[name] = cooldown.timestamp(released + timedelta(seconds=1))
        print(f"{exception.label}: excepted from the cooldown by {exception.source}; "
              f"released {cooldown.timestamp(released)}")
    return cutoffs


def _command(
    config: Config,
    group: RequirementGroup,
    output: Path,
    upgrade: bool,
    cutoff: str | None,
    package_cutoffs: dict[str, str] | None = None,
) -> list[str]:
    if group.input is None:
        raise AssertionError("lock-only groups cannot be compiled")
    command = [
        sys.executable,
        "-m",
        "uv",
        "pip",
        "compile",
        "--quiet",
        "--universal",
        "--python-version",
        config.require_python().version,
        "--generate-hashes",
        "--annotation-style=split",
        "--emit-build-options",
        "--cache-dir",
        str(Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "tapio-build-pip-cache"),
        "--custom-compile-command",
        "tapio-build --project . python requirements compile",
        "--output-file",
        str(output),
    ]
    if cutoff is not None:
        command += ["--exclude-newer", cutoff]
        for name, moment in sorted((package_cutoffs or {}).items()):
            command += ["--exclude-newer-package", f"{name}={moment}"]
    if upgrade:
        command.append("--upgrade")
    command.append(str(group.input.relative_to(config.project)))
    return command


_FORMAT_OPTIONS = (b"--no-binary ", b"--only-binary ")


def _order_build_options(lock: bytes) -> bytes:
    """Move blanket build options above the per-package exceptions.

    uv emits every ``--no-binary`` line before every ``--only-binary`` line.
    pip clears the opposing set whenever it reads ``:all:``, so an exception
    standing above ``--only-binary :all:`` is wiped and its package is left
    with no installable candidate. Listing the ``:all:`` options first keeps
    the exceptions pip applies.
    """
    lines = lock.split(b"\n")
    positions = [
        index
        for index, line in enumerate(lines)
        if line.startswith(_FORMAT_OPTIONS)
    ]
    options = [lines[index] for index in positions]
    ordered = [option for option in options if b":all:" in option]
    ordered += [option for option in options if b":all:" not in option]
    for position, option in zip(positions, ordered):
        lines[position] = option
    return b"\n".join(lines)


def compile_requirements(
    config: Config,
    *,
    group_name: str | None = None,
    check: bool = False,
    upgrade: bool = False,
    cooldown: bool = True,
) -> list[CompileResult]:
    if check and upgrade:
        raise ConfigError("--check and --upgrade cannot be combined")
    _check_python(config)
    python = config.require_python()
    groups = (
        (python.requirement(group_name),)
        if group_name is not None
        else python.requirements
    )
    # One cutoff for the whole run, so every group in it sees the same index.
    # It moves forward between runs, which only matters where uv is free to
    # choose a version: without --upgrade it keeps the pins already in the
    # lock, so a lock that was current stays current as the cutoff advances.
    cutoff = (
        _cutoff(python.cooldown_days)
        if cooldown and python.cooldown_days is not None
        else None
    )
    package_cutoffs = _excepted(config, cutoff) if cutoff is not None else {}
    results: list[CompileResult] = []
    stale: list[str] = []
    for group in groups:
        if group.input is None:
            results.append(CompileResult(group.name, "skipped (lock-only)"))
            continue
        group.lock.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{group.lock.name}.", suffix=".tmp", dir=group.lock.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        if group.lock.exists():
            shutil.copy2(group.lock, temporary)
        try:
            subprocess.run(
                _command(config, group, temporary, upgrade, cutoff, package_cutoffs),
                cwd=config.project,
                check=True,
            )
            generated = _order_build_options(temporary.read_bytes())
            current = group.lock.read_bytes() if group.lock.exists() else None
            if check:
                if current != generated:
                    stale.append(group.name)
                results.append(CompileResult(group.name, "current" if current == generated else "stale"))
            else:
                temporary.write_bytes(generated)
                os.replace(temporary, group.lock)
                results.append(CompileResult(group.name, "updated"))
        except subprocess.CalledProcessError as exc:
            raise RequirementsError(f"uv pip compile failed for group {group.name!r}") from exc
        finally:
            temporary.unlink(missing_ok=True)
    if stale:
        raise RequirementsError(f"stale requirement lock(s): {', '.join(stale)}")
    return results
