"""Hashed Python requirement lock generation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from tapio_build_tools import cooldown
from tapio_build_tools.config import Config, ConfigError, RequirementGroup


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


def _command(
    config: Config,
    group: RequirementGroup,
    output: Path,
    upgrade: bool,
    cutoff: str | None,
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
                _command(config, group, temporary, upgrade, cutoff),
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
