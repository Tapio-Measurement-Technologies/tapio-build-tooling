"""Hashed Python requirement lock generation."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from tapio_build_tools.config import Config, ConfigError, RequirementGroup


class RequirementsError(RuntimeError):
    """Requirement compilation failed or found stale output."""


@dataclass(frozen=True)
class CompileResult:
    group: str
    status: str


def _check_python(config: Config) -> None:
    configured = tuple(int(part) for part in config.python.version.split(".")[:2])
    running = sys.version_info[:2]
    if configured != running:
        raise RequirementsError(
            f"Python {config.python.version} is configured, but compiler runs on "
            f"{running[0]}.{running[1]}"
        )


def _command(config: Config, group: RequirementGroup, output: Path, upgrade: bool) -> list[str]:
    if group.input is None:
        raise AssertionError("lock-only groups cannot be compiled")
    command = [
        sys.executable,
        "-m",
        "piptools",
        "compile",
        "--quiet",
        "--generate-hashes",
        "--allow-unsafe",
        "--resolver=backtracking",
        "--strip-extras",
        "--annotation-style=split",
        "--cache-dir",
        str(Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "tapio-build-pip-cache"),
        "--output-file",
        str(output),
    ]
    if upgrade:
        command.append("--upgrade")
    command.append(str(group.input.relative_to(config.project)))
    return command


def compile_requirements(
    config: Config,
    *,
    group_name: str | None = None,
    check: bool = False,
    upgrade: bool = False,
) -> list[CompileResult]:
    if check and upgrade:
        raise ConfigError("--check and --upgrade cannot be combined")
    _check_python(config)
    groups = (
        (config.python.requirement(group_name),)
        if group_name is not None
        else config.python.requirements
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
        environment = os.environ.copy()
        environment["CUSTOM_COMPILE_COMMAND"] = "tapio-build --project . python requirements compile"
        try:
            subprocess.run(
                _command(config, group, temporary, upgrade),
                cwd=config.project,
                env=environment,
                check=True,
            )
            generated = temporary.read_bytes()
            current = group.lock.read_bytes() if group.lock.exists() else None
            if check:
                if current != generated:
                    stale.append(group.name)
                results.append(CompileResult(group.name, "current" if current == generated else "stale"))
            else:
                os.replace(temporary, group.lock)
                results.append(CompileResult(group.name, "updated"))
        except subprocess.CalledProcessError as exc:
            raise RequirementsError(f"pip-compile failed for group {group.name!r}") from exc
        finally:
            temporary.unlink(missing_ok=True)
    if stale:
        raise RequirementsError(f"stale requirement lock(s): {', '.join(stale)}")
    return results
