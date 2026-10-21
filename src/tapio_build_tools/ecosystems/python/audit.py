"""Python lock vulnerability audits."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile

from tapio_build_tools.config import Config
from tapio_build_tools.ecosystems.python.pins import LockError, read_pins, without_url_pins


class AuditError(RuntimeError):
    """Python audit invocation failed."""


def audit(config: Config, group_name: str) -> None:
    """Audit every release the group's lock pins, or say which it could not.

    pip-audit looks releases up on PyPI, where a wheel pinned by URL is not, so
    it would skip one and say so only in passing. Those pins are taken out of
    what it is given - each named here instead, as not audited - and what is
    left is audited strictly: anything else it cannot audit fails the run.
    The URL wheel's own dependencies are pins of their own in the lock, and
    are audited like any other.
    """
    group = config.require_python().requirement(group_name)
    try:
        url_pins = [pin for pin in read_pins(group.lock) if pin.url]
    except LockError as exc:
        raise AuditError(str(exc)) from exc

    with tempfile.TemporaryDirectory(prefix="tapio-audit-") as work:
        lock = group.lock
        if url_pins:
            lock = Path(work) / group.lock.name
            lock.write_text(without_url_pins(group.lock.read_text(encoding="utf-8")),
                            encoding="utf-8")
        command = [
            sys.executable,
            "-m",
            "pip_audit",
            "--requirement",
            str(lock),
            "--no-deps",
            "--disable-pip",
            "--strict",
        ]
        try:
            subprocess.run(command, cwd=config.project, check=True)
        except subprocess.CalledProcessError as exc:
            raise AuditError(f"audit failed for requirement group {group_name!r}") from exc

    for pin in url_pins:
        print(f"not audited: {pin.name} {pin.version} ({pin.url}), "
              f"a GitHub release wheel; its dependencies are audited")
