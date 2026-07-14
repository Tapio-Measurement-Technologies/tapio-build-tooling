"""Python lock vulnerability audits."""

from __future__ import annotations

import subprocess
import sys

from tapio_build_tools.config import Config


class AuditError(RuntimeError):
    """Python audit invocation failed."""


def audit(config: Config, group_name: str) -> None:
    group = config.python.requirement(group_name)
    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "--requirement",
        str(group.lock),
        "--no-deps",
        "--disable-pip",
    ]
    try:
        subprocess.run(command, cwd=config.project, check=True)
    except subprocess.CalledProcessError as exc:
        raise AuditError(f"audit failed for requirement group {group_name!r}") from exc

