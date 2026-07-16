"""npm lock vulnerability audits."""

from __future__ import annotations

import subprocess

from tapio_build_tools.config import Config


class AuditError(RuntimeError):
    """npm audit invocation failed."""


def audit(config: Config) -> None:
    node = config.require_node()
    command = ["npm", "audit", "--package-lock-only"]
    try:
        subprocess.run(command, cwd=node.package.parent, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuditError("npm audit failed") from exc
