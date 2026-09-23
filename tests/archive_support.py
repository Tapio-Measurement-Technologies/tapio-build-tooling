"""Fixtures shared by the archive tests: a firmware project on disk, a fake docker and Actions environments."""

from __future__ import annotations

import io
from pathlib import Path

from tapio_build_tools.config import Config, load_config


COMMIT = "0123456789abcdef0123456789abcdef01234567"

ARCHIVE_CONFIG = """\
schema-version = 1

[organization]
name = "Example Oy"

[products.gadget]
name = "Gadget Firmware"
license-name = "Proprietary"
component-type = "firmware"

[archive]
slug = "gadget"
zip = "gadget_firmware-${version}.zip"
files = ["dist/package/*"]
"""

ACTIONS = {
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_REF_NAME": "main",
    "GITHUB_RUN_NUMBER": "42",
    "GITHUB_RUN_ID": "9001",
    "GITHUB_SHA": COMMIT,
    "GITHUB_REPOSITORY_OWNER": "Example-Org",
}
TAG_PUSH = {**ACTIONS, "GITHUB_REF": "refs/tags/v1.2.0", "GITHUB_REF_NAME": "v1.2.0"}


def write_archive_project(root: Path, config: str = ARCHIVE_CONFIG) -> Config:
    """A firmware project whose build has prepared dist/package/firmware.hex."""
    (root / "build-tooling.toml").write_text(config, encoding="utf-8")
    package = root / "dist" / "package"
    package.mkdir(parents=True, exist_ok=True)
    (package / "firmware.hex").write_text(":00000001FF\n", encoding="utf-8")
    return load_config(root)


class FakeDocker:
    """Stands in for ``docker save``: hands back *image* on stdout, or fails."""

    def __init__(self, image: bytes = b"an image tar", *, returncode: int = 0, stderr: bytes = b"") -> None:
        self.image = image
        self.returncode = returncode
        self.stderr = stderr
        self.commands: list[list[str]] = []

    def __call__(self, args: list[str], **_: object) -> "_Process":
        self.commands.append(list(args))
        return _Process(self.image, self.returncode, self.stderr)


class _Process:
    def __init__(self, stdout: bytes, returncode: int, stderr: bytes) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode: int | None = None
        self._returncode = returncode

    def __enter__(self) -> "_Process":
        return self

    def __exit__(self, *_: object) -> None:
        self.returncode = self._returncode
