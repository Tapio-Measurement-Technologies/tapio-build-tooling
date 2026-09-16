"""Fixtures shared by the downloads tests: a project on disk and a fake aws CLI."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tarfile

from tapio_build_tools.config import Config, load_config


RELEASED = "2026-09-16T10:00:00Z"

GPL_CONFIG = """\
schema-version = 1

[organization]
name = "Example Oy"

[products.demo]
name = "Demo"
license-id = "GPL-3.0-or-later"

[ecosystems.python]
version = "3.12"

[[ecosystems.python.requirements]]
name = "runtime"
input = "requirements.in"
lock = "requirements.txt"

[downloads]
contact = "downloads@example.com"
logo = "src/assets/logo.png"

[downloads.programs.demo]
slug = "demo"
name = "Demo Program"
source-package = true
notes = "Unzip and run.\\n\\nSecond <paragraph>."

[[downloads.programs.demo.assets]]
os = "windows"
glob = "dist/demo-${version}-windows.exe"
sbom = "dist/demo-${version}-windows.cdx.json"

[[downloads.programs.demo.assets]]
os = "linux"
glob = "dist/demo-${version}-linux"
"""

PROPRIETARY_CONFIG = """\
schema-version = 1

[organization]
name = "Example Oy"

[products.suite]
name = "Suite"
license-name = "Proprietary"

[ecosystems.python]
version = "3.12"

[[ecosystems.python.requirements]]
name = "runtime"
input = "requirements.in"
lock = "requirements.txt"

[downloads]
contact = "downloads@example.com"

[downloads.programs.first]
slug = "suite-first"
name = "Suite First"

[[downloads.programs.first.assets]]
os = "windows"
glob = "dist/first-${version}-windows.exe"

[downloads.programs.second]
slug = "suite-second"
name = "Suite Second"

[[downloads.programs.second.assets]]
os = "windows"
glob = "dist/second-${version}-windows.exe"
"""


def write_project(root: Path, config: str = GPL_CONFIG, *, version: str = "v1.2.0") -> Config:
    """A consumer project with a build's outputs for *version* already in dist/."""
    (root / "requirements.in").write_text("packaging==26.2\n", encoding="utf-8")
    (root / "requirements.txt").write_text("packaging==26.2\n", encoding="utf-8")
    (root / "src" / "assets").mkdir(parents=True, exist_ok=True)
    (root / "src" / "assets" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\nnot really a png")
    (root / "build-tooling.toml").write_text(config, encoding="utf-8")
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    for name, size in (
        (f"demo-{version}-windows.exe", 3 * 1024 * 1024),
        (f"demo-{version}-linux", 2 * 1024 * 1024),
        (f"first-{version}-windows.exe", 1024),
        (f"second-{version}-windows.exe", 2048),
    ):
        (dist / name).write_bytes(bytes(size))
    (dist / f"demo-{version}-windows.cdx.json").write_text('{"bomFormat": "CycloneDX"}\n', encoding="utf-8")
    return load_config(root)


class FakeRunner:
    """Stands in for the aws and git command lines.

    Holds a bucket as a dictionary of key to bytes, answers ``s3 cp`` in both
    directions and ``s3api list-objects-v2``, and writes a small archive for
    ``git archive``. Every command is kept for the tests to look at.
    """

    def __init__(self, objects: dict[str, bytes] | None = None, *, fetch_error: str | None = None) -> None:
        self.objects: dict[str, bytes] = dict(objects or {})
        self.commands: list[list[str]] = []
        self.fetch_error = fetch_error

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess:
        self.commands.append(list(args))
        if args[0] == "git":
            return self._git(args)
        if args[:2] == ["aws", "s3"] and args[2] == "cp":
            return self._copy(args)
        if args[:2] == ["aws", "s3api"]:
            prefixes = sorted({key.split("/", 1)[0] + "/" for key in self.objects if "/" in key})
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(prefixes or None), stderr="")
        raise AssertionError(f"unexpected command: {args}")

    def _copy(self, args: list[str]) -> subprocess.CompletedProcess:
        source, target = args[3], args[4]
        if source.startswith("s3://"):
            key = source.split("/", 3)[3]
            if self.fetch_error:
                raise subprocess.CalledProcessError(1, args, stderr=self.fetch_error)
            if key not in self.objects:
                raise subprocess.CalledProcessError(
                    1, args, stderr=f'fatal error: An error occurred (404) when calling the HeadObject operation: Key "{key}" does not exist'
                )
            Path(target).write_bytes(self.objects[key])
        else:
            key = target.split("/", 3)[3]
            self.objects[key] = Path(source).read_bytes()
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    def _git(self, args: list[str]) -> subprocess.CompletedProcess:
        if "archive" in args:
            target = Path(args[args.index("-o") + 1])
            with tarfile.open(target, "w:gz") as archive:
                info = tarfile.TarInfo(args[args.index("--format=tar.gz") + 1].removeprefix("--prefix=") + "LICENSE")
                info.size = 0
                archive.addfile(info)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    def uploads(self) -> list[list[str]]:
        return [command for command in self.commands if command[:3] == ["aws", "s3", "cp"] and command[4].startswith("s3://")]

    def uploaded_keys(self) -> list[str]:
        return [command[4].split("/", 3)[3] for command in self.uploads()]
