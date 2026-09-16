"""Turning build outputs into the files a download page offers."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
import glob
import gzip
import os
import shutil
from pathlib import Path
from string import Template
import subprocess
import tarfile
import tempfile
import zipfile

from tapio_build_tools.config import VERSION_PLACEHOLDER
from tapio_build_tools.downloads import DownloadsError


Runner = Callable[[list[str]], subprocess.CompletedProcess]

CONTENT_TYPES = {
    ".zip": "application/zip",
    ".gz": "application/gzip",
    ".cdx.json": "application/vnd.cyclonedx+json",
    ".json": "application/json; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".exe": "application/vnd.microsoft.portable-executable",
}


def content_type(path: Path | str) -> str:
    name = str(path).lower()
    for suffix, value in CONTENT_TYPES.items():
        if name.endswith(suffix):
            return value
    return "application/octet-stream"


def resolve_glob(project: Path, pattern: str, version: str) -> Path:
    """The one file *pattern* names once *version* is filled in."""
    expanded = Template(pattern).substitute({VERSION_PLACEHOLDER: version})
    matches = sorted(glob.glob(expanded, root_dir=project))
    if len(matches) != 1:
        found = ", ".join(matches) if matches else "nothing"
        raise DownloadsError(f"{expanded} must match exactly one file; matched {found}")
    return project / matches[0]


def _run(runner: Runner, args: list[str]) -> subprocess.CompletedProcess:
    try:
        return runner(args)
    except FileNotFoundError as exc:
        raise DownloadsError(f"{args[0]} is not installed") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
        raise DownloadsError(f"{' '.join(args)} failed: {detail or exc}") from exc


def _subprocess_runner(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, capture_output=True, text=True)


def _atomically(target: Path, write: Callable[[Path], None]) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        write(temporary)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return target


def _epoch(modified: str) -> int:
    return int(datetime.fromisoformat(modified.replace("Z", "+00:00")).timestamp())


def zip_file(source: Path, target: Path, *, modified: str) -> Path:
    """*target*: a zip holding *source* under its own name, dated *modified*.

    The date is the release's, not the file's or the clock's: the same source
    packaged twice gives the same bytes, so publishing a release again after
    a failure part-way finds the files it already uploaded unchanged.
    """
    moment = datetime.fromtimestamp(_epoch(modified))

    def write(temporary: Path) -> None:
        info = zipfile.ZipInfo(source.name, date_time=moment.timetuple()[:6])
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o755 << 16
        with zipfile.ZipFile(temporary, "w") as archive, source.open("rb") as stream:
            with archive.open(info, "w") as member:
                shutil.copyfileobj(stream, member, 1024 * 1024)

    return _atomically(target, write)


def tar_gz_file(source: Path, target: Path, *, modified: str) -> Path:
    """*target*: a gzipped tar holding *source* under its own name, executable.

    The bit is forced rather than copied: a workflow artifact loses file modes
    on the way through upload-artifact, so the executable arrives 0644 here.
    Dated *modified* throughout, for the same reason as :func:`zip_file`.
    """
    epoch = _epoch(modified)

    def executable(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.mode = 0o755
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = epoch
        return info

    def write(temporary: Path) -> None:
        with temporary.open("wb") as stream:
            with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    archive.add(source, arcname=source.name, filter=executable)

    return _atomically(target, write)


def git_source_archive(
    project: Path,
    tag: str,
    prefix: str,
    target: Path,
    runner: Runner = _subprocess_runner,
) -> Path:
    """*target*: the tree at *tag*, every path under *prefix*/, as gzipped tar.

    This is the corresponding source a copyleft licence asks to be offered
    next to the binary: the tagged tree holds the licence, the pinned
    requirements and the workflow that built it. What is left out - test
    data, say - is the checkout's .gitattributes export-ignore, not the tag's,
    so publishing an older tag from a newer checkout leaves out the same.
    """
    try:
        _run(runner, ["git", "-C", str(project), "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}"])
    except DownloadsError as exc:
        raise DownloadsError(
            f"tag {tag} is not in the checkout; fetch it (actions/checkout fetches the pushed"
            f" tag, a deeper history needs fetch-depth: 0): {exc}"
        ) from exc
    target.parent.mkdir(parents=True, exist_ok=True)
    _run(
        runner,
        [
            "git", "-C", str(project), "archive", "--format=tar.gz", "--worktree-attributes",
            f"--prefix={prefix}/", "-o", str(target), tag,
        ],
    )
    return target
