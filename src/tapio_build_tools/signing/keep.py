"""Keep a signed module as a pre-release, with the record of what was signed.

Every signature is kept, so that what was issued can be looked up afterwards:
the signed file and its record go into a GitHub release of the product's own
repository, tagged ``<prefix>/<id>/v<version>``. A pre-release, and never
Latest: the product's own releases keep the Latest badge, and a workflow that
announces releases can pass pre-releases by.

One version of a module is one set of bytes. Signing the same content again
finds the release already there and changes nothing; signing different
content under a version already issued is refused, so a file a site holds is
never silently a different one from the file of the same name and version
that was kept.

Run in a job that cannot sign - one that may write to the repository and
holds no signing identity - so that neither job can do the other's part.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import tempfile

from tapio_build_tools.downloads.package import Runner, _subprocess_runner
from tapio_build_tools.evidence import sha256_file
from tapio_build_tools.signing import SigningError

#: What goes into a tag. Kept to what a git ref and a release URL take as is.
#: Matched whole, so a trailing newline is not taken for the end.
_TAG_PREFIX = re.compile(r"[a-z0-9]+(?:[-/][a-z0-9]+)*")
_ID = re.compile(r"[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*")
_VERSION = re.compile(r"[0-9A-Za-z]+(?:[.+-][0-9A-Za-z]+)*")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


@dataclass(frozen=True)
class Kept:
    tag: str
    #: False when the release already held this content and nothing was done.
    created: bool


def _run(runner: Runner, args: list[str], what: str) -> subprocess.CompletedProcess:
    try:
        return runner(args)
    except FileNotFoundError as exc:
        raise SigningError(f"{args[0]} is not installed") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
        raise SigningError(f"{what} failed: {detail or exc}") from exc


def _release_assets(runner: Runner, tag: str, repository: str) -> set[str] | None:
    """The names of the assets the release *tag* holds, or None if there is none."""
    args = ["gh", "release", "view", tag, "--repo", repository, "--json", "assets"]
    try:
        printed = runner(args).stdout
    except FileNotFoundError as exc:
        raise SigningError("gh is not installed") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
        if "not found" in detail.lower():
            return None
        raise SigningError(f"looking up release {tag} failed: {detail or exc}") from exc
    try:
        return {str(asset.get("name")) for asset in json.loads(printed or "{}").get("assets") or []}
    except (ValueError, AttributeError) as exc:
        raise SigningError(f"gh described release {tag} as {printed!r}") from exc


def _record(path: Path) -> dict:
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SigningError(f"{path} is not a signing record: {exc}") from exc
    if not isinstance(record, dict):
        raise SigningError(f"{path} is not a signing record")
    return record


def tag_for(record: dict, tag_prefix: str) -> str:
    """The tag a module's signature is kept under, or why it cannot have one."""
    if not _TAG_PREFIX.fullmatch(tag_prefix):
        raise SigningError(f"tag prefix {tag_prefix!r} is not lowercase words joined by - or /")
    module_id, version = str(record.get("id", "")), str(record.get("version", ""))
    if not _ID.fullmatch(module_id) or ".." in module_id:
        raise SigningError(f"the record's id {module_id!r} cannot be part of a tag")
    if not _VERSION.fullmatch(version):
        raise SigningError(f"the record's version {version!r} cannot be part of a tag")
    return f"{tag_prefix}/{module_id}/v{version}"


def keep_module(
    *,
    record_path: Path,
    files: Sequence[Path],
    tag_prefix: str,
    kind: str,
    repository: str,
    target: str,
    runner: Runner = _subprocess_runner,
) -> Kept:
    """Keep *files* and the record as the pre-release for this module version.

    *kind* names the module in the release title, as the product calls it:
    "postprocessor", "custom analysis module".
    """
    record_path = Path(record_path)
    files = [Path(path) for path in files]
    if not files:
        raise SigningError("no signed file to keep")
    for path in [*files, record_path]:
        if not path.is_file():
            raise SigningError(f"{path} does not exist")
    if not _REPOSITORY.fullmatch(repository):
        raise SigningError(f"{repository!r} is not owner/name")
    if not target:
        raise SigningError("no commit to tag")

    record = _record(record_path)
    tag = tag_for(record, tag_prefix)
    manifest = record.get("manifest_sha256")
    if not isinstance(manifest, str) or not manifest:
        raise SigningError(f"{record_path} names no manifest_sha256")
    # The file kept is the file the record describes: the one signed, as it
    # came out of signing, and nothing beside it.
    if [path.name for path in files] != [record.get("file")]:
        raise SigningError(
            f"the record describes {record.get('file')!r}; given {[path.name for path in files]}")
    if sha256_file(files[0]) != record.get("file_sha256"):
        raise SigningError(f"{files[0]} is not the file the record describes: its SHA-256 differs")

    assets = _release_assets(runner, tag, repository)
    if assets is not None and record_path.name in assets:
        with tempfile.TemporaryDirectory(prefix="tapio-keep-") as work:
            _run(runner, ["gh", "release", "download", tag, "--repo", repository,
                          "--pattern", record_path.name, "--dir", work],
                 f"reading the record kept with {tag}")
            kept = _record(Path(work) / record_path.name)
        if kept.get("manifest_sha256") != manifest:
            raise SigningError(
                f"{tag} was already issued with different content. "
                f"Raise the version in the module's source to sign this one.")
    if assets is not None:
        # A run that stopped part-way through uploading leaves a release
        # missing some of what it should hold; this one puts them there.
        missing = [path for path in [*files, record_path] if path.name not in assets]
        if missing:
            _run(runner, ["gh", "release", "upload", tag, *[str(path) for path in missing],
                          "--repo", repository], f"completing release {tag}")
        return Kept(tag=tag, created=bool(missing))

    title_kind = kind[:1].upper() + kind[1:]
    notes = (f"Signed {kind} {record['id']} {record['version']}.\n\n"
             f"```json\n{json.dumps(record, indent=2, sort_keys=True)}\n```\n")
    with tempfile.TemporaryDirectory(prefix="tapio-keep-") as work:
        notes_path = Path(work) / "notes.md"
        notes_path.write_text(notes, encoding="utf-8")
        _run(runner, [
            "gh", "release", "create", tag, *[str(path) for path in files], str(record_path),
            "--repo", repository, "--target", target,
            "--prerelease", "--latest=false",
            "--title", f"{title_kind} {record['id']} {record['version']}",
            "--notes-file", str(notes_path),
        ], f"creating release {tag}")
    return Kept(tag=tag, created=True)
