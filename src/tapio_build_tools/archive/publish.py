"""Archiving one build of a product in a private bucket.

The bucket is laid out one prefix per build, the same shape as a download
site's::

    <slug>/<archive-id>/<file>                            each file the pipeline prepared
    <slug>/<archive-id>/build.json                        what built it
    <slug>/<archive-id>/<zip>                             the files and build.json together
    <slug>/<archive-id>/<slug>-<archive-id>-builder.tar.gz   a release's builder image
    <slug>/<archive-id>/SHA256SUMS                        every file above

The archive ID is the release tag, or ``run-<number>-sha-<commit>`` for a
build that is not a release. The pipeline decides what goes in; the tooling
only names, bundles, sums and uploads it. SHA256SUMS goes up last, so an
archive that has one is whole.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import glob
import gzip
import json
import os
from pathlib import Path
import re
import shutil
from string import Template
import subprocess

from tapio_build_tools.archive import ArchiveError
from tapio_build_tools.config import VERSION_PLACEHOLDER, Archive, Config
from tapio_build_tools.downloads.package import Runner, _atomically, _subprocess_runner, zip_files
from tapio_build_tools.downloads.publish import S3Client
from tapio_build_tools.evidence import git_commit, sha256_file, utc_now


BUILD_FILE = "build.json"
SUMS_FILE = "SHA256SUMS"
# Nothing under a build's prefix is ever rewritten, and nothing in the bucket
# is for a shared cache.
CACHE_PRIVATE = "private, max-age=31536000, immutable"
ARCHIVE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
REGISTRY = "ghcr.io"

Popen = Callable[..., subprocess.Popen]


@dataclass(frozen=True)
class Names:
    """What one build is called, in the bucket and in the registry."""

    slug: str
    archive_id: str
    release_tag: str
    builder_repository: str
    builder_image: str

    def lines(self) -> str:
        """``key=value`` lines, ready for $GITHUB_OUTPUT."""
        return "".join(f"{key.replace('_', '-')}={value}\n" for key, value in asdict(self).items())


@dataclass
class ArchiveSummary:
    slug: str
    archive_id: str
    release_tag: str
    prefix: str
    uploaded: bool
    zip: str
    sums: str
    builder: str | None
    files: list[dict] = field(default_factory=list)


def names(
    config: Config,
    *,
    release_tag: str | None = None,
    commit: str | None = None,
    environ: Mapping[str, str] = os.environ,
) -> Names:
    """The archive ID, release tag and builder image of this build.

    A tag push is a release of that tag. Any other run is a release only when
    *release_tag* says so; otherwise its ID is the run number and commit.
    """
    archive = config.require_archive()
    commit = commit or environ.get("GITHUB_SHA") or git_commit(config.project)
    ref = environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/"):
        tag = environ.get("GITHUB_REF_NAME") or ref.removeprefix("refs/tags/")
    else:
        tag = release_tag or ""
    if tag:
        archive_id = tag
    elif run_number := environ.get("GITHUB_RUN_NUMBER"):
        archive_id = f"run-{run_number}-sha-{commit[:12]}"
    else:
        raise ArchiveError("--release-tag is required outside GitHub Actions")
    if not ARCHIVE_ID_PATTERN.match(archive_id):
        raise ArchiveError(f"{archive_id} cannot name an archive: use letters, digits, dots, hyphens and underscores")

    owner = environ.get("GITHUB_REPOSITORY_OWNER", "").lower()
    repository = f"{REGISTRY}/{owner}/{archive.slug}-builder" if owner else f"{archive.slug}-builder"
    return Names(
        slug=archive.slug,
        archive_id=archive_id,
        release_tag=tag,
        builder_repository=repository,
        builder_image=f"{repository}:sha-{commit}",
    )


def _prepared_files(project: Path, archive: Archive) -> list[Path]:
    """Every file the configured patterns match, each once, in pattern order."""
    found: list[Path] = []
    for index, pattern in enumerate(archive.files):
        matches = sorted(match for match in glob.glob(pattern, root_dir=project) if (project / match).is_file())
        if not matches:
            raise ArchiveError(f"archive.files[{index}] {pattern} matched nothing; the build prepares these files")
        for match in matches:
            path = project / match
            if path not in found:
                found.append(path)
    by_name: dict[str, Path] = {}
    for path in found:
        if path.name in by_name:
            raise ArchiveError(
                f"{by_name[path.name].relative_to(project)} and {path.relative_to(project)}"
                " would share one name in the archive"
            )
        by_name[path.name] = path
    return found


def _docker_save(image: str, target: Path, popen: Popen = subprocess.Popen) -> Path:
    """*target*: ``docker save`` of *image*, gzipped, without holding it in memory."""

    def write(temporary: Path) -> None:
        try:
            process = popen(["docker", "save", image], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError as exc:
            raise ArchiveError("docker is not installed") from exc
        with process:
            with temporary.open("wb") as stream:
                with gzip.GzipFile(filename="", mode="wb", fileobj=stream, compresslevel=9, mtime=0) as compressed:
                    shutil.copyfileobj(process.stdout, compressed, 1024 * 1024)
            detail = process.stderr.read()
        if process.returncode != 0:
            message = detail.decode(errors="replace").strip() if isinstance(detail, bytes) else str(detail or "")
            raise ArchiveError(f"docker save {image} failed: {message or process.returncode}")

    return _atomically(target, write)


def _retain_until(days: int, now: datetime | None = None) -> str:
    moment = (now or datetime.now(timezone.utc)) + timedelta(days=days)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def publish_archive(
    config: Config,
    *,
    output_dir: Path,
    release_tag: str | None = None,
    builder_image: str | None = None,
    bucket: str | None = None,
    aws_region: str | None = None,
    retention_days: int | None = None,
    dry_run: bool = False,
    commit: str | None = None,
    created: str | None = None,
    environ: Mapping[str, str] = os.environ,
    runner: Runner = _subprocess_runner,
    popen: Popen = subprocess.Popen,
) -> ArchiveSummary:
    """Bundle the prepared files of this build and, given a bucket, upload them.

    Without a bucket the archive is only written to *output_dir* - a pull
    request's build, say, which is kept as a workflow artifact and no more.
    """
    archive = config.require_archive()
    if retention_days is not None and retention_days < 1:
        raise ArchiveError("--retention-days must be a whole number of days, 1 or more")
    commit = commit or environ.get("GITHUB_SHA") or git_commit(config.project)
    chosen = names(config, release_tag=release_tag, commit=commit, environ=environ)
    created = created or utc_now()
    archive_id = chosen.archive_id

    zip_name = Template(archive.zip).substitute({VERSION_PLACEHOLDER: archive_id})
    builder_name = f"{archive.slug}-{archive_id}-builder.tar.gz"
    sources = _prepared_files(config.project, archive)
    reserved = {BUILD_FILE, SUMS_FILE, zip_name, builder_name}
    for source in sources:
        if source.name in reserved:
            raise ArchiveError(f"{source.relative_to(config.project)} has a name the archive writes itself")

    prefix = f"{archive.slug}/{archive_id}"
    target_dir = output_dir / prefix
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True)

    files = [shutil.copyfile(source, target_dir / source.name) for source in sources]
    build = {"commit": commit}
    if builder_image:
        build["builder_image"] = builder_image
    if run_id := environ.get("GITHUB_RUN_ID"):
        build["workflow_run"] = run_id
    build["archive_id"] = archive_id
    build_file = target_dir / BUILD_FILE
    build_file.write_text(json.dumps(build, indent=2) + "\n", encoding="utf-8")
    zip_path = zip_files([*files, build_file], target_dir / zip_name, modified=created)
    uploads = [*files, build_file, zip_path]

    # The image a release was built in is kept with it, so the release can be
    # rebuilt byte for byte long after the registry has moved on. A build
    # that is not a release is not worth the space.
    builder: Path | None = None
    if chosen.release_tag and builder_image:
        builder = _docker_save(builder_image, target_dir / builder_name, popen)
        uploads.append(builder)

    digests = {path: sha256_file(path) for path in uploads}
    sums = target_dir / SUMS_FILE
    sums.write_text("".join(f"{digests[path]}  {path.name}\n" for path in uploads), encoding="utf-8")
    digests[sums] = sha256_file(sums)
    uploads.append(sums)

    if bucket:
        client = S3Client(bucket, runner=runner, region=aws_region, dry_run=dry_run)
        retain = _retain_until(retention_days) if retention_days else None
        for path in uploads:
            client.put(path, f"{prefix}/{path.name}", CACHE_PRIVATE, retain_until=retain)
        (output_dir / "aws-commands.txt").write_text("\n".join(client.commands) + "\n", encoding="utf-8")

    summary = ArchiveSummary(
        slug=archive.slug,
        archive_id=archive_id,
        release_tag=chosen.release_tag,
        prefix=prefix,
        uploaded=bool(bucket) and not dry_run,
        zip=str(zip_path),
        sums=str(sums),
        builder=str(builder) if builder else None,
        files=[
            {"file": path.name, "key": f"{prefix}/{path.name}", "size": path.stat().st_size, "sha256": digests[path]}
            for path in uploads
        ],
    )
    (output_dir / "summary.json").write_text(json.dumps(asdict(summary), indent=2) + "\n", encoding="utf-8")
    return summary
