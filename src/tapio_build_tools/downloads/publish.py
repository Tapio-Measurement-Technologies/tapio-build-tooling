"""Publishing one release of every configured program to the bucket.

The bucket is laid out one prefix per program::

    <slug>/index.html               the permanent page; offers the latest release
    <slug>/versions/index.html      every release, newest first
    <slug>/releases.json            the manifest the pages are written from
    <slug>/<version>/index.html     the page for one release
    <slug>/<version>/<files>        the release's files; never rewritten

Files are uploaded before the pages that offer them, and the manifest before
the pages that list it, so a visitor never follows a link to something that
is not there yet. The permanent page is the last thing written, and only by
a release that is the newest.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import json
from pathlib import Path
import shutil
import subprocess

from tapio_build_tools.config import Config, DownloadProgram
from tapio_build_tools.downloads import DownloadsError
from tapio_build_tools.downloads.manifest import (
    Asset,
    Manifest,
    Release,
    dump_manifest,
    empty_manifest,
    latest,
    load_manifest,
    merge_release,
)
from tapio_build_tools.downloads.package import (
    Runner,
    _subprocess_runner,
    content_type,
    git_source_archive,
    resolve_glob,
    tar_gz_file,
    zip_file,
)
from tapio_build_tools.downloads.render import Page, render_program_pages, render_root_page
from tapio_build_tools.downloads.versions import is_prerelease, parse_version
from tapio_build_tools.evidence import git_commit, sha256_file, utc_now


# A release's files carry their version in the name and are never rewritten,
# so a browser or proxy may keep them for good. The pages and the manifest
# change with every release, so a browser must ask again each time.
CACHE_FOREVER = "public, max-age=31536000, immutable"
CACHE_ASK_AGAIN = "no-cache"
MANIFEST_FILE = "releases.json"


class S3Client:
    """The few things the publisher does to a bucket, through the aws CLI.

    Every command is recorded; with *dry_run* the writes are only recorded.
    """

    def __init__(
        self,
        bucket: str,
        *,
        runner: Runner = _subprocess_runner,
        region: str | None = None,
        dry_run: bool = False,
    ) -> None:
        self.bucket = bucket
        self.runner = runner
        self.region = region
        self.dry_run = dry_run
        self.commands: list[str] = []

    def _run(self, args: list[str], *, write: bool) -> subprocess.CompletedProcess | None:
        if self.region:
            args = [*args, "--region", self.region]
        command = ["aws", *args]
        self.commands.append(("# dry run: " if write and self.dry_run else "") + " ".join(command))
        if write and self.dry_run:
            return None
        try:
            return self.runner(command)
        except FileNotFoundError as exc:
            raise DownloadsError("the aws CLI is not installed") from exc

    def get(self, key: str, destination: Path) -> bool:
        """Fetch *key* to *destination*; False when there is no such object."""
        try:
            self._run(["s3", "cp", f"s3://{self.bucket}/{key}", str(destination)], write=False)
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr if isinstance(exc.stderr, str) else ""
            if "(404)" in detail or "Not Found" in detail or "does not exist" in detail:
                return False
            raise DownloadsError(f"fetching s3://{self.bucket}/{key} failed: {detail.strip() or exc}") from exc
        return True

    def put(self, path: Path, key: str, cache_control: str) -> None:
        args = [
            "s3", "cp", str(path), f"s3://{self.bucket}/{key}",
            "--content-type", content_type(key),
            "--cache-control", cache_control,
        ]
        try:
            self._run(args, write=True)
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr if isinstance(exc.stderr, str) else ""
            raise DownloadsError(f"uploading {key} failed: {detail.strip() or exc}") from exc

    def list_prefixes(self) -> list[str]:
        """The top-level prefixes of the bucket, one per program published."""
        try:
            result = self._run(
                [
                    "s3api", "list-objects-v2", "--bucket", self.bucket, "--delimiter", "/",
                    "--query", "CommonPrefixes[].Prefix", "--output", "json",
                ],
                write=False,
            )
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr if isinstance(exc.stderr, str) else ""
            raise DownloadsError(f"listing s3://{self.bucket} failed: {detail.strip() or exc}") from exc
        assert result is not None
        prefixes = json.loads(result.stdout or "null") or []
        return [prefix.rstrip("/") for prefix in prefixes]


@dataclass
class ProgramResult:
    id: str
    slug: str
    latest: bool
    page_url: str
    version_url: str
    assets: list[dict] = field(default_factory=list)


@dataclass
class Summary:
    version: str
    prerelease: bool
    latest: bool
    page_urls: list[str]
    programs: dict[str, ProgramResult]


def _asset_name(program: DownloadProgram, version: str, os_name: str, arch: str) -> str:
    return f"{program.slug}-{version}-{os_name}-{arch}"


def _copy(source: Path, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    return target


def _package_release(
    config: Config,
    program: DownloadProgram,
    version: str,
    base_url: str,
    output_dir: Path,
    *,
    released: str,
    commit: str,
    runner: Runner,
) -> Release:
    prefix = f"{program.slug}/{version}"
    target_dir = output_dir / program.slug / version
    files: list[tuple[str, Path, str | None, str | None]] = []

    for asset in program.assets:
        source = resolve_glob(config.project, asset.glob, version)
        stem = _asset_name(program, version, asset.os, asset.arch)
        if asset.archive == "zip":
            packaged = zip_file(source, target_dir / f"{stem}.zip", modified=released)
        elif asset.archive == "tar.gz":
            packaged = tar_gz_file(source, target_dir / f"{stem}.tar.gz", modified=released)
        else:
            packaged = _copy(source, target_dir / f"{stem}{source.suffix}")
        files.append(("binary", packaged, asset.os, asset.arch))
        if asset.sbom is not None:
            sbom = resolve_glob(config.project, asset.sbom, version)
            files.append(("sbom", _copy(sbom, target_dir / f"{stem}.cdx.json"), asset.os, asset.arch))

    if program.source_package:
        archive = git_source_archive(
            config.project,
            version,
            f"{program.slug}-{version}",
            target_dir / f"{program.slug}-{version}-source.tar.gz",
            runner,
        )
        files.append(("source", archive, None, None))

    assets = tuple(
        Asset(
            kind=kind,
            file=path.name,
            key=f"{prefix}/{path.name}",
            url=f"{base_url}/{prefix}/{path.name}",
            size=path.stat().st_size,
            sha256=sha256_file(path),
            os=os_name,
            arch=arch,
        )
        for kind, path, os_name, arch in files
    )
    return Release(version=version, released=released, commit=commit, assets=assets)


def _current_manifest(
    program: DownloadProgram,
    client: S3Client | None,
    existing: Path | None,
    scratch: Path,
    generated: str,
) -> Manifest:
    if existing is not None:
        text = existing.read_text(encoding="utf-8") if existing.exists() else ""
    else:
        assert client is not None
        fetched = scratch / f"{program.slug}-{MANIFEST_FILE}"
        text = fetched.read_text(encoding="utf-8") if client.get(f"{program.slug}/{MANIFEST_FILE}", fetched) else ""
    if not text.strip():
        return empty_manifest(program, generated)
    manifest = load_manifest(text)
    if manifest.slug != program.slug:
        raise DownloadsError(f"{MANIFEST_FILE} at {program.slug}/ belongs to {manifest.slug}")
    return manifest


def _write_pages(output_dir: Path, pages: list[Page]) -> None:
    for page in pages:
        path = output_dir / page.key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(page.html, encoding="utf-8")


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _release_notes(summary: Summary, config: Config, manifests: dict[str, Manifest]) -> str:
    lines = ["## Downloads", ""]
    for result in summary.programs.values():
        program = config.require_downloads().program(result.id)
        release = manifests[result.id].release(summary.version)
        assert release is not None
        lines.append(f"### {program.name}")
        lines.append("")
        for asset in release.assets:
            lines.append(f"- [{asset.file}]({asset.url})  ")
            lines.append(f"  SHA-256 `{asset.sha256}`")
        lines.append("")
        lines.append(f"Release page: {result.version_url}  ")
        if result.latest:
            lines.append(f"Permanent download page: {result.page_url}")
        else:
            lines.append("A newer release is already published; the permanent download page keeps offering it.")
        lines.append("")
    return "\n".join(lines)


def publish_downloads(
    config: Config,
    *,
    version: str,
    bucket: str,
    base_url: str,
    output_dir: Path,
    programs: list[str] | None = None,
    dry_run: bool = False,
    force: bool = False,
    root_index: bool = False,
    existing_manifest: Path | None = None,
    released: str | None = None,
    commit: str | None = None,
    aws_region: str | None = None,
    runner: Runner = _subprocess_runner,
) -> Summary:
    """Package, record and upload *version* of the chosen programs."""
    downloads = config.require_downloads()
    if is_prerelease(version):
        raise DownloadsError(f"{version} is a pre-release; not published")
    parse_version(version)
    base_url = base_url.rstrip("/")
    chosen = [downloads.program(name) for name in programs] if programs else list(downloads.programs.values())
    released = released or utc_now()
    commit = commit or git_commit(config.project)

    client = S3Client(bucket, runner=runner, region=aws_region, dry_run=dry_run)
    output_dir.mkdir(parents=True, exist_ok=True)
    scratch = output_dir / ".fetched"
    scratch.mkdir(exist_ok=True)

    # Every program is packaged and its manifest merged before anything is
    # uploaded: a configuration that fails on the third program has then
    # changed nothing in the bucket.
    plans: list[tuple[DownloadProgram, Manifest, Release, list[Page]]] = []
    for program in chosen:
        current = _current_manifest(program, client, existing_manifest, scratch, released)
        # A version published before keeps its date, and its files are
        # packaged with that date, so they come out byte for byte the same.
        earlier = current.release(version)
        stamp = earlier.released if earlier is not None else released
        release = _package_release(
            config, program, version, base_url, output_dir, released=stamp, commit=commit, runner=runner
        )
        manifest = replace(merge_release(current, release, force=force), generated=released)
        pages = render_program_pages(program, manifest, config.organization.name, downloads.logo)
        _write_pages(output_dir, pages)
        _write_text(output_dir / program.slug / MANIFEST_FILE, dump_manifest(manifest))
        plans.append((program, manifest, release, pages))

    results: dict[str, ProgramResult] = {}
    manifests: dict[str, Manifest] = {}
    for program, manifest, release, pages in plans:
        newest = latest(manifest)
        assert newest is not None
        is_latest = newest.version == version
        for asset in release.assets:
            client.put(output_dir / asset.key, asset.key, CACHE_FOREVER)
        # Every release's page, not only this one's: the older pages now say
        # a newer version exists.
        version_keys = {f"{program.slug}/{item.version}/index.html" for item in manifest.releases}
        for page in pages:
            if page.key in version_keys:
                client.put(output_dir / page.key, page.key, CACHE_ASK_AGAIN)
        manifest_key = f"{program.slug}/{MANIFEST_FILE}"
        client.put(output_dir / manifest_key, manifest_key, CACHE_ASK_AGAIN)
        versions_key = f"{program.slug}/versions/index.html"
        client.put(output_dir / versions_key, versions_key, CACHE_ASK_AGAIN)
        if is_latest:
            latest_key = f"{program.slug}/index.html"
            client.put(output_dir / latest_key, latest_key, CACHE_ASK_AGAIN)
        results[program.id] = ProgramResult(
            id=program.id,
            slug=program.slug,
            latest=is_latest,
            page_url=f"{base_url}/{program.slug}/index.html",
            version_url=f"{base_url}/{program.slug}/{version}/index.html",
            assets=[{k: v for k, v in asdict(asset).items() if v is not None} for asset in release.assets],
        )
        manifests[program.id] = manifest

    if root_index:
        _publish_root_index(config, client, output_dir, scratch, dict(
            (manifest.slug, manifest) for manifest in manifests.values()
        ))

    summary = Summary(
        version=version,
        prerelease=False,
        latest=all(result.latest for result in results.values()),
        page_urls=[result.page_url for result in results.values()],
        programs=results,
    )
    _write_text(
        output_dir / "summary.json",
        json.dumps(
            {**asdict(summary), "programs": {name: asdict(result) for name, result in results.items()}},
            indent=2,
        ) + "\n",
    )
    _write_text(output_dir / "release-notes.md", _release_notes(summary, config, manifests))
    _write_text(output_dir / "aws-commands.txt", "\n".join(client.commands) + "\n")
    return summary


def _publish_root_index(
    config: Config,
    client: S3Client,
    output_dir: Path,
    scratch: Path,
    known: dict[str, Manifest],
) -> Page:
    """Write the bucket-root page listing every program that has a manifest."""
    for prefix in client.list_prefixes():
        if prefix in known or not prefix:
            continue
        fetched = scratch / f"{prefix}-{MANIFEST_FILE}"
        if client.get(f"{prefix}/{MANIFEST_FILE}", fetched):
            known[prefix] = load_manifest(fetched.read_text(encoding="utf-8"))
    logo = config.downloads.logo if config.downloads is not None else None
    page = render_root_page(list(known.values()), config.organization.name, logo)
    _write_pages(output_dir, [page])
    client.put(output_dir / page.key, page.key, CACHE_ASK_AGAIN)
    return page


def publish_root_index(
    config: Config,
    *,
    bucket: str,
    output_dir: Path,
    dry_run: bool = False,
    aws_region: str | None = None,
    runner: Runner = _subprocess_runner,
) -> Page:
    """The bucket-root page on its own, from whatever the bucket already holds.

    A release role is confined to its program's prefix and cannot write the
    root, so this is run by hand, with credentials that can.
    """
    client = S3Client(bucket, runner=runner, region=aws_region, dry_run=dry_run)
    output_dir.mkdir(parents=True, exist_ok=True)
    scratch = output_dir / ".fetched"
    scratch.mkdir(exist_ok=True)
    page = _publish_root_index(config, client, output_dir, scratch, {})
    _write_text(output_dir / "aws-commands.txt", "\n".join(client.commands) + "\n")
    return page


def render_only(config: Config, *, program_id: str, manifest_path: Path, output_dir: Path) -> list[Page]:
    """Write *program*'s pages from a manifest already published, changing nothing else."""
    downloads = config.require_downloads()
    program = downloads.program(program_id)
    manifest = load_manifest(manifest_path.read_text(encoding="utf-8"))
    if manifest.slug != program.slug:
        raise DownloadsError(f"{manifest_path} belongs to {manifest.slug}, not {program.slug}")
    pages = render_program_pages(program, manifest, config.organization.name, downloads.logo)
    _write_pages(output_dir, pages)
    _write_text(output_dir / program.slug / MANIFEST_FILE, dump_manifest(manifest))
    return pages
