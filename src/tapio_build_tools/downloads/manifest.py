"""The record of what a program has published: ``releases.json``.

The manifest is the source of truth for a program's download pages. Every
publish reads the one in the bucket, adds its release, and writes the pages
from the result, so the pages can always be regenerated and a later release
knows about the earlier ones.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from typing import Any

from tapio_build_tools.config import DownloadProgram
from tapio_build_tools.downloads import DownloadsError
from tapio_build_tools.downloads.versions import parse_version


SCHEMA_VERSION = 1
KINDS = ("binary", "source", "sbom")


@dataclass(frozen=True)
class Asset:
    kind: str
    file: str
    key: str
    url: str
    size: int
    sha256: str
    os: str | None = None
    arch: str | None = None


@dataclass(frozen=True)
class Release:
    version: str
    released: str
    commit: str
    assets: tuple[Asset, ...]

    def binaries(self) -> tuple[Asset, ...]:
        return tuple(asset for asset in self.assets if asset.kind == "binary")

    def source(self) -> Asset | None:
        return next((asset for asset in self.assets if asset.kind == "source"), None)

    def sboms(self) -> tuple[Asset, ...]:
        return tuple(asset for asset in self.assets if asset.kind == "sbom")


@dataclass(frozen=True)
class Manifest:
    slug: str
    name: str
    license_id: str | None
    generated: str
    releases: tuple[Release, ...]

    def release(self, version: str) -> Release | None:
        return next((release for release in self.releases if release.version == version), None)


def empty_manifest(program: DownloadProgram, generated: str) -> Manifest:
    return Manifest(
        slug=program.slug,
        name=program.name,
        license_id=program.product.license_id,
        generated=generated,
        releases=(),
    )


def _sorted(releases: tuple[Release, ...]) -> tuple[Release, ...]:
    return tuple(sorted(releases, key=lambda release: parse_version(release.version), reverse=True))


def latest(manifest: Manifest) -> Release | None:
    """The newest release by version, which is not always the last one published.

    A patch cut for an older line - v1.2.3 after v1.3.0 - is published, but
    it does not become what the permanent page offers.
    """
    if not manifest.releases:
        return None
    return max(manifest.releases, key=lambda release: parse_version(release.version))


def merge_release(manifest: Manifest, release: Release, *, force: bool = False) -> Manifest:
    """*manifest* with *release* in it.

    Publishing the same version twice with the same files is a re-run after
    a failure part-way and is allowed; the original release date stands. The
    same version with different files is a mistake unless *force* says
    otherwise, because somebody may already have the earlier ones.
    """
    existing = manifest.release(release.version)
    if existing is None:
        releases = manifest.releases + (release,)
    else:
        same_files = {(asset.file, asset.sha256) for asset in existing.assets} == {
            (asset.file, asset.sha256) for asset in release.assets
        }
        if not same_files and not force:
            raise DownloadsError(
                f"{release.version} is already published with different files;"
                " pass --force to replace it"
            )
        kept = replace(release, released=existing.released)
        releases = tuple(kept if item.version == release.version else item for item in manifest.releases)
    return replace(manifest, releases=_sorted(releases))


def load_manifest(text: str) -> Manifest:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DownloadsError(f"releases.json is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DownloadsError("releases.json must be an object")
    if data.get("schema-version") != SCHEMA_VERSION:
        raise DownloadsError(f"unsupported releases.json schema-version: {data.get('schema-version')!r}")
    try:
        releases = tuple(
            Release(
                version=item["version"],
                released=item["released"],
                commit=item["commit"],
                assets=tuple(Asset(**asset) for asset in item["assets"]),
            )
            for item in data["releases"]
        )
        manifest = Manifest(
            slug=data["slug"],
            name=data["name"],
            license_id=data.get("license-id"),
            generated=data["generated"],
            releases=_sorted(releases),
        )
    except (KeyError, TypeError) as exc:
        raise DownloadsError(f"releases.json is missing or misnames a field: {exc}") from exc
    for release in manifest.releases:
        for asset in release.assets:
            if asset.kind not in KINDS:
                raise DownloadsError(f"releases.json has an asset of unknown kind: {asset.kind}")
    return manifest


def dump_manifest(manifest: Manifest) -> str:
    def _asset(asset: Asset) -> dict[str, Any]:
        return {key: value for key, value in asdict(asset).items() if value is not None}

    data = {
        "schema-version": SCHEMA_VERSION,
        "slug": manifest.slug,
        "name": manifest.name,
        "license-id": manifest.license_id,
        "generated": manifest.generated,
        "releases": [
            {
                "version": release.version,
                "released": release.released,
                "commit": release.commit,
                "assets": [_asset(asset) for asset in release.assets],
            }
            for release in manifest.releases
        ],
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"
