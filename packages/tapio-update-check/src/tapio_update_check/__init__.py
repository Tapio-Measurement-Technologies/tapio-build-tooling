"""Whether a newer release is out: read from the download site's manifest.

``tapio-build downloads publish`` writes, beside each program's download page,
the ``releases.json`` the page is made from. It lists every published release -
pre-releases never among them - by its tag with the leading "v" ("v1.6.5"),
the form a build stamps into the running copy as well. A product that tells
its user about a newer release reads that file and nothing else.

What is here is the part every product shares: where the manifest and the
page are, how to read the manifest, and which release to offer. Fetching it,
asking the user's consent first, and showing the notice belong to the
product, since they depend on its GUI toolkit and its preferences.

Nothing here names a deployment: the site's base URL and the program's slug
are the product's to supply.
"""

from __future__ import annotations

import json
import re

from packaging.version import InvalidVersion, Version

__version__ = "0.1.0"

__all__ = [
    "MANIFEST_FILE",
    "SCHEMA_VERSION",
    "ManifestError",
    "download_page_url",
    "manifest_url",
    "parse_manifest",
    "parse_version",
    "update_to_offer",
]

#: The manifest's version of its own format; one this does not know is refused.
SCHEMA_VERSION = 1

#: What the manifest is called beside a program's download page.
MANIFEST_FILE = "releases.json"

# The same rule the tooling holds a configured slug to: it is a path segment.
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# Longer than any tag a release is cut from. The manifest comes over the
# network, so what it holds is not handed to the version parser unbounded.
_MAX_TAG_LENGTH = 64


class ManifestError(ValueError):
    """The payload is not a manifest this version of the library can read."""


def manifest_url(base_url: str, slug: str) -> str:
    """Where the manifest of the program published under *slug* is."""
    return f"{download_page_url(base_url, slug)}{MANIFEST_FILE}"


def download_page_url(base_url: str, slug: str) -> str:
    """The permanent download page of the program published under *slug*.

    It always offers the newest release, so it is the page to send the user
    to rather than one release's own page.
    """
    if not isinstance(slug, str) or not _SLUG.match(slug):
        raise ValueError(f"not a download slug: {slug!r}")
    base = base_url.rstrip("/")
    if not base.startswith("https://"):
        raise ValueError(f"the download site must be https: {base_url!r}")
    return f"{base}/{slug}/"


def parse_version(tag: object) -> Version | None:
    """A release tag as a comparable version, or None.

    "v1.6.5" and "1.6.5" read alike, and "v1.6.0-beta.1" as the pre-release
    of 1.6.0 it is. Anything else reads as None, which includes the
    "(development version)" of a run from source and the odd early tag such as
    "v1.3.0-test".
    """
    if not isinstance(tag, str) or len(tag) > _MAX_TAG_LENGTH:
        return None
    try:
        return Version(tag.strip())
    except InvalidVersion:
        return None


def parse_manifest(payload: bytes, expected_slug: str | None = None) -> str | None:
    """The tag of the newest final release in a manifest, or None when it lists none.

    Entries that cannot be read are passed over rather than failing the lot,
    and the newest is found by version, not taken from the order the manifest
    lists them in: a patch for an older line is published after the newer
    line's releases.

    With *expected_slug*, a manifest written for any other program is refused,
    so a build pointed at the wrong program's page does not offer that
    program's releases.

    Raises ManifestError when the payload is not a manifest at all.
    """
    try:
        manifest = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"not JSON: {error}") from error
    if not isinstance(manifest, dict):
        raise ManifestError("top level is not an object")
    schema = manifest.get("schema-version")
    if schema != SCHEMA_VERSION:
        raise ManifestError(f"unsupported schema-version {schema!r}")
    if expected_slug is not None and manifest.get("slug") != expected_slug:
        raise ManifestError(f"manifest is for {manifest.get('slug')!r}, not {expected_slug!r}")
    releases = manifest.get("releases")
    if not isinstance(releases, list):
        raise ManifestError("releases is not a list")

    newest: tuple[Version, str] | None = None
    for release in releases:
        if not isinstance(release, dict):
            continue
        tag = release.get("version")
        version = parse_version(tag)
        if version is None or version.is_prerelease:
            continue
        if newest is None or version > newest[0]:
            newest = (version, tag)
    return newest[1] if newest else None


def update_to_offer(latest: str | None, current: str | None, skipped: str | None) -> str | None:
    """The release to offer, or None.

    A release is offered when it is newer than the running version and is not
    the one the user chose to skip, however either was written ("v1.6.6" and
    "1.6.6" are the same release). A running version that cannot be read - a
    run from source among them - is offered nothing.
    """
    latest_version = parse_version(latest)
    current_version = parse_version(current)
    if latest_version is None or current_version is None:
        return None
    if latest_version <= current_version:
        return None
    if parse_version(skipped) == latest_version:
        return None
    return latest
