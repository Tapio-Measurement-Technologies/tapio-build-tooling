"""How release versions are read off tags and put in order."""

from __future__ import annotations

from packaging.version import InvalidVersion, Version

from tapio_build_tools.downloads import DownloadsError


def parse_version(tag: str) -> Version:
    """The version a release tag names; a leading ``v`` is convention, not content."""
    try:
        return Version(tag.removeprefix("v"))
    except InvalidVersion as exc:
        raise DownloadsError(f"{tag} is not a version") from exc


def is_prerelease(tag: str) -> bool:
    """A hyphen in the tag - v1.3.0-beta.1 - marks a pre-release.

    That is the rule the release workflows document. Anything the version
    grammar itself calls a pre-release or development version - v1.3.0rc1 -
    counts as well, so a tag cannot slip past by leaving the hyphen out.
    """
    if "-" in tag:
        return True
    version = parse_version(tag)
    return version.is_prerelease or version.is_devrelease
