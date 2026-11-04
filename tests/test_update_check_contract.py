"""The manifest the publisher writes is the one tapio-update-check reads.

Products ship the reader and the bucket holds what the writer made, so the two
are released apart. Nothing else would notice them drift.
"""

from dataclasses import replace
import unittest

import tapio_update_check
from tapio_build_tools.downloads import manifest as written
from tapio_build_tools.downloads import publish, versions
from tapio_build_tools.downloads.manifest import Asset, Manifest, Release, dump_manifest, latest, merge_release

BASE = "https://downloads.example.com"
SLUG = "demo"


def release(version: str) -> Release:
    return Release(
        version=version,
        released="2026-09-16T10:00:00Z",
        commit="0123abcd",
        assets=(
            Asset(
                kind="binary", os="windows", arch="x86_64",
                file=f"{SLUG}-{version}-windows-x86_64.zip",
                key=f"{SLUG}/{version}/{SLUG}-{version}-windows-x86_64.zip",
                url=f"{BASE}/{SLUG}/{version}/{SLUG}-{version}-windows-x86_64.zip",
                size=10, sha256="aa",
            ),
        ),
        notes="Fixes.",
    )


def published(*tags: str) -> Manifest:
    """A manifest the way publishing builds it: one release at a time."""
    manifest = Manifest(slug=SLUG, name="Demo", license_id=None, generated="2026-09-16T10:00:00Z", releases=())
    for tag in tags:
        manifest = merge_release(manifest, release(tag))
    return manifest


class ReaderMatchesWriterTest(unittest.TestCase):
    def test_both_sides_know_the_same_schema(self) -> None:
        self.assertEqual(tapio_update_check.SCHEMA_VERSION, written.SCHEMA_VERSION)

    def test_the_reader_finds_the_release_the_writer_calls_latest(self) -> None:
        # Published out of order, with a patch for an older line last.
        manifest = published("v1.6.3", "v1.6.10", "v1.7.0", "v1.6.11")
        payload = dump_manifest(manifest).encode("utf-8")
        self.assertEqual(latest(manifest).version, "v1.7.0")
        self.assertEqual(tapio_update_check.parse_manifest(payload, expected_slug=SLUG), "v1.7.0")

    def test_an_empty_manifest_offers_nothing(self) -> None:
        payload = dump_manifest(published()).encode("utf-8")
        self.assertIsNone(tapio_update_check.parse_manifest(payload, expected_slug=SLUG))

    def test_a_manifest_with_no_license_or_notes_still_reads(self) -> None:
        manifest = published("v1.0.0")
        manifest = replace(manifest, releases=tuple(replace(item, notes=None) for item in manifest.releases))
        payload = dump_manifest(manifest).encode("utf-8")
        self.assertEqual(tapio_update_check.parse_manifest(payload), "v1.0.0")

    def test_every_tag_the_publisher_accepts_reads_as_a_final_release(self) -> None:
        for tag in ["v1.0.0", "v1.6.10", "v2.0", "v10.0.1", "1.2.3", "v1.2.3.post1"]:
            with self.subTest(tag=tag):
                self.assertFalse(versions.is_prerelease(tag))
                version = tapio_update_check.parse_version(tag)
                self.assertIsNotNone(version)
                self.assertFalse(version.is_prerelease)
                self.assertEqual(version, versions.parse_version(tag))

    def test_the_reader_looks_where_the_publisher_writes(self) -> None:
        self.assertEqual(tapio_update_check.MANIFEST_FILE, publish.MANIFEST_FILE)
        self.assertEqual(tapio_update_check.manifest_url(BASE, SLUG), f"{BASE}/{SLUG}/{publish.MANIFEST_FILE}")


if __name__ == "__main__":
    unittest.main()
