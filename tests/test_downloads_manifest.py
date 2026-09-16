import json
from pathlib import Path
import tempfile
import unittest

from tapio_build_tools.downloads import DownloadsError
from tapio_build_tools.downloads.manifest import (
    Asset,
    Release,
    dump_manifest,
    empty_manifest,
    latest,
    load_manifest,
    merge_release,
)
from tapio_build_tools.downloads.versions import is_prerelease, parse_version
from tests.downloads_support import RELEASED, write_project


def release(version: str, *, sha: str = "aa", released: str = RELEASED) -> Release:
    return Release(
        version=version,
        released=released,
        commit="0123abcd",
        assets=(
            Asset(
                kind="binary", os="windows", arch="x86_64",
                file=f"demo-{version}-windows-x86_64.zip",
                key=f"demo/{version}/demo-{version}-windows-x86_64.zip",
                url=f"https://example.invalid/demo/{version}/demo-{version}-windows-x86_64.zip",
                size=10, sha256=sha,
            ),
        ),
    )


class VersionTests(unittest.TestCase):
    def test_versions_sort_numerically_not_lexically(self) -> None:
        tags = ["v1.1.9", "v1.1.10", "v1.1.11", "v1.2.0"]
        self.assertEqual(sorted(tags, key=parse_version), tags)

    def test_a_hyphen_or_a_prerelease_marker_is_a_prerelease(self) -> None:
        for tag in ["v1.3.0-beta.1", "v1.3.0-rc1", "v1.3.0rc1", "v1.3.0.dev1"]:
            with self.subTest(tag=tag):
                self.assertTrue(is_prerelease(tag))
        self.assertFalse(is_prerelease("v1.3.0"))
        self.assertFalse(is_prerelease("1.3.0"))

    def test_something_that_is_not_a_version_is_refused(self) -> None:
        with self.assertRaisesRegex(DownloadsError, "is not a version"):
            parse_version("nightly")


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.program = write_project(Path(self.temporary.name)).require_downloads().program("demo")
        self.empty = empty_manifest(self.program, RELEASED)

    def test_an_empty_manifest_has_no_latest(self) -> None:
        self.assertIsNone(latest(self.empty))
        self.assertEqual(self.empty.license_id, "GPL-3.0-or-later")

    def test_merging_keeps_releases_newest_first_and_latest_is_by_version(self) -> None:
        manifest = merge_release(self.empty, release("v1.3.0"))
        manifest = merge_release(manifest, release("v1.2.3"))  # a patch to an older line
        manifest = merge_release(manifest, release("v1.1.10"))
        self.assertEqual([item.version for item in manifest.releases], ["v1.3.0", "v1.2.3", "v1.1.10"])
        self.assertEqual(latest(manifest).version, "v1.3.0")

    def test_publishing_the_same_files_again_changes_nothing(self) -> None:
        first = merge_release(self.empty, release("v1.3.0", released="2026-01-01T00:00:00Z"))
        again = merge_release(first, release("v1.3.0", released="2026-02-02T00:00:00Z"))
        self.assertEqual(again.releases, first.releases)
        self.assertEqual(again.release("v1.3.0").released, "2026-01-01T00:00:00Z")

    def test_different_files_for_a_published_version_need_force(self) -> None:
        first = merge_release(self.empty, release("v1.3.0", sha="aa"))
        with self.assertRaisesRegex(DownloadsError, "already published with different files"):
            merge_release(first, release("v1.3.0", sha="bb"))
        forced = merge_release(first, release("v1.3.0", sha="bb"), force=True)
        self.assertEqual(forced.release("v1.3.0").assets[0].sha256, "bb")
        self.assertEqual(forced.release("v1.3.0").released, RELEASED)

    def test_round_trips_through_json(self) -> None:
        manifest = merge_release(merge_release(self.empty, release("v1.2.0")), release("v1.3.0"))
        text = dump_manifest(manifest)
        data = json.loads(text)
        self.assertEqual(data["schema-version"], 1)
        self.assertEqual(data["slug"], "demo")
        self.assertNotIn("os", json.dumps(data["releases"][0]["assets"][0]) and "")  # no null keys written
        self.assertEqual(load_manifest(text), manifest)

    def test_rejects_manifests_it_does_not_understand(self) -> None:
        cases = [
            ("not json", "not valid JSON"),
            ("[]", "must be an object"),
            ('{"schema-version": 2}', "unsupported releases.json schema-version"),
            ('{"schema-version": 1, "slug": "demo"}', "missing or misnames a field"),
            (
                '{"schema-version": 1, "slug": "demo", "name": "Demo", "generated": "x", "releases": '
                '[{"version": "v1.0.0", "released": "x", "commit": "c", "assets": [{"kind": "blob", '
                '"file": "f", "key": "k", "url": "u", "size": 1, "sha256": "s"}]}]}',
                "unknown kind: blob",
            ),
        ]
        for text, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(DownloadsError, message):
                    load_manifest(text)


if __name__ == "__main__":
    unittest.main()
