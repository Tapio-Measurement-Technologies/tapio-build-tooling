import json
from pathlib import Path
import tempfile
import unittest

from tapio_build_tools.config import ConfigError
from tapio_build_tools.downloads import DownloadsError
from tapio_build_tools.downloads.manifest import dump_manifest, load_manifest
from tapio_build_tools.downloads.publish import CACHE_ASK_AGAIN, CACHE_FOREVER, publish_downloads, render_only
from tests.downloads_support import PROPRIETARY_CONFIG, RELEASED, FakeRunner, write_project


class PublishTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = write_project(self.root)
        self.output = self.root / "site"

    def publish(self, runner: FakeRunner, **overrides):
        options = dict(
            version="v1.2.0", bucket="bucket", base_url="https://example.invalid/",
            output_dir=self.output, released=RELEASED, commit="0123abcd", runner=runner,
        )
        options.update(overrides)
        return publish_downloads(self.config, **options)

    def test_uploads_files_then_pages_then_manifest_then_the_permanent_page(self) -> None:
        runner = FakeRunner()
        summary = self.publish(runner)

        self.assertEqual(runner.uploaded_keys(), [
            "demo/v1.2.0/demo-v1.2.0-windows-x86_64.zip",
            "demo/v1.2.0/demo-v1.2.0-windows-x86_64.cdx.json",
            "demo/v1.2.0/demo-v1.2.0-linux-x86_64.tar.gz",
            "demo/v1.2.0/demo-v1.2.0-source.tar.gz",
            "demo/v1.2.0/index.html",
            "demo/releases.json",
            "demo/versions/index.html",
            "demo/index.html",
        ])
        for command in runner.uploads():
            key = command[4]
            headers = command[command.index("--content-type") + 1], command[command.index("--cache-control") + 1]
            if key.endswith(".zip"):
                self.assertEqual(headers, ("application/zip", CACHE_FOREVER))
            elif key.endswith(".tar.gz"):
                self.assertEqual(headers, ("application/gzip", CACHE_FOREVER))
            elif key.endswith(".cdx.json"):
                self.assertEqual(headers, ("application/vnd.cyclonedx+json", CACHE_FOREVER))
            elif key.endswith("releases.json"):
                self.assertEqual(headers, ("application/json; charset=utf-8", CACHE_ASK_AGAIN))
            else:
                self.assertEqual(headers, ("text/html; charset=utf-8", CACHE_ASK_AGAIN))
        self.assertTrue(summary.latest)
        self.assertEqual(summary.page_urls, ["https://example.invalid/demo/index.html"])
        self.assertEqual(summary.programs["demo"].version_url, "https://example.invalid/demo/v1.2.0/index.html")
        # The first fetch found nothing, which is the first release, not an error.
        self.assertIn(["aws", "s3", "cp", "s3://bucket/demo/releases.json", str(self.output / ".fetched" / "demo-releases.json")], runner.commands)

    def test_writes_the_summary_notes_and_command_log(self) -> None:
        runner = FakeRunner()
        self.publish(runner)
        summary = json.loads((self.output / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["version"], "v1.2.0")
        self.assertTrue(summary["latest"])
        self.assertEqual(summary["programs"]["demo"]["slug"], "demo")
        self.assertEqual(len(summary["programs"]["demo"]["assets"]), 4)
        notes = (self.output / "release-notes.md").read_text(encoding="utf-8")
        self.assertIn("### Demo Program", notes)
        self.assertIn("[demo-v1.2.0-source.tar.gz](https://example.invalid/demo/v1.2.0/demo-v1.2.0-source.tar.gz)", notes)
        self.assertIn("Permanent download page: https://example.invalid/demo/index.html", notes)
        self.assertIn("SHA-256 `", notes)
        commands = (self.output / "aws-commands.txt").read_text(encoding="utf-8")
        self.assertEqual(commands.count("aws s3 cp"), 9)
        manifest = load_manifest(runner.objects["demo/releases.json"].decode("utf-8"))
        self.assertEqual(manifest.release("v1.2.0").commit, "0123abcd")
        self.assertEqual(manifest.release("v1.2.0").assets[3].kind, "source")

    def test_a_patch_to_an_older_line_leaves_the_permanent_page_alone(self) -> None:
        first = FakeRunner()
        self.publish(first, version="v1.2.0")
        write_project(self.root, version="v1.3.0")
        self.publish(first, version="v1.3.0")
        write_project(self.root, version="v1.2.1")
        before = first.objects["demo/index.html"]
        summary = self.publish(first, version="v1.2.1")

        self.assertFalse(summary.latest)
        self.assertEqual(first.objects["demo/index.html"], before)
        keys = first.uploaded_keys()[-6:]
        self.assertNotIn("demo/index.html", keys)
        # Every version page is rewritten: the old ones now know about v1.3.0.
        self.assertIn("demo/v1.2.0/index.html", keys)
        self.assertIn("demo/v1.2.1/index.html", keys)
        self.assertIn("demo/v1.3.0/index.html", keys)
        manifest = load_manifest(first.objects["demo/releases.json"].decode("utf-8"))
        self.assertEqual([item.version for item in manifest.releases], ["v1.3.0", "v1.2.1", "v1.2.0"])
        notes = (self.output / "release-notes.md").read_text(encoding="utf-8")
        self.assertIn("A newer release is already published", notes)

    def test_publishing_again_is_harmless_and_different_files_need_force(self) -> None:
        runner = FakeRunner()
        self.publish(runner)
        manifest_before = runner.objects["demo/releases.json"]
        self.publish(runner, released="2026-12-24T00:00:00Z")  # a re-run, later
        self.assertEqual(
            load_manifest(runner.objects["demo/releases.json"].decode("utf-8")).release("v1.2.0").released,
            RELEASED,
        )
        self.assertEqual(json.loads(manifest_before)["releases"], json.loads(runner.objects["demo/releases.json"])["releases"])

        (self.root / "dist" / "demo-v1.2.0-linux").write_bytes(b"rebuilt")
        with self.assertRaisesRegex(DownloadsError, "pass --force"):
            self.publish(runner)
        self.publish(runner, force=True)

    def test_a_prerelease_is_refused_before_anything_happens(self) -> None:
        runner = FakeRunner()
        with self.assertRaisesRegex(DownloadsError, "v1.2.0-beta.1 is a pre-release; not published"):
            self.publish(runner, version="v1.2.0-beta.1")
        self.assertEqual(runner.commands, [])

    def test_a_dry_run_reads_but_never_writes(self) -> None:
        runner = FakeRunner()
        summary = self.publish(runner, dry_run=True)
        self.assertEqual(runner.uploads(), [])
        self.assertEqual(len(runner.commands), 3)  # manifest fetch, git rev-parse, git archive
        self.assertTrue(summary.latest)
        self.assertTrue((self.output / "demo" / "index.html").is_file())
        commands = (self.output / "aws-commands.txt").read_text(encoding="utf-8")
        self.assertEqual(commands.count("# dry run: aws s3 cp"), 8)

    def test_an_existing_manifest_replaces_the_fetch(self) -> None:
        runner = FakeRunner()
        self.publish(runner, existing_manifest=Path("/dev/null"), dry_run=True)
        self.assertEqual([command for command in runner.commands if command[0] == "aws"], [])
        self.publish(runner, existing_manifest=self.output / "demo" / "releases.json", dry_run=True)

    def test_a_fetch_that_fails_for_another_reason_is_an_error(self) -> None:
        runner = FakeRunner(fetch_error="fatal error: An error occurred (403) when calling the HeadObject operation: Forbidden")
        with self.assertRaisesRegex(DownloadsError, "fetching s3://bucket/demo/releases.json failed: .*403"):
            self.publish(runner)
        self.assertEqual(runner.uploads(), [])

    def test_a_manifest_of_another_program_is_refused(self) -> None:
        runner = FakeRunner()
        self.publish(runner)
        foreign = load_manifest(runner.objects["demo/releases.json"].decode("utf-8"))
        runner.objects["demo/releases.json"] = dump_manifest(foreign.__class__(**{**foreign.__dict__, "slug": "other"})).encode()
        with self.assertRaisesRegex(DownloadsError, "belongs to other"):
            self.publish(runner)

    def test_the_region_reaches_every_aws_call(self) -> None:
        runner = FakeRunner()
        self.publish(runner, aws_region="eu-north-1")
        for command in runner.commands:
            if command[0] == "aws":
                self.assertEqual(command[-2:], ["--region", "eu-north-1"])

    def test_the_root_index_gathers_every_program_that_has_a_manifest(self) -> None:
        runner = FakeRunner()
        self.publish(runner)
        other = load_manifest(runner.objects["demo/releases.json"].decode("utf-8"))
        runner.objects["other/releases.json"] = dump_manifest(
            other.__class__(**{**other.__dict__, "slug": "other", "name": "Other Program"})
        ).encode()
        runner.objects["stray/file.txt"] = b""
        self.publish(runner, root_index=True)
        self.assertEqual(runner.uploaded_keys()[-1], "index.html")
        page = runner.objects["index.html"].decode("utf-8")
        self.assertIn('href="demo/index.html">Demo Program</a>', page)
        self.assertIn('href="other/index.html">Other Program</a>', page)
        self.assertNotIn("stray", page)
        self.publish(runner)
        self.assertNotIn("index.html", runner.uploaded_keys()[-8:])

    def test_several_programs_of_one_product_each_get_their_own_prefix(self) -> None:
        self.config = write_project(self.root, PROPRIETARY_CONFIG)
        runner = FakeRunner()
        summary = self.publish(runner, programs=["second", "first"])
        self.assertEqual(sorted(summary.programs), ["first", "second"])
        self.assertEqual(
            summary.page_urls,
            ["https://example.invalid/suite-second/index.html", "https://example.invalid/suite-first/index.html"],
        )
        self.assertIn("suite-first/v1.2.0/suite-first-v1.2.0-windows-x86_64.zip", runner.uploaded_keys())
        self.assertIn("suite-second/releases.json", runner.objects)
        notes = (self.output / "release-notes.md").read_text(encoding="utf-8")
        self.assertIn("### Suite First", notes)
        self.assertIn("### Suite Second", notes)
        with self.assertRaisesRegex(ConfigError, "unknown program 'third'"):
            self.publish(runner, programs=["third"])

    def test_a_failing_program_publishes_nothing_for_any_program(self) -> None:
        self.config = write_project(self.root, PROPRIETARY_CONFIG)
        (self.root / "dist" / "second-v1.2.0-windows.exe").unlink()
        runner = FakeRunner()
        with self.assertRaisesRegex(DownloadsError, "second-v1.2.0-windows.exe must match exactly one file"):
            self.publish(runner)
        self.assertEqual(runner.uploads(), [])

    def test_render_only_rewrites_pages_from_a_manifest(self) -> None:
        runner = FakeRunner()
        self.publish(runner)
        manifest = self.output / "demo" / "releases.json"
        elsewhere = self.root / "again"
        pages = render_only(self.config, program_id="demo", manifest_path=manifest, output_dir=elsewhere)
        self.assertEqual(len(pages), 3)
        self.assertEqual(
            (elsewhere / "demo" / "index.html").read_text(encoding="utf-8"),
            (self.output / "demo" / "index.html").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
