import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from tapio_build_tools.archive import ArchiveError
from tapio_build_tools.archive.publish import names, publish_archive
from tests.archive_support import ACTIONS, COMMIT, TAG_PUSH, FakeDocker, write_archive_project
from tests.downloads_support import RELEASED, FakeRunner


RUN_ID = f"run-42-sha-{COMMIT[:12]}"
BUILDER = f"ghcr.io/example-org/gadget-builder:sha-{COMMIT}"


class NamesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = write_archive_project(Path(self.temporary.name))

    def test_a_tag_push_is_a_release_of_its_tag(self) -> None:
        chosen = names(self.config, environ=TAG_PUSH)
        self.assertEqual((chosen.archive_id, chosen.release_tag), ("v1.2.0", "v1.2.0"))
        self.assertEqual(chosen.builder_repository, "ghcr.io/example-org/gadget-builder")
        self.assertEqual(chosen.builder_image, BUILDER)

    def test_a_push_is_archived_by_run_and_commit(self) -> None:
        chosen = names(self.config, environ=ACTIONS)
        self.assertEqual((chosen.archive_id, chosen.release_tag), (RUN_ID, ""))

    def test_a_manual_run_is_a_release_when_given_a_tag(self) -> None:
        chosen = names(self.config, release_tag="v1.3.0", environ=ACTIONS)
        self.assertEqual((chosen.archive_id, chosen.release_tag), ("v1.3.0", "v1.3.0"))
        self.assertEqual(names(self.config, release_tag="v9.9.9", environ=TAG_PUSH).archive_id, "v1.2.0")

    def test_outside_actions_a_tag_is_required(self) -> None:
        with self.assertRaisesRegex(ArchiveError, "--release-tag is required outside GitHub Actions"):
            names(self.config, commit=COMMIT, environ={})
        local = names(self.config, release_tag="v0.0.0-test", commit=COMMIT, environ={})
        self.assertEqual(local.builder_image, f"gadget-builder:sha-{COMMIT}")

    def test_an_id_must_be_one_path_segment(self) -> None:
        with self.assertRaisesRegex(ArchiveError, "cannot name an archive"):
            names(self.config, release_tag="v1/2", environ=ACTIONS)

    def test_lines_are_ready_for_github_output(self) -> None:
        self.assertEqual(
            names(self.config, environ=TAG_PUSH).lines(),
            "slug=gadget\narchive-id=v1.2.0\nrelease-tag=v1.2.0\n"
            "builder-repository=ghcr.io/example-org/gadget-builder\n"
            f"builder-image={BUILDER}\n",
        )


class PublishArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = write_archive_project(self.root)
        self.output = self.root / "out"

    def publish(self, runner=None, docker=None, **overrides):
        options = {
            "output_dir": self.output,
            "builder_image": BUILDER,
            "bucket": "bucket",
            "created": RELEASED,
            "environ": ACTIONS,
            "runner": runner or FakeRunner(),
            "popen": docker or FakeDocker(),
        }
        options.update(overrides)
        return publish_archive(self.config, **options)

    def test_a_build_that_is_not_a_release_leaves_the_image_out(self) -> None:
        runner, docker = FakeRunner(), FakeDocker()
        summary = self.publish(runner, docker)
        prefix = f"gadget/{RUN_ID}"
        self.assertEqual(
            runner.uploaded_keys(),
            [f"{prefix}/firmware.hex", f"{prefix}/build.json", f"{prefix}/gadget_firmware-{RUN_ID}.zip", f"{prefix}/SHA256SUMS"],
        )
        self.assertEqual(docker.commands, [])
        self.assertIsNone(summary.builder)
        self.assertTrue(summary.uploaded)
        self.assertEqual(summary.release_tag, "")

    def test_a_release_keeps_its_builder_image_beside_it(self) -> None:
        runner, docker = FakeRunner(), FakeDocker(b"layers")
        summary = self.publish(runner, docker, environ=TAG_PUSH)
        self.assertEqual(
            runner.uploaded_keys(),
            [
                "gadget/v1.2.0/firmware.hex",
                "gadget/v1.2.0/build.json",
                "gadget/v1.2.0/gadget_firmware-v1.2.0.zip",
                "gadget/v1.2.0/gadget-v1.2.0-builder.tar.gz",
                "gadget/v1.2.0/SHA256SUMS",
            ],
        )
        self.assertEqual(docker.commands, [["docker", "save", BUILDER]])
        self.assertEqual(gzip.decompress(runner.objects["gadget/v1.2.0/gadget-v1.2.0-builder.tar.gz"]), b"layers")
        self.assertEqual(Path(summary.builder).name, "gadget-v1.2.0-builder.tar.gz")

    def test_the_files_are_summed_bundled_and_described(self) -> None:
        runner = FakeRunner()
        summary = self.publish(runner, environ=TAG_PUSH)
        objects = {key.rsplit("/", 1)[1]: data for key, data in runner.objects.items()}
        self.assertEqual(
            json.loads(objects["build.json"]),
            {"commit": COMMIT, "builder_image": BUILDER, "workflow_run": "9001", "archive_id": "v1.2.0"},
        )
        with zipfile.ZipFile(summary.zip) as bundle:
            self.assertEqual(bundle.namelist(), ["firmware.hex", "build.json"])
            self.assertEqual(bundle.read("firmware.hex"), b":00000001FF\n")
        sums = objects["SHA256SUMS"].decode().splitlines()
        self.assertEqual(
            [line.split("  ")[1] for line in sums],
            ["firmware.hex", "build.json", "gadget_firmware-v1.2.0.zip", "gadget-v1.2.0-builder.tar.gz"],
        )
        for line in sums:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256(objects[name]).hexdigest(), digest)
        self.assertEqual([item["file"] for item in summary.files][-1], "SHA256SUMS")
        written = json.loads((self.output / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual((written["prefix"], written["release_tag"]), ("gadget/v1.2.0", "v1.2.0"))

    def test_uploads_state_their_types_and_stay_private(self) -> None:
        runner = FakeRunner()
        self.publish(runner, environ=TAG_PUSH, aws_region="eu-north-1")
        types = {}
        for command in runner.uploads():
            types[command[4].rsplit("/", 1)[1]] = command[command.index("--content-type") + 1]
            self.assertEqual(command[command.index("--cache-control") + 1], "private, max-age=31536000, immutable")
            self.assertNotIn("--object-lock-mode", command)
            self.assertEqual(command[-2:], ["--region", "eu-north-1"])
        self.assertEqual(
            types,
            {
                "firmware.hex": "application/octet-stream",
                "build.json": "application/json; charset=utf-8",
                "gadget_firmware-v1.2.0.zip": "application/zip",
                "gadget-v1.2.0-builder.tar.gz": "application/gzip",
                "SHA256SUMS": "text/plain; charset=utf-8",
            },
        )

    def test_retention_locks_every_upload(self) -> None:
        runner = FakeRunner()
        self.publish(runner, retention_days=365)
        for command in runner.uploads():
            lock = command.index("--object-lock-mode")
            self.assertEqual(command[lock + 1 : lock + 3], ["GOVERNANCE", "--object-lock-retain-until-date"])
            self.assertRegex(command[lock + 3], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        with self.assertRaisesRegex(ArchiveError, "--retention-days must be"):
            self.publish(retention_days=0)

    def test_without_a_bucket_the_archive_is_only_written(self) -> None:
        runner = FakeRunner()
        summary = self.publish(runner, bucket=None)
        self.assertEqual(runner.commands, [])
        self.assertFalse(summary.uploaded)
        self.assertTrue(Path(summary.zip).is_file())
        self.assertTrue(Path(summary.sums).is_file())
        self.assertFalse((self.output / "aws-commands.txt").exists())

    def test_a_dry_run_lists_the_uploads_and_runs_none(self) -> None:
        runner = FakeRunner()
        summary = self.publish(runner, dry_run=True)
        self.assertEqual(runner.commands, [])
        self.assertFalse(summary.uploaded)
        commands = (self.output / "aws-commands.txt").read_text(encoding="utf-8")
        self.assertEqual(commands.count("# dry run: aws s3 cp"), 4)

    def test_what_the_build_prepared_must_be_there_and_distinct(self) -> None:
        cases = [
            ('files = ["dist/package/*"]', 'files = ["dist/package/*.bin"]', r"archive.files\[0\] dist/package/\*.bin matched nothing"),
            ('files = ["dist/package/*"]', 'files = ["dist/package/*", "dist/other/*"]', "would share one name in the archive"),
            ('files = ["dist/package/*"]', 'files = ["dist/package/*", "dist/extra/build.json"]', "has a name the archive writes itself"),
        ]
        (self.root / "dist" / "other").mkdir()
        (self.root / "dist" / "other" / "firmware.hex").write_text("again\n", encoding="utf-8")
        (self.root / "dist" / "extra").mkdir()
        (self.root / "dist" / "extra" / "build.json").write_text("{}\n", encoding="utf-8")
        for old, new, message in cases:
            with self.subTest(message=message):
                config_text = (self.root / "build-tooling.toml").read_text(encoding="utf-8")
                self.config = write_archive_project(self.root, config_text.replace(old, new))
                runner = FakeRunner()
                with self.assertRaisesRegex(ArchiveError, message):
                    self.publish(runner)
                self.assertEqual(runner.commands, [])
                self.config = write_archive_project(self.root)

    def test_a_pattern_matching_one_file_twice_archives_it_once(self) -> None:
        self.config = write_archive_project(
            self.root, (self.root / "build-tooling.toml").read_text(encoding="utf-8").replace(
                'files = ["dist/package/*"]', 'files = ["dist/package/*", "dist/package/firmware.hex"]'
            )
        )
        runner = FakeRunner()
        self.publish(runner)
        self.assertEqual(sum(key.endswith("/firmware.hex") for key in runner.uploaded_keys()), 1)

    def test_a_failed_image_save_uploads_nothing(self) -> None:
        runner = FakeRunner()
        with self.assertRaisesRegex(ArchiveError, "docker save .* failed: no such image"):
            self.publish(runner, FakeDocker(returncode=1, stderr=b"no such image"), environ=TAG_PUSH)
        self.assertEqual(runner.commands, [])


if __name__ == "__main__":
    unittest.main()
