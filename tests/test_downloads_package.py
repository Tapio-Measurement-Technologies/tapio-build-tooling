import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
import zipfile

from tapio_build_tools.downloads import DownloadsError
from tapio_build_tools.downloads.package import (
    content_type,
    git_source_archive,
    resolve_glob,
    tar_gz_file,
    zip_file,
)
from tests.downloads_support import RELEASED, FakeRunner


class PackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "dist" / "demo-v1.2.0-linux"
        self.source.parent.mkdir()
        self.source.write_bytes(b"binary" * 1000)
        self.source.chmod(0o644)

    def test_content_types(self) -> None:
        self.assertEqual(content_type("a.zip"), "application/zip")
        self.assertEqual(content_type("a.tar.gz"), "application/gzip")
        self.assertEqual(content_type("a.cdx.json"), "application/vnd.cyclonedx+json")
        self.assertEqual(content_type("releases.json"), "application/json; charset=utf-8")
        self.assertEqual(content_type("demo/index.html"), "text/html; charset=utf-8")
        self.assertEqual(content_type("a.exe"), "application/vnd.microsoft.portable-executable")
        self.assertEqual(content_type("a"), "application/octet-stream")

    def test_a_pattern_must_name_exactly_one_file(self) -> None:
        self.assertEqual(resolve_glob(self.root, "dist/demo-${version}-*", "v1.2.0"), self.source)
        with self.assertRaisesRegex(DownloadsError, "matched nothing"):
            resolve_glob(self.root, "dist/demo-${version}-linux", "v9.9.9")
        (self.root / "dist" / "demo-v1.2.0-windows.exe").write_bytes(b"")
        with self.assertRaisesRegex(DownloadsError, "must match exactly one file; matched dist/demo-v1.2.0-linux, dist/demo-v1.2.0-windows.exe"):
            resolve_glob(self.root, "dist/demo-${version}-*", "v1.2.0")

    def test_zip_holds_the_file_under_its_own_name(self) -> None:
        target = zip_file(self.source, self.root / "out" / "demo.zip", modified=RELEASED)
        with zipfile.ZipFile(target) as archive:
            self.assertEqual(archive.namelist(), ["demo-v1.2.0-linux"])
            self.assertEqual(archive.read("demo-v1.2.0-linux"), self.source.read_bytes())
        self.assertEqual([path.name for path in target.parent.iterdir()], ["demo.zip"])

    def test_tar_forces_the_executable_bit_and_no_owner(self) -> None:
        target = tar_gz_file(self.source, self.root / "out" / "demo.tar.gz", modified=RELEASED)
        with tarfile.open(target) as archive:
            (member,) = archive.getmembers()
        self.assertEqual(member.name, "demo-v1.2.0-linux")
        self.assertEqual(member.mode, 0o755)
        self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, "", ""))

    def test_archives_are_the_same_bytes_whenever_they_are_made(self) -> None:
        """A re-run of a release finds its files unchanged, so it can be a no-op."""
        first_zip = zip_file(self.source, self.root / "a.zip", modified=RELEASED).read_bytes()
        first_tar = tar_gz_file(self.source, self.root / "a.tar.gz", modified=RELEASED).read_bytes()
        later = time.time() + 100
        os.utime(self.source, (later, later))
        self.assertEqual(zip_file(self.source, self.root / "b.zip", modified=RELEASED).read_bytes(), first_zip)
        self.assertEqual(tar_gz_file(self.source, self.root / "b.tar.gz", modified=RELEASED).read_bytes(), first_tar)

    def test_source_archive_asks_git_for_the_tag_under_a_prefix(self) -> None:
        runner = FakeRunner()
        target = git_source_archive(self.root, "v1.2.0", "demo-v1.2.0", self.root / "out" / "src.tar.gz", runner)
        self.assertTrue(target.is_file())
        self.assertEqual(
            runner.commands,
            [
                ["git", "-C", str(self.root), "rev-parse", "--verify", "--quiet", "refs/tags/v1.2.0^{commit}"],
                ["git", "-C", str(self.root), "archive", "--format=tar.gz", "--worktree-attributes", "--prefix=demo-v1.2.0/", "-o", str(target), "v1.2.0"],
            ],
        )

    def test_a_missing_tag_is_explained(self) -> None:
        def runner(args):
            raise subprocess.CalledProcessError(1, args, stderr="")

        with self.assertRaisesRegex(DownloadsError, "tag v9.9.9 is not in the checkout"):
            git_source_archive(self.root, "v9.9.9", "demo-v9.9.9", self.root / "src.tar.gz", runner)

    @unittest.skipIf(shutil.which("git") is None, "git is not installed")
    def test_source_archive_with_real_git(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        (repository / "LICENSE").write_text("GPL\n", encoding="utf-8")
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        for command in (["init", "-q"], ["add", "LICENSE"], ["commit", "-qm", "init"], ["tag", "v1.0.0"]):
            subprocess.run(["git", "-C", str(repository), *command], check=True, env=env, capture_output=True)
        target = git_source_archive(repository, "v1.0.0", "demo-v1.0.0", self.root / "demo-v1.0.0-source.tar.gz")
        with tarfile.open(target) as archive:
            self.assertIn("demo-v1.0.0/LICENSE", archive.getnames())
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        again = git_source_archive(repository, "v1.0.0", "demo-v1.0.0", self.root / "again.tar.gz")
        self.assertEqual(hashlib.sha256(again.read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
