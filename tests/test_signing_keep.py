import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tapio_build_tools.signing import SigningError
from tapio_build_tools.signing.keep import keep_module, tag_for

COMMIT = "b" * 40


class FakeGh:
    """gh as the keep step sees it: releases by tag, each with its assets."""

    def __init__(self, releases=None, view_error=None) -> None:
        self.releases: dict[str, dict[str, bytes]] = dict(releases or {})
        self.view_error = view_error
        self.commands: list[list[str]] = []
        self.created: list[list[str]] = []
        self.uploaded: list[list[str]] = []

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess:
        self.commands.append(list(args))
        assert args[:2] == ["gh", "release"], args
        return getattr(self, "_" + args[2])(args)

    @staticmethod
    def _done(args, stdout=""):
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    @staticmethod
    def _value(args, flag):
        return args[args.index(flag) + 1]

    def _view(self, args):
        if self.view_error:
            raise subprocess.CalledProcessError(1, args, stderr=self.view_error)
        if args[3] not in self.releases:
            raise subprocess.CalledProcessError(1, args, stderr="release not found")
        return self._done(args, json.dumps(
            {"assets": [{"name": name} for name in self.releases[args[3]]]}))

    def _upload(self, args):
        self.uploaded.append(list(args))
        for path in args[4:args.index("--repo")]:
            self.releases[args[3]][Path(path).name] = Path(path).read_bytes()
        return self._done(args)

    def _download(self, args):
        name = self._value(args, "--pattern")
        Path(self._value(args, "--dir"), name).write_bytes(self.releases[args[3]][name])
        return self._done(args)

    def _create(self, args):
        self.created.append(list(args))
        assets = [arg for arg in args[4:args.index("--repo")]]
        self.releases[args[3]] = {Path(path).name: Path(path).read_bytes() for path in assets}
        return self._done(args)


class KeepTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dist = Path(temporary.name)
        self.signed = self.dist / "export.tpp"
        self.signed.write_bytes(b"signed")
        self.record = self.write_record(manifest_sha256="1" * 64)

    def write_record(self, **changes):
        record = {"id": "export", "version": "1.2.0", "manifest_sha256": "1" * 64,
                  "key_id": "gadget-2026a", "file": "export.tpp",
                  "file_sha256": hashlib.sha256(self.signed.read_bytes()).hexdigest(), **changes}
        path = self.dist / "signing-record.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        return path

    def keep(self, gh, **overrides):
        options = {"record_path": self.record, "files": [self.signed],
                   "tag_prefix": "postprocessor", "kind": "postprocessor",
                   "repository": "example-org/gadget", "target": COMMIT, "runner": gh}
        options.update(overrides)
        return keep_module(**options)

    def test_a_new_version_is_kept_as_a_pre_release_that_is_never_latest(self) -> None:
        gh = FakeGh()
        kept = self.keep(gh)

        self.assertEqual(kept.tag, "postprocessor/export/v1.2.0")
        self.assertTrue(kept.created)
        [create] = gh.created
        self.assertIn("--prerelease", create)
        self.assertIn("--latest=false", create)
        self.assertEqual(create[create.index("--target") + 1], COMMIT)
        self.assertEqual(create[create.index("--title") + 1], "Postprocessor export 1.2.0")
        self.assertEqual(sorted(gh.releases[kept.tag]), ["export.tpp", "signing-record.json"])

    def test_the_same_content_again_changes_nothing(self) -> None:
        gh = FakeGh()
        self.keep(gh)

        kept = self.keep(gh)

        self.assertFalse(kept.created)
        self.assertEqual(len(gh.created), 1)

    def test_different_content_under_a_version_already_issued_is_refused(self) -> None:
        gh = FakeGh()
        self.keep(gh)
        self.record = self.write_record(manifest_sha256="2" * 64)

        with self.assertRaisesRegex(SigningError, "already issued with different content"):
            self.keep(gh)
        self.assertEqual(len(gh.created), 1)

    def test_a_lookup_that_fails_for_another_reason_is_not_taken_for_absence(self) -> None:
        gh = FakeGh(view_error="HTTP 401: Bad credentials")
        with self.assertRaisesRegex(SigningError, "Bad credentials"):
            self.keep(gh)
        self.assertEqual(gh.created, [])

    def test_the_kind_names_the_release(self) -> None:
        gh = FakeGh()
        self.keep(gh, kind="custom analysis module", tag_prefix="custom-module")
        [create] = gh.created
        self.assertEqual(create[3], "custom-module/export/v1.2.0")
        self.assertEqual(create[create.index("--title") + 1], "Custom analysis module export 1.2.0")

    def test_what_cannot_be_part_of_a_tag_is_refused(self) -> None:
        for prefix, record in [
            ("Post Processor", {}), ("../x", {}), ("postprocessor", {"id": "a..b"}),
            ("postprocessor", {"id": "a b"}), ("postprocessor", {"version": "1.0 beta"}),
            ("postprocessor", {"version": ""}),
        ]:
            with self.subTest(prefix=prefix, record=record):
                full = {"id": "export", "version": "1.2.0", **record}
                with self.assertRaises(SigningError):
                    tag_for(full, prefix)

    def test_a_file_that_is_not_the_one_the_record_describes_is_refused(self) -> None:
        """Swapped between the jobs, or another module's: the record would be wrong."""
        self.signed.write_bytes(b"something else")
        with self.assertRaisesRegex(SigningError, "SHA-256 differs"):
            self.keep(FakeGh())
        other = self.dist / "other.tpp"
        other.write_bytes(b"signed")
        with self.assertRaisesRegex(SigningError, "record describes"):
            self.keep(FakeGh(), files=[other])
        with self.assertRaisesRegex(SigningError, "record describes"):
            self.keep(FakeGh(), files=[self.dist / "export.tpp", other])

    def test_a_release_left_without_its_signed_file_is_completed(self) -> None:
        """A run that stopped after the record went up, and before the file did."""
        gh = FakeGh(releases={"postprocessor/export/v1.2.0": {
            "signing-record.json": self.record.read_bytes()}})

        kept = self.keep(gh)

        self.assertTrue(kept.created)
        [upload] = gh.uploaded
        self.assertEqual([Path(arg).name for arg in upload[4:upload.index("--repo")]],
                         ["export.tpp"])
        self.assertEqual(gh.created, [])

    def test_nothing_to_keep_is_an_error(self) -> None:
        with self.assertRaisesRegex(SigningError, "no signed file"):
            self.keep(FakeGh(), files=[])
        with self.assertRaisesRegex(SigningError, "does not exist"):
            self.keep(FakeGh(), files=[self.dist / "missing.tpp"])


if __name__ == "__main__":
    unittest.main()
