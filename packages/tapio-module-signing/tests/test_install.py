"""Installing a signed module: checked as the copy that will land, then landed."""

import os
from unittest.mock import patch

import support
from support import PROFILE, SignedModuleFixture
from tapio_module_signing import FileError, SignatureError, VersionError, prepare_install
from tapio_module_signing.install import STAGING_PREFIX


class InstallFixture(SignedModuleFixture):
    def setUp(self):
        super().setUp()
        self.folder = os.path.join(self.tmp, "installed")
        os.makedirs(self.folder)

    def version(self, version, min_app_version=None):
        text = ('id = "com.example.test"\nname = "Test module"\n'
                f'version = "{version}"\nmodule = "mill_export.py"\n')
        if min_app_version:
            text += f'min_app_version = "{min_app_version}"\n'
        self.write("gadget.toml", text)
        return self.build(f"chosen-{version}.tgm")

    def folder_contents(self):
        return sorted(os.listdir(self.folder))


class InstallingAModuleTest(InstallFixture):
    def test_it_is_staged_until_confirmed_then_installed_under_its_id(self):
        pending = prepare_install(self.version("1.0.0"), self.folder, profile=PROFILE)

        self.assertEqual(pending.id, "com.example.test")
        self.assertEqual(pending.name, "Test module")
        self.assertEqual(pending.version, "1.0.0")
        self.assertFalse(pending.is_update)
        [staged] = self.folder_contents()
        self.assertTrue(staged.startswith(STAGING_PREFIX))

        pending.commit()

        self.assertEqual(self.folder_contents(), ["com.example.test.tgm"])

    def test_saying_no_leaves_the_folder_as_it_was(self):
        prepare_install(self.version("1.0.0"), self.folder, profile=PROFILE).discard()

        self.assertEqual(self.folder_contents(), [])

    def test_what_is_installed_is_what_was_checked(self):
        """Changing the chosen file after the check changes nothing installed."""
        chosen = self.version("1.0.0")
        pending = prepare_install(chosen, self.folder, profile=PROFILE)
        with open(chosen, "wb") as handle:
            handle.write(b"replaced after the check")

        pending.commit()

        with open(os.path.join(self.folder, "com.example.test.tgm"), "rb") as handle:
            self.assertNotEqual(handle.read(), b"replaced after the check")

    def test_the_manifest_comes_with_it(self):
        pending = prepare_install(self.version("1.0.0"), self.folder, profile=PROFILE)
        self.addCleanup(pending.discard)

        self.assertEqual(pending.manifest["module"], "mill_export.py")


class ReplacingAnInstalledOneTest(InstallFixture):
    def test_a_new_version_replaces_the_old_whatever_the_old_file_was_called(self):
        prepare_install(self.version("1.0.0"), self.folder, profile=PROFILE).commit()
        os.replace(os.path.join(self.folder, "com.example.test.tgm"),
                   os.path.join(self.folder, "renamed by hand.tgm"))

        pending = prepare_install(self.version("1.1.0"), self.folder, profile=PROFILE)

        self.assertTrue(pending.is_update)
        self.assertFalse(pending.is_reinstall)
        self.assertEqual(pending.replaced_version, "1.0.0")
        pending.commit()
        self.assertEqual(self.folder_contents(), ["com.example.test.tgm"])

    def test_the_same_version_again_is_a_reinstall(self):
        prepare_install(self.version("1.0.0"), self.folder, profile=PROFILE).commit()

        pending = prepare_install(self.version("1.0.0"), self.folder, profile=PROFILE)
        self.addCleanup(pending.discard)

        self.assertTrue(pending.is_reinstall)

    def test_one_this_release_cannot_load_is_still_recognised_and_replaced(self):
        # Installed by a release new enough for it, or by a source run.
        prepare_install(self.version("2.0.0", min_app_version="9.0.0"), self.folder,
                        profile=PROFILE).commit()

        with patch.object(support, "running_version", return_value="v1.0.0"):
            pending = prepare_install(self.version("1.0.0"), self.folder, profile=PROFILE)

        self.assertEqual(pending.replaced_version, "2.0.0")
        pending.commit()
        self.assertEqual(self.folder_contents(), ["com.example.test.tgm"])

    def test_other_files_in_the_folder_are_left_alone(self):
        for name in ("notes.txt", "loose.py", "unsigned.tgm"):
            with open(os.path.join(self.folder, name), "w", encoding="utf-8") as handle:
                handle.write("x")

        prepare_install(self.version("1.0.0"), self.folder, profile=PROFILE).commit()

        self.assertEqual(self.folder_contents(),
                         ["com.example.test.tgm", "loose.py", "notes.txt", "unsigned.tgm"])


class RefusingAFileTest(InstallFixture):
    def assert_refused(self, path, error):
        with self.assertRaises(error) as caught:
            prepare_install(path, self.folder, profile=PROFILE)
        self.assertEqual(self.folder_contents(), [])
        return caught.exception

    def test_one_not_signed_by_a_trusted_key(self):
        tampered = self.rewrite(self.version("1.0.0"), {"signature.json": b"{}"})
        self.assert_refused(tampered, SignatureError)

    def test_a_damaged_file(self):
        damaged = os.path.join(self.tmp, "damaged.tgm")
        with open(damaged, "wb") as handle:
            handle.write(b"not a zip")
        self.assert_refused(damaged, FileError)

    def test_one_for_a_later_release(self):
        with patch.object(support, "running_version", return_value="v1.0.0"):
            error = self.assert_refused(self.version("1.0.0", min_app_version="2.0.0"),
                                        VersionError)
        self.assertEqual(error.required, "2.0.0")

    def test_a_file_far_too_large_to_be_one_is_not_read(self):
        with self.assertRaises(FileError) as caught:
            prepare_install(self.version("1.0.0"), self.folder, profile=PROFILE, max_bytes=10)
        self.assertIn("too large to be a gadget module", str(caught.exception))
        self.assertEqual(self.folder_contents(), [])
