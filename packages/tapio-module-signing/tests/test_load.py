"""What the loader does with a module once it has verified."""

import os
import shutil
import sys

from support import PROFILE, SignedModuleFixture
import unittest

from tapio_module_signing import FileError, Loader, SignatureError, verify
from tapio_module_signing.testing import generate_key, write_key_file


class LoaderFixture(SignedModuleFixture):
    def setUp(self):
        super().setUp()
        self.loader = Loader(PROFILE)
        self.addCleanup(self.loader.discard)
        self.addCleanup(self.forget_modules)

    @staticmethod
    def forget_modules():
        for name in [key for key in sys.modules
                     if key == PROFILE.package_root or key.startswith(PROFILE.package_root + ".")]:
            del sys.modules[name]

    def module_source(self, module_id, files, module="mill_export.py"):
        source = os.path.join(self.tmp, "src-" + module_id)
        # Fresh each time: a version is exactly the files it is given.
        shutil.rmtree(source, ignore_errors=True)
        os.makedirs(source)
        for name, text in files.items():
            path = os.path.join(source, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
        with open(os.path.join(source, "gadget.toml"), "w", encoding="utf-8") as handle:
            handle.write(f'id = "{module_id}"\nversion = "1.0.0"\nmodule = "{module}"\n')
        return source

    def signed(self, module_id, files, module="mill_export.py", out_name=None):
        source = self.module_source(module_id, files, module)
        return self.build(out_name or f"{module_id}.tgm", source=source)


class LoadingAModuleTest(LoaderFixture):
    def test_it_is_imported_beneath_the_profiles_package(self):
        _verified, module = self.loader.load_file(
            self.signed("com.example.one", {"mill_export.py": "VALUE = 1\n"}))

        self.assertTrue(module.__name__.startswith("gadget_modules.com_example_one_"))
        self.assertTrue(module.__name__.endswith(".mill_export"))
        self.assertIs(sys.modules[module.__name__], module)
        self.assertEqual(module.VALUE, 1)

    def test_two_may_name_their_module_the_same(self):
        _, one = self.loader.load_file(self.signed("one", {"mill_export.py": "VALUE = 1\n"}))
        _, two = self.loader.load_file(self.signed("two", {"mill_export.py": "VALUE = 2\n"}))

        self.assertIsNot(one, two)
        self.assertEqual((one.VALUE, two.VALUE), (1, 2))

    def test_its_module_may_import_a_helper_it_carries(self):
        _, module = self.loader.load_file(self.signed("helped", {
            "helpers.py": "LABEL = 'from the helper'\n",
            "mill_export.py": "from . import helpers\n\nLABEL = helpers.LABEL\n",
        }))

        self.assertEqual(module.LABEL, "from the helper")

    def test_a_helper_is_not_importable_by_its_bare_name(self):
        """What keeps one module's helper from being picked up by another."""
        with self.assertRaises(ModuleNotFoundError):
            self.loader.load_file(self.signed("bare", {
                "unlikely_helper_name.py": "LABEL = 1\n",
                "mill_export.py": "import unlikely_helper_name\n",
            }))

    def test_attributes_are_set_before_its_code_runs(self):
        _, module = self.loader.load_file(
            self.signed("knows", {"mill_export.py": "SEEN_AT_IMPORT = module_id\n"}),
            attributes={"module_id": "knows"})

        self.assertEqual(module.SEEN_AT_IMPORT, "knows")

    def test_only_its_module_is_imported(self):
        """A helper it carries runs only if the module imports it."""
        sentinel = os.path.join(self.tmp, "helper-ran")
        self.loader.load_file(self.signed("quiet", {
            "helpers.py": f"open({sentinel!r}, 'w').close()\n",
            "mill_export.py": "VALUE = 1\n",
        }))

        self.assertFalse(os.path.exists(sentinel))

    def test_a_module_that_raises_while_importing_is_not_left_registered(self):
        with self.assertRaises(RuntimeError):
            self.loader.load_file(self.signed("raises", {
                "mill_export.py": "raise RuntimeError('broken')\n"}))

        self.assertNotIn("gadget_modules.raises.mill_export", sys.modules)

    def test_a_reload_after_an_update_imports_the_new_helper(self):
        """Not the old one still sitting in sys.modules from the first load."""
        files = {"helpers.py": "LABEL = 'one'\n",
                 "mill_export.py": "from . import helpers\n\nLABEL = helpers.LABEL\n"}
        self.loader.load_file(self.signed("updated", files, out_name="first.tgm"))

        self.loader.start_generation()
        files["helpers.py"] = "LABEL = 'two'\n"
        _, module = self.loader.load_file(self.signed("updated", files, out_name="second.tgm"))

        self.assertEqual(module.LABEL, "two")

    def test_it_is_unpacked_outside_the_folder_it_was_installed_in(self):
        path = self.signed("elsewhere", {"mill_export.py": "VALUE = 1\n"})
        _, module = self.loader.load_file(path)

        self.assertFalse(module.__file__.startswith(os.path.dirname(path) + os.sep))
        self.assertTrue(module.__file__.startswith(self.loader.generations[0]))
        self.assertEqual(sorted(os.listdir(self.tmp)).count("mill_export.py"), 0)

    def test_the_verified_archive_is_closed_once_loaded(self):
        verified = verify(self.signed("closed", {"mill_export.py": "VALUE = 1\n"}),
                          profile=PROFILE)
        self.loader.load(verified)

        os.replace(verified.path, verified.path + ".moved")


class PackageNamesTest(unittest.TestCase):
    def test_ids_that_read_the_same_without_punctuation_stay_apart(self):
        from tapio_module_signing.load import package_name

        names = {package_name(module_id) for module_id in ("a.b", "a-b", "a_b", "a.b-c", "a-b.c")}
        self.assertEqual(len(names), 5)
        self.assertEqual(package_name("site_dirt"), "site_dirt")
        for name in names:
            self.assertTrue(name.isidentifier(), name)


class LoadingTwiceTest(LoaderFixture):
    def test_a_second_load_into_the_same_generation_leaves_nothing_of_the_first(self):
        """A helper the new version no longer carries must not still import."""
        self.loader.load_file(self.signed("again", {
            "old_helper.py": "VALUE = 1\n", "mill_export.py": "VALUE = 1\n"}, out_name="one.tgm"))

        with self.assertRaises(ImportError):
            self.loader.load_file(self.signed("again", {
                "mill_export.py": "from . import old_helper\n"}, out_name="two.tgm"))

    def test_bytes_that_no_longer_match_the_manifest_are_not_imported(self):
        """Hashed again as they are written out, not trusted to the zip's CRC."""
        sentinel = os.path.join(self.tmp, "ran")
        verified = verify(self.signed("swapped", {
            "mill_export.py": f"open({sentinel!r}, 'w').close()\n"}), profile=PROFILE)
        verified.manifest["files"]["mill_export.py"] = "sha256:" + "0" * 64

        with self.assertRaises(FileError):
            self.loader.load(verified)
        self.assertFalse(os.path.exists(sentinel))


class ARefusedModuleTest(LoaderFixture):
    def test_it_is_neither_unpacked_nor_run(self):
        sentinel = os.path.join(self.tmp, "forged-ran")
        other = write_key_file(generate_key(), os.path.join(self.tmp, "other.pem"))
        source = self.module_source(
            "forged", {"mill_export.py": f"open({sentinel!r}, 'w').close()\n"})
        out = os.path.join(self.tmp, "forged.tgm")
        from support import KEY_ID, quietly
        quietly(["pack", "--source", source, "--out", out, "--key-id", KEY_ID,
                 "--key-file", other])

        with self.assertRaises(SignatureError):
            self.loader.load_file(out)

        unpacked = [name for root in self.loader.generations
                    for _dir, _subdirs, names in os.walk(root) for name in names]
        self.assertNotIn("mill_export.py", unpacked)
        self.assertFalse(os.path.exists(sentinel))


class GenerationsTest(LoaderFixture):
    def test_old_unpacked_modules_are_cleaned_up(self):
        self.loader.load_file(self.signed("sweep", {"mill_export.py": "VALUE = 1\n"}))
        first = self.loader.generations[0]

        self.loader.start_generation()
        self.loader.start_generation()

        self.assertFalse(os.path.exists(first))
        self.assertEqual(len(self.loader.generations), 2)

    def test_the_list_of_generations_is_kept_not_replaced(self):
        held = self.loader.generations
        self.loader.start_generation()
        self.loader.discard()

        self.assertIs(self.loader.generations, held)
        self.assertEqual(held, [])
