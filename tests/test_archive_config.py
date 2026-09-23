from pathlib import Path
import tempfile
import unittest

from tapio_build_tools.config import ConfigError
from tests.archive_support import ARCHIVE_CONFIG, write_archive_project
from tests.downloads_support import GPL_CONFIG, write_project


class ArchiveConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def load(self, config: str):
        return write_archive_project(self.root, config)

    def test_an_archive_needs_no_ecosystem(self) -> None:
        config = self.load(ARCHIVE_CONFIG)
        archive = config.require_archive()
        self.assertEqual((archive.product.id, archive.slug), ("gadget", "gadget"))
        self.assertEqual(archive.zip, "gadget_firmware-${version}.zip")
        self.assertEqual(archive.files, ("dist/package/*",))
        self.assertIsNone(config.python)
        self.assertIsNone(config.node)

    def test_the_zip_is_named_after_the_slug_by_default(self) -> None:
        config = self.load(ARCHIVE_CONFIG.replace('zip = "gadget_firmware-${version}.zip"\n', ""))
        self.assertEqual(config.require_archive().zip, "gadget-${version}.zip")

    def test_a_config_without_an_archive_still_needs_an_ecosystem(self) -> None:
        without = ARCHIVE_CONFIG.split("[archive]")[0]
        with self.assertRaisesRegex(ConfigError, "ecosystems must be a table"):
            self.load(without)
        with self.assertRaisesRegex(ConfigError, "at least one ecosystem must be configured"):
            self.load(without + "[ecosystems]\n")
        with self.assertRaisesRegex(ConfigError, "archive is not configured"):
            write_project(self.root, GPL_CONFIG).require_archive()

    def test_an_archive_sits_beside_an_ecosystem(self) -> None:
        config = write_project(self.root, GPL_CONFIG + '\n[archive]\nslug = "demo"\nfiles = ["dist/*.exe"]\n')
        self.assertIsNotNone(config.python)
        self.assertEqual(config.require_archive().slug, "demo")

    def test_rejects_invalid_archives(self) -> None:
        two_products = ARCHIVE_CONFIG.replace("[archive]", '[products.other]\nname = "Other"\n\n[archive]')
        cases = [
            (ARCHIVE_CONFIG, 'slug = "gadget"', 'slug = "gadget"\nextra = 1', "unknown archive key"),
            (ARCHIVE_CONFIG, 'slug = "gadget"', 'slug = "Gadget Firmware"', "archive.slug must be lower-case"),
            (ARCHIVE_CONFIG, 'slug = "gadget"\n', "", "archive.slug must be a non-empty string"),
            (ARCHIVE_CONFIG, 'slug = "gadget"', 'product = "nope"\nslug = "gadget"', "archive.product is unknown: nope"),
            (two_products, 'slug = "gadget"', 'slug = "gadget"', "archive.product is required when multiple products"),
            (ARCHIVE_CONFIG, 'zip = "gadget_firmware-${version}.zip"', 'zip = "out/gadget-${version}.zip"', "must be a file name ending in .zip"),
            (ARCHIVE_CONFIG, 'zip = "gadget_firmware-${version}.zip"', 'zip = "gadget-${version}.tar.gz"', "must be a file name ending in .zip"),
            (ARCHIVE_CONFIG, 'zip = "gadget_firmware-${version}.zip"', 'zip = "gadget-${tag}.zip"', "unknown placeholder"),
            (ARCHIVE_CONFIG, 'zip = "gadget_firmware-${version}.zip"', 'zip = "gadget-$.zip"', "not a valid pattern"),
            (ARCHIVE_CONFIG, 'files = ["dist/package/*"]', "files = []", "archive.files must be a non-empty array"),
            (ARCHIVE_CONFIG, 'files = ["dist/package/*"]', 'files = "dist/package/*"', "archive.files must be a non-empty array"),
            (ARCHIVE_CONFIG, 'files = ["dist/package/*"]', 'files = [""]', r"archive.files\[0\] must be a non-empty string"),
            (ARCHIVE_CONFIG, 'files = ["dist/package/*"]', 'files = ["../elsewhere/*"]', "escapes project root"),
            (ARCHIVE_CONFIG, 'files = ["dist/package/*"]', 'files = ["/dist/package/*"]', "must be relative to project root"),
        ]
        for base, old, new, message in cases:
            with self.subTest(message=message):
                self.assertIn(old, base)
                with self.assertRaisesRegex(ConfigError, message):
                    self.load(base.replace(old, new))


if __name__ == "__main__":
    unittest.main()
