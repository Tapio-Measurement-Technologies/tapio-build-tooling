from pathlib import Path
import tempfile
import unittest

from tapio_build_tools.config import ConfigError, load_config
from tests.downloads_support import GPL_CONFIG, PROPRIETARY_CONFIG, write_project


class DownloadsConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def load(self, config: str):
        return write_project(self.root, config)

    def test_a_config_without_downloads_still_loads(self) -> None:
        config = self.load(GPL_CONFIG.split("[downloads]")[0])
        self.assertIsNone(config.downloads)
        with self.assertRaisesRegex(ConfigError, "downloads are not configured"):
            config.require_downloads()

    def test_loads_a_copyleft_program_with_defaults_filled_in(self) -> None:
        program = self.load(GPL_CONFIG).require_downloads().program("demo")
        self.assertEqual(program.product.id, "demo")
        self.assertEqual(program.contact, "downloads@example.com")
        self.assertTrue(program.source_package)
        self.assertFalse(program.indexable)
        self.assertTrue(program.listed)
        self.assertIsNone(program.security_contact)
        self.assertIsNone(program.support_years)
        supported = self.load(
            GPL_CONFIG.replace('contact = "downloads@example.com"', 'contact = "downloads@example.com"\nsecurity-contact = "security@example.com"')
            .replace('slug = "demo"', 'slug = "demo"\nsupport-years = 5')
        ).require_downloads().program("demo")
        self.assertEqual((supported.security_contact, supported.support_years), ("security@example.com", 5))
        unlisted = self.load(GPL_CONFIG.replace('slug = "demo"', 'slug = "demo"\nlisted = false'))
        self.assertFalse(unlisted.require_downloads().program("demo").listed)
        windows, linux = program.assets
        self.assertEqual((windows.os, windows.arch, windows.archive), ("windows", "x86_64", "zip"))
        self.assertEqual((linux.os, linux.archive, linux.sbom), ("linux", "tar.gz", None))
        self.assertEqual(windows.sbom, "dist/demo-${version}-windows.cdx.json")
        self.assertEqual(self.load(GPL_CONFIG).downloads.logo, self.root / "src" / "assets" / "logo.png")

    def test_loads_several_programs_of_one_product(self) -> None:
        downloads = self.load(PROPRIETARY_CONFIG).require_downloads()
        self.assertEqual(sorted(downloads.programs), ["first", "second"])
        self.assertEqual(downloads.program("second").slug, "suite-second")
        self.assertIsNone(downloads.logo)
        with self.assertRaisesRegex(ConfigError, "unknown program 'third'"):
            downloads.program("third")

    def test_rejects_invalid_downloads(self) -> None:
        two_products = GPL_CONFIG.replace(
            "[ecosystems.python]", '[products.other]\nname = "Other"\n\n[ecosystems.python]'
        )
        cases = [
            (GPL_CONFIG, 'contact = "downloads@example.com"', 'contact = "downloads@example.com"\nextra = 1', "unknown downloads key"),
            (GPL_CONFIG, 'slug = "demo"', 'slug = "demo"\nextra = 1', "unknown downloads.programs.demo key"),
            (GPL_CONFIG, 'os = "linux"', 'os = "linux"\nextra = 1', r"unknown downloads.programs.demo.assets\[1\] key"),
            (GPL_CONFIG, 'os = "linux"', 'os = "freebsd"', "os is invalid: freebsd; supported: windows, linux, macos"),
            (GPL_CONFIG, 'os = "linux"', 'os = "linux"\narch = "riscv"', "arch is invalid: riscv"),
            (GPL_CONFIG, 'os = "linux"', 'os = "linux"\narchive = "7z"', "archive is invalid: 7z"),
            (GPL_CONFIG, 'os = "linux"', 'os = "windows"', "configures windows x86_64 twice"),
            (GPL_CONFIG, 'slug = "demo"', 'slug = "Demo Program"', "slug must be lower-case"),
            (GPL_CONFIG, 'slug = "demo"', 'product = "nope"\nslug = "demo"', "product is unknown: nope"),
            (two_products, 'slug = "demo"', 'slug = "demo"', "product is required when multiple products"),
            (GPL_CONFIG, 'logo = "src/assets/logo.png"', 'logo = "src/assets/missing.png"', "does not exist"),
            (GPL_CONFIG, 'logo = "src/assets/logo.png"', 'logo = "requirements.txt"', "must be a .png or .svg"),
            (GPL_CONFIG, 'glob = "dist/demo-${version}-linux"', 'glob = "../demo-${version}-linux"', "escapes project root"),
            (GPL_CONFIG, 'glob = "dist/demo-${version}-linux"', 'glob = "dist/demo-${tag}-linux"', "unknown placeholder"),
            (GPL_CONFIG, 'glob = "dist/demo-${version}-linux"', 'glob = "dist/demo-$-linux"', "not a valid pattern"),
            (GPL_CONFIG, 'license-id = "GPL-3.0-or-later"', 'license-name = "Proprietary"', "source-package needs products.demo.license-id"),
            (GPL_CONFIG, 'contact = "downloads@example.com"', 'contact = "nobody"', "contact must be an email address"),
            (GPL_CONFIG, 'contact = "downloads@example.com"', 'contact = "downloads@example.com"\nsecurity-contact = "nobody"', "security-contact must be an email address"),
            (GPL_CONFIG, 'slug = "demo"', 'slug = "demo"\nsupport-years = 0', "support-years must be a whole number"),
            (GPL_CONFIG, 'slug = "demo"', 'slug = "demo"\nsupport-years = "five"', "support-years must be a whole number"),
            (GPL_CONFIG, 'slug = "demo"', 'slug = "demo"\nsupport-years = true', "support-years must be a whole number"),
            (PROPRIETARY_CONFIG, 'slug = "suite-second"', 'slug = "suite-first"', "slug duplicates downloads.programs.first"),
            (PROPRIETARY_CONFIG, 'contact = "downloads@example.com"\n', "", "contact is required when downloads.contact is not set"),
            (PROPRIETARY_CONFIG, '[[downloads.programs.second.assets]]\nos = "windows"\nglob = "dist/second-${version}-windows.exe"\n', "", "assets must be a non-empty array"),
        ]
        for base, old, new, message in cases:
            with self.subTest(message=message):
                self.assertIn(old, base)
                with self.assertRaisesRegex(ConfigError, message):
                    self.load(base.replace(old, new))

    def test_glob_need_not_exist_until_publishing(self) -> None:
        config = self.load(GPL_CONFIG.replace("dist/demo-${version}-linux", "out/not-built-yet-${version}"))
        self.assertEqual(config.require_downloads().program("demo").assets[1].glob, "out/not-built-yet-${version}")


if __name__ == "__main__":
    unittest.main()
