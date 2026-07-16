from pathlib import Path
import tempfile
import unittest

from tapio_build_tools.config import ConfigError, load_config


BASE = """\
schema-version = 1

[organization]
name = "Tapio Measurement Technologies Oy"

[products.first]
name = "First"
license-id = "GPL-3.0-or-later"

[ecosystems.python]
version = "3.12"

[[ecosystems.python.requirements]]
name = "runtime"
input = "requirements.in"
lock = "requirements.txt"
"""


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def project(self, config: str = BASE) -> Path:
        (self.root / "requirements.in").write_text("packaging==26.2\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text("packaging==26.2\n", encoding="utf-8")
        (self.root / "build-tooling.toml").write_text(config, encoding="utf-8")
        return self.root

    def test_loads_config_and_selects_only_product(self) -> None:
        config = load_config(self.project())
        self.assertEqual(config.product(None).id, "first")
        self.assertEqual(config.python.requirement("runtime").lock, self.root / "requirements.txt")

    def test_requires_product_selection_for_multiple_products(self) -> None:
        text = BASE.replace(
            "[ecosystems.python]",
            '[products.second]\nname = "Second"\nlicense-name = "Proprietary"\n\n[ecosystems.python]',
        )
        config = load_config(self.project(text))
        with self.assertRaisesRegex(ConfigError, "--product is required"):
            config.product(None)
        self.assertEqual(config.product("second").license_name, "Proprietary")

    def test_rejects_invalid_config(self) -> None:
        replacements = [
            ("schema-version = 1", "schema-version = 2", "unsupported schema-version"),
            ('name = "runtime"', 'name = "runtime"\nfoo = "bar"', "unknown"),
            (
                'license-id = "GPL-3.0-or-later"',
                'license-id = "GPL-3.0-or-later"\nlicense-name = "GPL"',
                "both license-id and license-name",
            ),
            (
                'lock = "requirements.txt"',
                'lock = "../requirements.txt"',
                "escapes project root",
            ),
        ]
        for old, new, message in replacements:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ConfigError, message):
                    load_config(self.project(BASE.replace(old, new)))

    def test_rejects_duplicate_groups(self) -> None:
        duplicate = BASE + """

[[ecosystems.python.requirements]]
name = "runtime"
lock = "requirements.txt"
"""
        with self.assertRaisesRegex(ConfigError, "duplicate requirement group"):
            load_config(self.project(duplicate))

    def test_lock_only_group_is_supported(self) -> None:
        config = load_config(self.project(BASE.replace('input = "requirements.in"\n', "")))
        self.assertIsNone(config.python.requirement("runtime").input)

    def test_nested_lock_path(self) -> None:
        (self.root / "app").mkdir()
        text = BASE.replace('input = "requirements.in"\n', "").replace(
            'lock = "requirements.txt"', 'lock = "app/requirements.txt"'
        )
        self.project(text)
        (self.root / "requirements.txt").rename(self.root / "app" / "requirements.txt")
        config = load_config(self.root)
        self.assertEqual(config.python.requirement("runtime").lock, self.root / "app" / "requirements.txt")

    def test_loads_node_only_config(self) -> None:
        (self.root / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
        (self.root / "package-lock.json").write_text(
            '{"name":"demo","lockfileVersion":3}\n', encoding="utf-8"
        )
        (self.root / "build-tooling.toml").write_text(
            """schema-version = 1
[organization]
name = "Tapio"
[products.demo]
name = "Demo"
[ecosystems.node]
version = "24"
package = "package.json"
lock = "package-lock.json"
""",
            encoding="utf-8",
        )
        config = load_config(self.root)
        self.assertIsNone(config.python)
        self.assertEqual(config.require_node().version, "24")
        self.assertEqual(config.require_node().lock, self.root / "package-lock.json")

    def test_loads_mixed_python_and_node_config(self) -> None:
        (self.root / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
        (self.root / "package-lock.json").write_text(
            '{"name":"demo","lockfileVersion":3}\n', encoding="utf-8"
        )
        mixed = BASE + """
[ecosystems.node]
version = "24"
package = "package.json"
lock = "package-lock.json"
"""
        config = load_config(self.project(mixed))
        self.assertIsNotNone(config.python)
        self.assertIsNotNone(config.node)

    def test_requires_at_least_one_ecosystem(self) -> None:
        text = BASE[: BASE.index("[ecosystems.python]")] + "[ecosystems]\n"
        with self.assertRaisesRegex(ConfigError, "at least one ecosystem"):
            load_config(self.project(text))

    def test_rejects_invalid_node_paths(self) -> None:
        (self.root / "package.json").write_text("{}\n", encoding="utf-8")
        (self.root / "package-lock.json").write_text("{}\n", encoding="utf-8")
        base = """schema-version = 1
[organization]
name = "Tapio"
[products.demo]
name = "Demo"
[ecosystems.node]
version = "24"
package = "package.json"
lock = "package-lock.json"
"""
        replacements = [
            ('package = "package.json"', 'package = "../package.json"', "escapes project root"),
            ('lock = "package-lock.json"', 'lock = "missing/package-lock.json"', "does not exist"),
        ]
        for old, new, message in replacements:
            with self.subTest(message=message):
                (self.root / "build-tooling.toml").write_text(
                    base.replace(old, new), encoding="utf-8"
                )
                with self.assertRaisesRegex(ConfigError, message):
                    load_config(self.root)

    def test_requires_node_files_in_same_directory(self) -> None:
        (self.root / "package.json").write_text("{}\n", encoding="utf-8")
        (self.root / "nested").mkdir()
        (self.root / "nested" / "package-lock.json").write_text("{}\n", encoding="utf-8")
        text = """schema-version = 1
[organization]
name = "Tapio"
[products.demo]
name = "Demo"
[ecosystems.node]
version = "24"
package = "package.json"
lock = "nested/package-lock.json"
"""
        (self.root / "build-tooling.toml").write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ConfigError, "share a directory"):
            load_config(self.root)


if __name__ == "__main__":
    unittest.main()
