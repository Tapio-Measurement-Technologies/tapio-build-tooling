from datetime import date
from pathlib import Path
import tempfile
import unittest

from packaging.version import Version

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
            (
                'version = "3.12"',
                'version = "3.12"\ncooldown-days = 0',
                "whole number of days from 1 to 365",
            ),
            (
                'version = "3.12"',
                'version = "3.12"\ncooldown-days = "7"',
                "whole number of days from 1 to 365",
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

    def test_cooldown_days_defaults_to_none_and_is_read_when_set(self) -> None:
        self.assertIsNone(load_config(self.project()).python.cooldown_days)
        text = BASE.replace('version = "3.12"', 'version = "3.12"\ncooldown-days = 7')
        self.assertEqual(load_config(self.project(text)).python.cooldown_days, 7)

    def test_node_takes_a_cooldown_too(self) -> None:
        text = BASE + """
[ecosystems.node]
version = "24"
package = "package.json"
lock = "package-lock.json"
cooldown-days = 14
"""
        root = self.project(text)
        (root / "package.json").write_text("{}\n", encoding="utf-8")
        (root / "package-lock.json").write_text("{}\n", encoding="utf-8")
        self.assertEqual(load_config(root).node.cooldown_days, 14)

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


RISK = """
[[ecosystems.python.accepted-risks]]
id = "GHSA-h35f-9h28-mq5c"
package = "setuptools"
reason = "Held below 80 by zappa; see R-08."
review-by = 2027-01-31
"""

EXCEPTION = """
[[ecosystems.python.cooldown-exceptions]]
package = "certifi"
version = "2026.10.19"
reason = "Fixes PYSEC-2026-4320."
"""

NODE = """
[ecosystems.node]
version = "24"
package = "package.json"
lock = "package-lock.json"
cooldown-days = 7
"""


class AcceptedRiskConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name, text in [("requirements.in", "packaging==26.2\n"),
                           ("requirements.txt", "packaging==26.2\n"),
                           ("package.json", "{}\n"), ("package-lock.json", "{}\n")]:
            (self.root / name).write_text(text, encoding="utf-8")

    def load(self, text: str):
        (self.root / "build-tooling.toml").write_text(text, encoding="utf-8")
        return load_config(self.root)

    def test_reads_accepted_risks_with_their_review_dates(self) -> None:
        text = BASE + RISK + RISK.replace("GHSA-h35f-9h28-mq5c", "PYSEC-2026-3447").replace(
            "2027-01-31", '"2027-02-28"')
        risks = self.load(text).python.accepted_risks
        self.assertEqual([risk.id for risk in risks], ["GHSA-h35f-9h28-mq5c", "PYSEC-2026-3447"])
        self.assertEqual(risks[0].review_by, date(2027, 1, 31))
        self.assertEqual(risks[1].review_by, date(2027, 2, 28))
        self.assertEqual(risks[0].source, "ecosystems.python.accepted-risks[0]")
        self.assertEqual(risks[0].ecosystem, "python")
        self.assertTrue(risks[0].active(date(2027, 1, 31)))
        self.assertFalse(risks[0].active(date(2027, 2, 1)))

    def test_without_entries_nothing_is_accepted(self) -> None:
        python = self.load(BASE).python
        self.assertEqual(python.accepted_risks, ())
        self.assertEqual(python.cooldown_exceptions, ())

    def test_rejects_an_accepted_risk_that_does_not_say_enough(self) -> None:
        cases = [
            ('reason = "Held below 80 by zappa; see R-08."\n', "", "reason must be a non-empty string"),
            ('reason = "Held below 80 by zappa; see R-08."', 'reason = "  "', "reason must be a non-empty"),
            ("review-by = 2027-01-31\n", "", "review-by is required"),
            ("review-by = 2027-01-31", "review-by = 2027-01-31T12:00:00", "must be a date"),
            ("review-by = 2027-01-31", 'review-by = "soon"', "must be a date"),
            ('package = "setuptools"\n', "", "package must be a non-empty string"),
            ('package = "setuptools"', 'package = "not a name"', "not a Python package name"),
            ('id = "GHSA-h35f-9h28-mq5c"', 'id = "R-08"', "not a PYSEC or GHSA or CVE id"),
            ('id = "GHSA-h35f-9h28-mq5c"', 'id = "GHSA-H35F-9H28-MQ5C"', "not a PYSEC or GHSA or CVE id"),
            ("review-by = 2027-01-31", 'review-by = 2027-01-31\nseverity = "low"', "unknown"),
        ]
        for old, new, message in cases:
            with self.subTest(message=message, new=new):
                with self.assertRaisesRegex(ConfigError, message):
                    self.load(BASE + RISK.replace(old, new))

    def test_rejects_the_same_advisory_accepted_twice_for_one_package(self) -> None:
        with self.assertRaisesRegex(ConfigError, "accepts GHSA-h35f-9h28-mq5c for SetupTools again"):
            self.load(BASE + RISK + RISK.replace('"setuptools"', '"SetupTools"'))

    def test_npm_audit_names_github_advisories_only(self) -> None:
        node_risk = RISK.replace("ecosystems.python", "ecosystems.node").replace(
            '"setuptools"', '"deepmerge"')
        config = self.load(BASE + NODE + node_risk)
        self.assertEqual(config.node.accepted_risks[0].ecosystem, "node")
        with self.assertRaisesRegex(ConfigError, "not a GHSA id: CVE-2026-1234; npm audit reports"):
            self.load(BASE + NODE + node_risk.replace("GHSA-h35f-9h28-mq5c", "CVE-2026-1234"))
        with self.assertRaisesRegex(ConfigError, "not an npm package name"):
            self.load(BASE + NODE + node_risk.replace('"deepmerge"', '"Deep Merge"'))

    def test_reads_cooldown_exceptions(self) -> None:
        text = BASE.replace('version = "3.12"', 'version = "3.12"\ncooldown-days = 7') + EXCEPTION
        [exception] = self.load(text).python.cooldown_exceptions
        self.assertEqual(exception.label, "certifi 2026.10.19")
        self.assertEqual(exception.key, ("certifi", Version("2026.10.19.0")))
        self.assertIsNone(exception.review_by)
        self.assertTrue(exception.active(date(2099, 1, 1)))
        dated = self.load(text + 'review-by = 2026-11-30\n').python.cooldown_exceptions[0]
        self.assertEqual(dated.review_by, date(2026, 11, 30))
        self.assertFalse(dated.active(date(2026, 12, 1)))

    def test_rejects_cooldown_exceptions_that_do_not_say_enough(self) -> None:
        with_cooldown = BASE.replace('version = "3.12"', 'version = "3.12"\ncooldown-days = 7')
        cases = [
            (BASE + EXCEPTION, "cooldown-exceptions needs ecosystems.python.cooldown-days"),
            (with_cooldown + EXCEPTION.replace('reason = "Fixes PYSEC-2026-4320."\n', ""),
             "reason must be a non-empty string"),
            (with_cooldown + EXCEPTION.replace('version = "2026.10.19"\n', ""),
             "version must be a non-empty string"),
            (with_cooldown + EXCEPTION.replace('"2026.10.19"', '"latest"'), "not a Python version"),
            (with_cooldown + EXCEPTION + EXCEPTION.replace('"2026.10.19"', '"2026.10.19.0"'),
             "excepts certifi 2026.10.19.0 again"),
            (with_cooldown + EXCEPTION + "review-by = 2026\n", "must be a date"),
            (BASE + NODE + EXCEPTION.replace("ecosystems.python", "ecosystems.node").replace(
                '"certifi"', '"follow-redirects"').replace('"2026.10.19"', '"latest"'),
             "not an npm version"),
        ]
        for text, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ConfigError, message):
                    self.load(text)

    def test_node_reads_cooldown_exceptions_by_exact_version(self) -> None:
        text = BASE + NODE + EXCEPTION.replace("ecosystems.python", "ecosystems.node").replace(
            '"certifi"', '"follow-redirects"').replace('"2026.10.19"', '"1.16.3"')
        [exception] = self.load(text).node.cooldown_exceptions
        self.assertEqual(exception.label, "follow-redirects 1.16.3")
        self.assertEqual(exception.source, "ecosystems.node.cooldown-exceptions[0]")


if __name__ == "__main__":
    unittest.main()
