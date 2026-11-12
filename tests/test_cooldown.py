from contextlib import redirect_stdout
from datetime import date, datetime, timedelta, timezone
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tapio_build_tools.config import CooldownException

from tapio_build_tools.cooldown import (
    CooldownError,
    Pinned,
    cutoff,
    published,
    refuse_young,
    timestamp,
)
from tapio_build_tools.ecosystems.node import cooldown as node_cooldown
from tapio_build_tools.ecosystems.python import cooldown as python_cooldown


MOMENT = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)


class WindowTests(unittest.TestCase):
    def test_cutoff_counts_back_from_now(self) -> None:
        self.assertEqual(cutoff(7, now=MOMENT), MOMENT - timedelta(days=7))

    def test_timestamp_is_rfc_3339_utc(self) -> None:
        self.assertEqual(timestamp(MOMENT), "2026-09-22T12:00:00Z")
        other = timezone(timedelta(hours=3))
        self.assertEqual(timestamp(MOMENT.astimezone(other)), "2026-09-22T12:00:00Z")

    def test_published_reads_both_forms_the_indexes_use(self) -> None:
        self.assertEqual(published("2026-09-22T12:00:00Z"), MOMENT)
        self.assertEqual(published("2026-09-22T12:00:00.123456Z").replace(microsecond=0), MOMENT)

    def test_old_releases_pass_and_young_ones_are_named_newest_first(self) -> None:
        old = Pinned("old==1", MOMENT - timedelta(days=30))
        recent = Pinned("recent==2", MOMENT - timedelta(days=1))
        fresh = Pinned("fresh==3", MOMENT - timedelta(hours=1))
        self.assertEqual(refuse_young([old], MOMENT - timedelta(days=7)), [old])
        with self.assertRaises(CooldownError) as caught:
            refuse_young([old, recent, fresh], MOMENT - timedelta(days=7))
        message = str(caught.exception)
        self.assertNotIn("old==1", message)
        self.assertLess(message.index("fresh==3"), message.index("recent==2"))
        self.assertIn(timestamp(MOMENT - timedelta(days=7)), message)


def exception(package: str, version: str, review_by: date | None = None, index: int = 0):
    return CooldownException(package, version, "Fixes an advisory.", review_by,
                             f"ecosystems.node.cooldown-exceptions[{index}]")


class CooldownExceptionTests(unittest.TestCase):
    """A release taken inside the window on purpose, until it no longer needs to be."""

    WINDOW = MOMENT - timedelta(days=7)
    TODAY = date(2026, 9, 22)

    def setUp(self) -> None:
        environment = patch.dict(os.environ, {"GITHUB_ACTIONS": ""})
        environment.start()
        self.addCleanup(environment.stop)
        self.old = Pinned("left-pad@1.3.0", MOMENT - timedelta(days=30), "left-pad", "1.3.0")
        self.fix = Pinned("follow-redirects@1.16.3", MOMENT - timedelta(days=1),
                          "follow-redirects", "1.16.3")

    def screen(self, releases, exceptions, **options):
        stdout = StringIO()
        with redirect_stdout(stdout):
            try:
                return refuse_young(releases, self.WINDOW, exceptions, ecosystem="node",
                                    on=options.pop("on", self.TODAY), subject="package-lock.json",
                                    **options)
            finally:
                self.output = stdout.getvalue()

    def test_an_excepted_young_release_passes_and_is_named_with_its_reason(self) -> None:
        releases = self.screen([self.old, self.fix], [exception("follow-redirects", "1.16.3")])
        self.assertEqual(releases, [self.old, self.fix])
        self.assertIn("accepted inside the cooldown: follow-redirects@1.16.3 (2026-09-21T12:00:00Z) - "
                      "ecosystems.node.cooldown-exceptions[0]: Fixes an advisory.", self.output)
        self.assertNotIn("warning", self.output)

    def test_an_exception_names_one_version_only(self) -> None:
        with self.assertRaisesRegex(CooldownError, "follow-redirects@1.16.3"):
            self.screen([self.fix], [exception("follow-redirects", "1.16.2")])
        self.assertIn("excepts follow-redirects 1.16.2 from the cooldown, and the lock does not pin it",
                      self.output)

    def test_an_exception_past_its_review_by_date_lets_nothing_through(self) -> None:
        dated = [exception("follow-redirects", "1.16.3", date(2026, 9, 21))]
        with self.assertRaises(CooldownError) as caught:
            self.screen([self.fix], dated)
        self.assertIn("follow-redirects@1.16.3 (2026-09-21T12:00:00Z), whose exception in "
                      "ecosystems.node.cooldown-exceptions[0] lapsed after 2026-09-21",
                      str(caught.exception))
        self.screen([self.fix], dated, on=date(2026, 9, 21))

    def test_an_exception_for_a_release_older_than_the_window_is_flagged(self) -> None:
        self.screen([self.old], [exception("left-pad", "1.3.0")])
        self.assertIn("warning: package-lock.json: ecosystems.node.cooldown-exceptions[0] excepts "
                      "left-pad 1.3.0 from the cooldown, and it was released 2026-08-23T12:00:00Z, "
                      "before the window; remove the entry", self.output)

    def test_python_releases_match_by_normalised_name_and_version(self) -> None:
        pinned = Pinned("Zope.Interface==7.0", MOMENT - timedelta(days=1), "Zope.Interface", "7.0")
        stdout = StringIO()
        with redirect_stdout(stdout):
            refuse_young([pinned], self.WINDOW, [exception("zope-interface", "7.0.0")],
                         ecosystem="python", on=self.TODAY)
        self.assertIn("accepted inside the cooldown: Zope.Interface==7.0", stdout.getvalue())

    def test_an_exception_for_a_package_another_lock_pins_is_left_to_it(self) -> None:
        self.screen([self.old], [exception("certifi", "2026.10.19")], packages={"left-pad"})
        self.assertNotIn("warning", self.output)
        self.screen([self.old], [exception("left-pad", "1.4.0")], packages={"left-pad"})
        self.assertIn("excepts left-pad 1.4.0 from the cooldown, and the lock does not pin it",
                      self.output)


LOCK = """\
# This file was autogenerated by uv via the following command:
#    tapio-build --project . python requirements compile
--only-binary :all:
--no-binary pylatex

certifi==2026.7.22 \\
    --hash=sha256:{a} \\
    --hash=sha256:{b}
    # via requests
Tzdata==2026.3 ; sys_platform == 'win32' \\
    --hash=sha256:{c}
""".format(a="a" * 64, b="b" * 64, c="c" * 64)


class PythonPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.lock = Path(self.temporary.name) / "requirements.txt"

    def pins(self, text: str = LOCK):
        self.lock.write_text(text, encoding="utf-8")
        return {pin.name: pin for pin in python_cooldown.read_pins(self.lock)}

    def test_reads_pins_over_continuations_past_options_and_comments(self) -> None:
        pins = self.pins()
        self.assertEqual(set(pins), {"certifi", "tzdata"})
        self.assertEqual(pins["certifi"].hashes, frozenset({"a" * 64, "b" * 64}))
        self.assertEqual(pins["tzdata"].version, "2026.3")
        self.assertEqual(pins["tzdata"].hashes, frozenset({"c" * 64}))

    def test_a_group_without_hashes_is_still_read(self) -> None:
        pins = self.pins("packaging==26.2\n")
        self.assertEqual(pins["packaging"].hashes, frozenset())

    def test_an_unpinned_requirement_is_refused(self) -> None:
        with self.assertRaisesRegex(CooldownError, "not pinned: requests"):
            self.pins("requests\n")


def pypi_document(*files) -> dict:
    return {
        "urls": [
            {"digests": {"sha256": digest}, "upload_time_iso_8601": moment}
            for digest, moment in files
        ]
    }


class PythonDateTests(unittest.TestCase):
    def pin(self, *hashes):
        return python_cooldown.Pin("certifi", "2026.7.22", frozenset(hashes))

    @patch("tapio_build_tools.ecosystems.python.cooldown.fetch_json")
    def test_dates_a_release_by_the_newest_file_it_pins(self, fetch_json) -> None:
        fetch_json.return_value = pypi_document(
            ("a" * 64, "2026-07-22T03:35:11Z"),
            ("b" * 64, "2026-07-24T03:35:12Z"),
            ("c" * 64, "2026-08-01T00:00:00Z"),  # a file the lock does not allow
        )
        dated = python_cooldown._dated(self.pin("a" * 64, "b" * 64))
        self.assertEqual(dated.label, "certifi==2026.7.22")
        self.assertEqual(dated.published, published("2026-07-24T03:35:12Z"))

    @patch("tapio_build_tools.ecosystems.python.cooldown.fetch_json")
    def test_without_hashes_the_whole_release_is_dated(self, fetch_json) -> None:
        fetch_json.return_value = pypi_document(
            ("a" * 64, "2026-07-22T03:35:11Z"), ("c" * 64, "2026-08-01T00:00:00Z")
        )
        self.assertEqual(
            python_cooldown._dated(self.pin()).published, published("2026-08-01T00:00:00Z")
        )

    @patch("tapio_build_tools.ecosystems.python.cooldown.fetch_json")
    def test_a_hash_no_file_has_is_refused(self, fetch_json) -> None:
        fetch_json.return_value = pypi_document(("a" * 64, "2026-07-22T03:35:11Z"))
        with self.assertRaisesRegex(CooldownError, "no file on PyPI has"):
            python_cooldown._dated(self.pin("a" * 64, "d" * 64))


def npm_lock(**packages) -> str:
    entries = {"": {"name": "demo", "version": "1.0.0"}}
    entries.update(packages)
    return json.dumps({"lockfileVersion": 3, "packages": entries})


def tarball(name: str, version: str) -> str:
    return f"{node_cooldown.REGISTRY}/{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz"


class NodePinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.lock = Path(self.temporary.name) / "package-lock.json"

    def pins(self, text: str):
        self.lock.write_text(text, encoding="utf-8")
        return node_cooldown.read_pins(self.lock)

    def test_reads_nested_and_scoped_packages_and_skips_the_project(self) -> None:
        pins = self.pins(npm_lock(**{
            "node_modules/left-pad": {
                "version": "1.3.0", "resolved": tarball("left-pad", "1.3.0")
            },
            "node_modules/@babel/core": {
                "version": "7.28.4", "resolved": tarball("@babel/core", "7.28.4")
            },
            "node_modules/a/node_modules/left-pad": {
                "version": "1.2.0", "resolved": tarball("left-pad", "1.2.0")
            },
            "packages/app": {"version": "1.0.0", "link": True},
        }))
        self.assertEqual(pins, {"left-pad": {"1.3.0", "1.2.0"}, "@babel/core": {"7.28.4"}})

    def test_a_tarball_from_another_registry_is_refused(self) -> None:
        with self.assertRaisesRegex(CooldownError, "does not come from"):
            self.pins(npm_lock(**{
                "node_modules/left-pad": {
                    "version": "1.3.0", "resolved": "https://nexus.example.com/left-pad.tgz"
                },
            }))

    def test_a_lock_without_a_packages_table_is_refused(self) -> None:
        with self.assertRaisesRegex(CooldownError, "lockfileVersion 2 or 3"):
            self.pins(json.dumps({"lockfileVersion": 1, "dependencies": {}}))


class NodeDateTests(unittest.TestCase):
    @patch("tapio_build_tools.ecosystems.node.cooldown.fetch_json")
    def test_one_document_dates_every_pinned_version(self, fetch_json) -> None:
        fetch_json.return_value = {
            "time": {
                "created": "2014-03-14T09:09:20Z",
                "1.2.0": "2015-01-01T00:00:00Z",
                "1.3.0": "2018-02-01T00:00:00Z",
            }
        }
        dated = node_cooldown._dated(("left-pad", {"1.3.0", "1.2.0"}))
        self.assertEqual(fetch_json.call_count, 1)
        self.assertEqual([(release.package, release.version) for release in dated],
                         [("left-pad", "1.2.0"), ("left-pad", "1.3.0")])
        self.assertEqual(
            [(release.label, timestamp(release.published)) for release in dated],
            [("left-pad@1.2.0", "2015-01-01T00:00:00Z"), ("left-pad@1.3.0", "2018-02-01T00:00:00Z")],
        )

    @patch("tapio_build_tools.ecosystems.node.cooldown.fetch_json")
    def test_a_version_the_registry_does_not_date_is_refused(self, fetch_json) -> None:
        fetch_json.return_value = {"time": {"1.2.0": "2015-01-01T00:00:00Z"}}
        with self.assertRaisesRegex(CooldownError, "no publication time for left-pad@1.3.0"):
            node_cooldown._dated(("left-pad", {"1.3.0"}))


if __name__ == "__main__":
    unittest.main()
