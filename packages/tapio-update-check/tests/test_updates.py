"""Reading the manifest, choosing what to offer, and where the files are."""

import json
import unittest

import tapio_update_check as updates

BASE = "https://downloads.example.com"


def manifest(*versions, schema=1, **extra):
    document = {"schema-version": schema, "slug": "gadget", "releases": [{"version": v} for v in versions]}
    document.update(extra)
    return json.dumps(document).encode("utf-8")


class TestUrls(unittest.TestCase):
    def test_the_manifest_sits_beside_the_page(self):
        self.assertEqual(updates.download_page_url(BASE, "gadget"), f"{BASE}/gadget/")
        self.assertEqual(updates.manifest_url(BASE, "gadget"), f"{BASE}/gadget/releases.json")

    def test_a_trailing_slash_on_the_base_makes_no_difference(self):
        self.assertEqual(updates.manifest_url(BASE + "/", "gadget"), updates.manifest_url(BASE, "gadget"))

    def test_a_base_that_is_not_https_is_refused(self):
        for base in ("http://downloads.example.com", "downloads.example.com", "file:///tmp"):
            with self.subTest(base=base), self.assertRaises(ValueError):
                updates.manifest_url(base, "gadget")

    def test_a_slug_must_be_one_path_segment(self):
        for slug in ("", "Gadget", "gadget/v1", "../gadget", "-gadget", None):
            with self.subTest(slug=slug), self.assertRaises(ValueError):
                updates.download_page_url(BASE, slug)


class TestParseVersion(unittest.TestCase):
    def test_a_tag_reads_with_or_without_its_v(self):
        self.assertEqual(updates.parse_version("v1.6.5"), updates.parse_version("1.6.5"))
        self.assertEqual(str(updates.parse_version("v1.6.5")), "1.6.5")

    def test_a_beta_tag_is_the_pre_release_it_names(self):
        version = updates.parse_version("v1.6.0-beta.1")
        self.assertTrue(version.is_prerelease)
        self.assertLess(version, updates.parse_version("v1.6.0"))

    def test_what_is_not_a_release_reads_as_none(self):
        for tag in ("(development version)", "v1.3.0-test", "test001", "", None, 123):
            with self.subTest(tag=tag):
                self.assertIsNone(updates.parse_version(tag))

    def test_a_tag_longer_than_any_release_reads_as_none(self):
        self.assertIsNone(updates.parse_version("v1." + "0" * 100))


class TestParseManifest(unittest.TestCase):
    def test_the_newest_is_found_by_version_not_by_position(self):
        self.assertEqual(updates.parse_manifest(manifest("v1.6.3", "v1.6.10", "v1.6.9")), "v1.6.10")

    def test_the_tag_comes_back_as_the_manifest_wrote_it(self):
        self.assertEqual(updates.parse_manifest(manifest("v1.6.5")), "v1.6.5")

    def test_entries_that_cannot_be_read_are_passed_over(self):
        payload = json.dumps({
            "schema-version": 1,
            "releases": [
                "v9.9.9",
                {"version": None},
                {"version": "v1.3.0-test"},
                {},
                {"version": "v1.6.4"},
            ],
        }).encode("utf-8")
        self.assertEqual(updates.parse_manifest(payload), "v1.6.4")

    def test_a_pre_release_is_never_the_newest(self):
        self.assertEqual(updates.parse_manifest(manifest("v1.6.5", "v1.7.0-beta.1", "v1.7.0.dev1")), "v1.6.5")

    def test_a_manifest_with_nothing_to_offer_says_so(self):
        self.assertIsNone(updates.parse_manifest(manifest()))
        self.assertIsNone(updates.parse_manifest(manifest("v2.0.0-beta.1")))

    def test_what_is_not_a_manifest_is_refused(self):
        payloads = {
            "not JSON": b"<html>Gateway timeout</html>",
            "not UTF-8": b"\xff\xfe\x00",
            "a list": b"[]",
            "a newer schema": manifest("v1.6.5", schema=2),
            "no schema": json.dumps({"releases": []}).encode("utf-8"),
            "no releases": json.dumps({"schema-version": 1}).encode("utf-8"),
            "releases not a list": manifest(releases={"version": "v1.6.5"}),
        }
        for name, payload in payloads.items():
            with self.subTest(name):
                with self.assertRaises(updates.ManifestError):
                    updates.parse_manifest(payload)

    def test_the_expected_program_is_read(self):
        self.assertEqual(updates.parse_manifest(manifest("v1.6.5"), expected_slug="gadget"), "v1.6.5")

    def test_another_programs_manifest_is_refused_when_one_is_expected(self):
        for payload in (manifest("v1.6.5", slug="widget"), manifest("v1.6.5", slug=None)):
            with self.subTest(payload=payload), self.assertRaises(updates.ManifestError):
                updates.parse_manifest(payload, expected_slug="gadget")

    def test_without_an_expected_program_any_is_read(self):
        self.assertEqual(updates.parse_manifest(manifest("v1.6.5", slug="widget")), "v1.6.5")


class TestUpdateToOffer(unittest.TestCase):
    def test_a_newer_release_is_offered(self):
        self.assertEqual(updates.update_to_offer("v1.6.6", "v1.6.5", None), "v1.6.6")

    def test_the_same_or_an_older_release_is_not(self):
        self.assertIsNone(updates.update_to_offer("v1.6.5", "v1.6.5", None))
        self.assertIsNone(updates.update_to_offer("v1.6.4", "v1.6.5", None))

    def test_versions_compare_as_numbers_not_as_text(self):
        self.assertEqual(updates.update_to_offer("v1.6.10", "v1.6.9", None), "v1.6.10")

    def test_a_beta_is_offered_its_final_release(self):
        self.assertEqual(updates.update_to_offer("v1.6.0", "v1.6.0-beta.4", None), "v1.6.0")

    def test_a_skipped_release_is_not_offered_however_it_was_written(self):
        self.assertIsNone(updates.update_to_offer("v1.6.6", "v1.6.5", "v1.6.6"))
        self.assertIsNone(updates.update_to_offer("v1.6.6", "v1.6.5", "1.6.6"))

    def test_skipping_one_release_does_not_skip_the_next(self):
        self.assertEqual(updates.update_to_offer("v1.6.7", "v1.6.5", "v1.6.6"), "v1.6.7")

    def test_a_skipped_value_that_is_not_a_version_is_ignored(self):
        self.assertEqual(updates.update_to_offer("v1.6.6", "v1.6.5", "nonsense"), "v1.6.6")

    def test_a_run_from_source_is_offered_nothing(self):
        self.assertIsNone(updates.update_to_offer("v1.6.6", "(development version)", None))
        self.assertIsNone(updates.update_to_offer("v1.6.6", "v1.3.0-test", None))

    def test_a_latest_that_cannot_be_read_is_not_offered(self):
        self.assertIsNone(updates.update_to_offer("garbage", "v1.6.5", None))


if __name__ == "__main__":
    unittest.main()
