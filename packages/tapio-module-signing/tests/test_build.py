"""What the builder writes, which is what a key vault is asked to sign."""

import dataclasses
import json
import os
import zipfile

from support import KEY_ID, PROFILE, SignedModuleFixture, quietly
from tapio_module_signing import SIGNATURE_NAME, build, verify
from tapio_module_signing.testing import trusting


class TheBuilderTest(SignedModuleFixture):
    def manifest(self, profile=PROFILE, created="2026-01-01T00:00:00Z"):
        path = os.path.join(self.tmp, "manifest.json")
        quietly(["manifest", "--source", self.source, "--out", path, "--created", created],
                profile)
        with open(path, "rb") as handle:
            return handle.read()

    def test_the_manifest_holds_the_format_fields_and_nothing_else(self):
        manifest = json.loads(self.manifest())

        self.assertEqual(set(manifest), {
            "schema", "id", "name", "version", "publisher", "created",
            "min_app_version", "module", "files"})
        self.assertEqual(manifest["publisher"], "Example Publisher")
        self.assertEqual(manifest["min_app_version"], "")
        self.assertEqual(manifest["created"], "2026-01-01T00:00:00Z")

    def test_the_manifest_is_sorted_indented_and_ends_in_a_newline(self):
        manifest_bytes = self.manifest()

        self.assertEqual(manifest_bytes, build.serialize_manifest(json.loads(manifest_bytes)))
        self.assertTrue(manifest_bytes.endswith(b"}\n"))
        self.assertIn(b'\n  "created": ', manifest_bytes)

    def test_build_leavings_documentation_and_the_source_config_are_not_carried(self):
        self.write("README.md", "for whoever installs it\n")
        self.write("gadget.example.toml", "x = 1\n")
        self.write("gadget.toml~", "editor backup\n")
        self.write("__pycache__/helpers.cpython-312.pyc", "")
        self.write("lib/inner.py", "VALUE = 2\n")

        files = json.loads(self.manifest())["files"]

        self.assertEqual(sorted(files), ["helpers.py", "lib/inner.py", "mill_export.py"])

    def test_extra_fields_are_carried_only_when_the_source_sets_them(self):
        """So adding one to a profile changes no manifest already built."""
        with_plugins = dataclasses.replace(PROFILE, extra_fields=("plugins",))

        self.assertNotIn("plugins", json.loads(self.manifest(with_plugins)))

        with open(os.path.join(self.source, "gadget.toml"), "a", encoding="utf-8") as handle:
            handle.write('plugins = ["dirt"]\n')
        self.assertEqual(json.loads(self.manifest(with_plugins))["plugins"], ["dirt"])
        self.assertNotIn("plugins", json.loads(self.manifest(PROFILE)))

    def test_an_id_the_verifier_would_refuse_is_refused_before_signing(self):
        self.write("gadget.toml", 'id = "Not An Id"\nmodule = "mill_export.py"\n')

        with self.assertRaises(SystemExit) as caught:
            self.manifest()
        self.assertIn("unusable id", str(caught.exception))
        self.assertIn("gadget.toml", str(caught.exception))

    def test_a_module_that_is_not_there_is_refused(self):
        self.write("gadget.toml", 'id = "a"\nmodule = "missing.py"\n')

        with self.assertRaises(SystemExit) as caught:
            self.manifest()
        self.assertIn("gadget.toml names missing.py", str(caught.exception))

    def test_building_the_same_source_twice_signs_the_same_bytes(self):
        """Everything the signature covers rebuilds identically.

        The signature itself does not: ECDSA draws a random nonce, so signing
        one manifest twice gives two different signatures. That is the whole
        of the difference, which is what makes a release checkable - rebuild
        it, and every byte that was signed comes back the same.
        """
        manifest_path = os.path.join(self.tmp, "manifest.json")
        quietly(["manifest", "--source", self.source, "--out", manifest_path,
                 "--created", "2026-01-01T00:00:00Z"])
        first = os.path.join(self.tmp, "a.tgm")
        second = os.path.join(self.tmp, "b.tgm")
        for out in (first, second):
            quietly(["pack", "--source", self.source, "--out", out, "--key-id", KEY_ID,
                     "--key-file", self.key_file, "--manifest", manifest_path])

        with zipfile.ZipFile(first) as a, zipfile.ZipFile(second) as b:
            self.assertEqual(a.namelist(), b.namelist())
            for info in a.infolist():
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
                if info.filename == SIGNATURE_NAME:
                    continue
                self.assertEqual(a.read(info), b.read(info.filename), info.filename)
            self.assertNotEqual(a.read(SIGNATURE_NAME), b.read(SIGNATURE_NAME))

    def test_a_file_signed_the_way_the_vault_signs_verifies(self):
        from tapio_module_signing.testing import build_vault_style

        out = build_vault_style(self.source, os.path.join(self.tmp, "vault.tgm"), KEY_ID,
                                self.private_key, profile=PROFILE)

        with trusting(PROFILE, {KEY_ID: self.public_key_b64}):
            verify(out, profile=PROFILE).close()
        self.assertFalse(os.path.exists(out + ".manifest.json"))
