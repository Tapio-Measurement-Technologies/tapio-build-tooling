"""What the signature check accepts, and what it turns away.

Loading a module runs it, so this check is the whole of the defence: if a
module gets past here, its code executes. Every test below is a way a file
could be wrong, and the assertion is that it does not get past.

The signed files are built by the builder - the same code a product's release
pipeline runs - so these tests check the builder and the verifier against each
other rather than against a hand-written fixture that could drift from both.
"""

import base64
import dataclasses
import hashlib
import json
import os
import re
import sys
import unittest
import zipfile
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

import support
from support import KEY_ID, MODULE_SOURCE, PROFILE, SignedModuleFixture, quietly
from tapio_module_signing import (
    MANIFEST_NAME,
    SIGNATURE_ALGORITHM,
    SIGNATURE_NAME,
    FileError,
    Profile,
    SignatureError,
    VersionError,
    is_signed_file,
    parse_app_version,
    verify,
)
from tapio_module_signing import build
from tapio_module_signing.testing import generate_key, public_b64, trusting, write_key_file


def verify_file(path, profile=PROFILE):
    verified = verify(path, profile=profile)
    verified.close()
    return verified


class AValidModuleTest(SignedModuleFixture):
    def test_it_verifies_and_reports_what_it_holds(self):
        verified = verify(self.build(), profile=PROFILE)
        self.addCleanup(verified.close)

        self.assertEqual(verified.id, "com.example.test")
        self.assertEqual(verified.name, "Test module")
        self.assertEqual(verified.version, "1.0.0")
        self.assertEqual(verified.module, "mill_export.py")
        self.assertEqual(verified.key_id, KEY_ID)

    def test_it_hands_back_the_bytes_it_checked(self):
        verified = verify(self.build(), profile=PROFILE)
        self.addCleanup(verified.close)

        self.assertEqual(verified.read("mill_export.py").decode("utf-8"), MODULE_SOURCE)

    def test_a_file_carried_but_not_imported_is_still_covered(self):
        verified = verify_file(self.build())

        self.assertIn("helpers.py", verified.manifest["files"])
        self.assertNotEqual(verified.module, "helpers.py")

    def test_the_extension_is_the_profiles(self):
        self.assertTrue(is_signed_file("a/b/Module.TGM", profile=PROFILE))
        self.assertFalse(is_signed_file("module.tpp", profile=PROFILE))
        self.assertFalse(is_signed_file("module.py", profile=PROFILE))


class TheBuilderVerifyTest(SignedModuleFixture):
    """`verify` is what the shared signing step asks before calling a file signed."""

    def run_verify(self, path):
        return json.loads(quietly(["verify", "--file", path]))

    def test_it_says_what_verified_and_with_which_key(self):
        self.assertEqual(self.run_verify(self.build()),
                         {"id": "com.example.test", "version": "1.0.0", "key_id": KEY_ID})

    def test_a_file_the_product_would_refuse_fails_it(self):
        tampered = self.rewrite(self.build(), {"mill_export.py": b"BAD = True\n"})
        with self.assertRaises(SystemExit) as caught:
            self.run_verify(tampered)
        self.assertIn("does not verify", str(caught.exception))


class ATamperedModuleTest(SignedModuleFixture):
    def test_a_changed_module_is_refused(self):
        tampered = self.rewrite(self.build(), {
            "mill_export.py": b"import os\nos.system('id')\n"})

        with self.assertRaises(FileError) as caught:
            verify(tampered, profile=PROFILE)
        self.assertIn("mill_export.py", str(caught.exception))

    def test_a_changed_manifest_is_refused(self):
        built = self.build()
        with zipfile.ZipFile(built) as archive:
            manifest = json.loads(archive.read(MANIFEST_NAME))
        manifest["files"]["mill_export.py"] = "sha256:" + hashlib.sha256(b"x").hexdigest()

        tampered = self.rewrite(built, {MANIFEST_NAME: json.dumps(manifest).encode()})

        with self.assertRaises(SignatureError):
            verify(tampered, profile=PROFILE)

    def test_an_extra_module_smuggled_in_beside_the_listed_files_is_refused(self):
        """The manifest has to cover every member, not just the ones it names."""
        tampered = self.rewrite(self.build(), {"evil.py": b"BAD = True\n"})

        with self.assertRaises(FileError) as caught:
            verify(tampered, profile=PROFILE)
        self.assertIn("evil.py", str(caught.exception))

    def test_a_dropped_file_is_refused(self):
        tampered = self.rewrite(self.build(), {"helpers.py": None})

        with self.assertRaises(FileError) as caught:
            verify(tampered, profile=PROFILE)
        self.assertIn("helpers.py", str(caught.exception))

    def test_a_path_that_escapes_the_file_is_refused(self):
        for name in ("../evil.py", "/etc/evil.py", "a/../../evil.py", "C:/evil.py",
                     "a\\evil.py", "./evil.py"):
            with self.subTest(name=name):
                tampered = self.rewrite(self.build(), {name: b"BAD = True\n"})

                with self.assertRaises(FileError):
                    verify(tampered, profile=PROFILE)


class AnUntrustedSignatureTest(SignedModuleFixture):
    def test_a_signature_from_another_key_is_refused(self):
        other_file = write_key_file(generate_key(), os.path.join(self.tmp, "other.pem"))
        out = os.path.join(self.tmp, "other.tgm")
        quietly(["pack", "--source", self.source, "--out", out,
                 "--key-id", KEY_ID, "--key-file", other_file])

        with self.assertRaises(SignatureError):
            verify(out, profile=PROFILE)

    def test_an_unknown_key_id_is_refused(self):
        built = self.build()
        with zipfile.ZipFile(built) as archive:
            signature = json.loads(archive.read(SIGNATURE_NAME))
        signature["key_id"] = "some-key-we-do-not-have"

        tampered = self.rewrite(built, {SIGNATURE_NAME: json.dumps(signature).encode()})

        with self.assertRaises(SignatureError) as caught:
            verify(tampered, profile=PROFILE)
        self.assertIn("unknown key", str(caught.exception))

    def test_an_unsigned_zip_is_refused(self):
        plain = os.path.join(self.tmp, "plain.tgm")
        with zipfile.ZipFile(plain, "w") as archive:
            archive.writestr("mill_export.py", MODULE_SOURCE)

        with self.assertRaises(SignatureError) as caught:
            verify(plain, profile=PROFILE)
        self.assertIn(MANIFEST_NAME, str(caught.exception))

    def test_a_signature_over_the_manifest_alone_is_refused(self):
        """Without the context prefix, a signature made elsewhere would verify.

        The key that signs modules must not be usable to make something that
        reads as one by signing the same bytes in another setting.
        """
        built = self.build()
        with zipfile.ZipFile(built) as archive:
            manifest_bytes = archive.read(MANIFEST_NAME)
            signature = json.loads(archive.read(SIGNATURE_NAME))

        der = self.private_key.sign(manifest_bytes, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        signature["signature"] = base64.b64encode(
            r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode("ascii")

        tampered = self.rewrite(built, {SIGNATURE_NAME: json.dumps(signature).encode()})

        with self.assertRaises(SignatureError):
            verify(tampered, profile=PROFILE)

    def test_a_file_signed_for_another_product_is_refused(self):
        """The same key, trusted by both, still cannot carry one's file to the other.

        Products have keys of their own, so this should never arise; the
        context is what makes it not matter if it did.
        """
        other = dataclasses.replace(PROFILE, context=b"example-other-module-manifest-v1\x00")
        out = os.path.join(self.tmp, "other-product.tgm")
        quietly(["pack", "--source", self.source, "--out", out,
                 "--key-id", KEY_ID, "--key-file", self.key_file], other)

        verify_file(out, profile=other)
        with self.assertRaises(SignatureError):
            verify(out, profile=PROFILE)

    def test_an_unexpected_algorithm_is_refused(self):
        built = self.build()
        with zipfile.ZipFile(built) as archive:
            signature = json.loads(archive.read(SIGNATURE_NAME))
        signature["algorithm"] = "none"

        tampered = self.rewrite(built, {SIGNATURE_NAME: json.dumps(signature).encode()})

        with self.assertRaises(SignatureError):
            verify(tampered, profile=PROFILE)

    def test_a_signature_of_the_wrong_length_is_refused(self):
        built = self.build()
        with zipfile.ZipFile(built) as archive:
            signature = json.loads(archive.read(SIGNATURE_NAME))
        signature["signature"] = base64.b64encode(b"\x01" * 70).decode("ascii")

        tampered = self.rewrite(built, {SIGNATURE_NAME: json.dumps(signature).encode()})

        with self.assertRaises(SignatureError) as caught:
            verify(tampered, profile=PROFILE)
        self.assertIn("70 bytes", str(caught.exception))


class TheKeyVaultSignatureFormatTest(SignedModuleFixture):
    def test_a_base64url_signature_from_the_key_vault_verifies(self):
        """The REST API returns base64url, where az prints base64; both pack."""
        built = self.build()
        with zipfile.ZipFile(built) as archive:
            signature = json.loads(archive.read(SIGNATURE_NAME))
        raw = base64.b64decode(signature["signature"])
        url = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        rewritten = self.rewrite(built, {
            SIGNATURE_NAME: json.dumps({
                **signature, "signature": build.normalize_signature(url),
            }).encode()})

        verify_file(rewritten)

    def test_a_vault_signature_that_begins_with_a_dash_packs_and_verifies(self):
        """One REST API signature in 64 starts with "-" in base64url.

        Passed as `--signature VALUE`, argparse takes it for an option and the
        pack step fails - now and then, in CI, with nothing changed. The
        documented form is `--signature=VALUE`; this holds that form to work.
        """
        manifest_path = os.path.join(self.tmp, "manifest.json")
        quietly(["manifest", "--source", self.source, "--out", manifest_path])
        with open(manifest_path, "rb") as handle:
            manifest_bytes = handle.read()

        # ECDSA draws a fresh nonce each time, so sign until one starts with
        # "-". Expected in 64 tries; missing in 2000 is not going to happen.
        for _attempt in range(2000):
            raw = base64.b64decode(
                build.sign_with_key_file(manifest_bytes, self.key_file, profile=PROFILE))
            signature = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
            if signature.startswith("-"):
                break
        else:
            self.fail("no signature starting with '-' in 2000 tries")

        out = os.path.join(self.tmp, "dash.tgm")
        quietly(["pack", "--source", self.source, "--manifest", manifest_path,
                 "--key-id", KEY_ID, f"--signature={signature}", "--out", out])

        verify_file(out)

    def test_the_digest_decodes_the_way_az_decodes_it(self):
        """What `digest` prints is what `az keyvault key sign --digest` signs.

        az hands the argument to base64.b64decode - standard alphabet,
        non-validating - so that is how it is decoded here. Unpadded base64url
        fails there outright; with the padding back, its - and _ would be
        dropped as noise and a different digest signed.
        """
        path = os.path.join(self.tmp, "manifest.json")
        quietly(["manifest", "--source", self.source, "--out", path])
        with open(path, "rb") as handle:
            manifest_bytes = handle.read()

        printed = build.signing_digest(manifest_bytes, profile=PROFILE)
        expected = hashlib.sha256(PROFILE.context + manifest_bytes).digest()

        self.assertEqual(base64.b64decode(printed.encode("utf-8")), expected)
        self.assertEqual(base64.b64decode(printed, validate=True), expected)


class AMalformedFileTest(SignedModuleFixture):
    def test_something_that_is_not_a_zip_is_refused(self):
        path = os.path.join(self.tmp, "not-a-zip.tgm")
        with open(path, "wb") as handle:
            handle.write(b"this is not an archive")

        with self.assertRaises(FileError):
            verify(path, profile=PROFILE)

    def resigned(self, built, **changes):
        """The file rebuilt with its manifest changed and signed again.

        Signed with the trusted key, so the only thing left wrong is the change:
        the test is then of what the manifest says, not of the signature.
        """
        with zipfile.ZipFile(built) as archive:
            manifest = json.loads(archive.read(MANIFEST_NAME))
        for key, value in changes.items():
            if value is None:
                manifest.pop(key, None)
            else:
                manifest[key] = value
        manifest_bytes = build.serialize_manifest(manifest)
        return self.rewrite(built, {
            MANIFEST_NAME: manifest_bytes,
            SIGNATURE_NAME: json.dumps({
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id": KEY_ID,
                "signature": build.sign_with_key_file(manifest_bytes, self.key_file,
                                                      profile=PROFILE),
            }).encode(),
        })

    def test_an_id_that_could_not_name_a_file_and_a_package_is_refused(self):
        """By default: lowercase letters and digits, joined by single hyphens or dots."""
        for unusable in ("excel_export", "Acme", "-acme", "acme-", "acme..x", "acme/x", "a b"):
            with self.subTest(id=unusable):
                with self.assertRaises(FileError) as caught:
                    verify(self.resigned(self.build(), id=unusable), profile=PROFILE)
                self.assertIn("unusable id", str(caught.exception))

    def test_a_plain_name_is_an_id(self):
        for usable in ("folder-export", "zones", "com.example.signing-canary"):
            with self.subTest(id=usable):
                verify_file(self.resigned(self.build(), id=usable))

    def test_a_profile_may_set_its_own_id_rule(self):
        """A product whose ids are already Python names keeps them."""
        snake = dataclasses.replace(
            PROFILE, id_pattern=re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$"))
        with trusting(snake, {KEY_ID: self.public_key_b64}):
            verify(self.resigned(self.build(), id="excel_export"), profile=snake).close()
            with self.assertRaises(FileError):
                verify(self.resigned(self.build(), id="excel-export"), profile=snake)

    def test_a_manifest_naming_several_modules_is_refused(self):
        """One signed file is one module; a list of modules is not a module."""
        tampered = self.resigned(
            self.build(), module=None, modules=["mill_export.py", "helpers.py"])

        with self.assertRaises(FileError) as caught:
            verify(tampered, profile=PROFILE)
        self.assertIn("module", str(caught.exception))

    def test_a_module_that_cannot_be_imported_by_name_is_refused(self):
        for module in ("mill-export.py", "helpers/mill_export.py", "mill_export.txt"):
            with self.subTest(module=module):
                built = self.build()
                with zipfile.ZipFile(built) as archive:
                    files = json.loads(archive.read(MANIFEST_NAME))["files"]
                files[module] = files["mill_export.py"]
                with self.assertRaises(FileError):
                    verify(self.resigned(built, module=module, files=files), profile=PROFILE)

    def test_a_manifest_from_a_newer_format_is_refused_by_version(self):
        with self.assertRaises(FileError) as caught:
            verify(self.resigned(self.build(), schema=99), profile=PROFILE)
        self.assertIn("99", str(caught.exception))
        self.assertIn("gadget module format", str(caught.exception))

    def test_an_implausibly_large_manifest_is_not_read(self):
        built = self.build()
        tampered = self.rewrite(built, {MANIFEST_NAME: b" " * (256 * 1024 + 1)})

        with self.assertRaises(FileError) as caught:
            verify(tampered, profile=PROFILE)
        self.assertIn("implausibly large", str(caught.exception))

    def test_the_archive_is_closed_when_verification_fails(self):
        """A refused file must not be left held open.

        On Windows an open handle is a file the operator cannot delete or
        replace, which is exactly what they will be trying to do next.
        """
        path = os.path.join(self.tmp, "plain.tgm")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("x.py", "")

        with self.assertRaises(SignatureError):
            verify(path, profile=PROFILE)
        os.replace(path, path + ".moved")


class AFileThatIsBrokenInsideTest(SignedModuleFixture):
    """Damage the zip reports in its own ways is still only a damaged file."""

    def test_a_member_whose_bytes_fail_their_crc_is_a_damaged_file(self):
        built = self.build()
        with open(built, "rb") as handle:
            data = bytearray(handle.read())
        with zipfile.ZipFile(built) as archive:
            info = archive.getinfo("mill_export.py")
        # The member's first stored byte, past its local header and name.
        start = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
        data[start] ^= 0xFF
        with open(built, "wb") as handle:
            handle.write(bytes(data))

        with self.assertRaises(FileError) as caught:
            verify(built, profile=PROFILE)
        self.assertIn("could not be read", str(caught.exception))

    def test_signature_json_nested_past_the_parsers_depth_is_refused(self):
        tampered = self.rewrite(self.build(), {SIGNATURE_NAME: b"[" * 200_000})

        with self.assertRaises(SignatureError):
            verify(tampered, profile=PROFILE)

    def test_a_file_far_too_large_to_be_one_is_not_opened(self):
        # The package's verify is the function; the module is the one patched.
        verify_module = sys.modules["tapio_module_signing.verify"]

        built = self.build()
        with patch.object(verify_module, "MAX_FILE_BYTES", 100), \
                patch("zipfile.ZipFile", side_effect=AssertionError("it was parsed")):
            with self.assertRaises(FileError) as caught:
                verify(built, profile=PROFILE)
        self.assertIn("too large to be a gadget module", str(caught.exception))

    def test_an_id_with_a_trailing_newline_is_refused(self):
        """A pattern ending in $ matches before a final newline; the check does not."""
        tampered = AMalformedFileTest.resigned(self, self.build(), id="com.example.test\n")

        with self.assertRaises(FileError) as caught:
            verify(tampered, profile=PROFILE)
        self.assertIn("unusable id", str(caught.exception))


class ReadingAVersionTest(unittest.TestCase):
    def test_a_release_tag_and_a_plain_version_read_the_same(self):
        self.assertEqual(parse_app_version("v1.7.0"), (1, 7, 0))
        self.assertEqual(parse_app_version("1.7.0"), (1, 7, 0))

    def test_a_missing_patch_number_is_zero(self):
        self.assertEqual(parse_app_version("1.7"), (1, 7, 0))

    def test_a_pre_release_reads_as_the_release_it_leads_up_to(self):
        self.assertEqual(parse_app_version("v1.7.0-beta.2"), (1, 7, 0))

    def test_what_is_not_a_version_reads_as_none(self):
        for text in ("(development version)", "main", "", "1", "1.7.0.1",
                     "latest", " ", None, 1.7):
            with self.subTest(text=text):
                self.assertIsNone(parse_app_version(text))


class TheReleaseAModuleNeedsTest(SignedModuleFixture):
    """min_app_version, checked against the release doing the loading."""

    def require(self, version):
        self.write("gadget.toml",
                   'id = "com.example.test"\n'
                   'name = "Test module"\n'
                   'version = "1.0.0"\n'
                   f'min_app_version = {version}\n'
                   'module = "mill_export.py"\n')

    def verify_in(self, running, path):
        # The profile looks the version up through support.running_version on
        # every check, which is what lets a product's test patch its own.
        with patch.object(support, "running_version", return_value=running):
            verify_file(path)

    def test_one_for_a_later_release_is_refused_and_says_which(self):
        self.require('"1.8.0"')
        built = self.build()

        with self.assertRaises(VersionError) as caught:
            self.verify_in("v1.7.0", built)
        self.assertEqual(caught.exception.required, "1.8.0")
        self.assertEqual(caught.exception.running, "v1.7.0")
        self.assertEqual(caught.exception.id, "com.example.test")
        self.assertEqual(caught.exception.version, "1.0.0")
        self.assertEqual(str(caught.exception),
                         "requires Gadget 1.8.0 or later (running v1.7.0)")

    def test_the_release_it_names_and_every_later_one_load_it(self):
        self.require('"1.8.0"')
        built = self.build()

        for running in ("v1.8.0", "v1.8.1", "v1.9.0", "v2.0.0"):
            with self.subTest(running=running):
                self.verify_in(running, built)

    def test_versions_compare_as_numbers_not_as_text(self):
        """As text, "1.10.0" sorts before "1.9.0"."""
        self.require('"1.10.0"')
        built = self.build()

        self.verify_in("v1.10.0", built)
        with self.assertRaises(VersionError):
            self.verify_in("v1.9.0", built)

    def test_a_pre_release_of_the_release_it_names_loads_it(self):
        self.require('"1.8.0"')
        self.verify_in("v1.8.0-beta.1", self.build())

    def test_a_run_with_no_release_number_does_not_check(self):
        """A source run, or a build from something other than a release tag."""
        self.require('"99.0.0"')
        built = self.build()

        for running in (None, "(development version)", "main"):
            with self.subTest(running=running):
                self.verify_in(running, built)

    def test_one_that_names_no_version_loads_in_any_release(self):
        self.verify_in("v0.1.0", self.build())

    def test_a_damaged_file_is_called_damaged_and_not_too_new(self):
        """Updating would not fix it, so it must not be told to update."""
        self.require('"99.0.0"')
        tampered = self.rewrite(self.build(), {"mill_export.py": b"BAD = True\n"})

        with self.assertRaises(FileError):
            self.verify_in("v1.7.0", tampered)

    def test_the_builder_refuses_a_version_it_cannot_read(self):
        """Caught before signing, not at every site the module reaches."""
        for version in ('"latest"', '"1.7.0.1"', '1.7'):
            with self.subTest(version=version):
                self.require(version)
                with self.assertRaises(SystemExit) as caught:
                    self.build()
                self.assertIn("min_app_version", str(caught.exception))
                self.assertIn("Gadget version", str(caught.exception))

    def test_a_signed_manifest_with_a_version_it_cannot_read_is_refused(self):
        built = self.build()
        with zipfile.ZipFile(built) as archive:
            manifest = json.loads(archive.read(MANIFEST_NAME))
        manifest["min_app_version"] = "next"
        manifest_bytes = build.serialize_manifest(manifest)

        resigned = self.rewrite(built, {
            MANIFEST_NAME: manifest_bytes,
            SIGNATURE_NAME: json.dumps({
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id": KEY_ID,
                "signature": build.sign_with_key_file(manifest_bytes, self.key_file,
                                                      profile=PROFILE),
            }).encode(),
        })

        with self.assertRaises(FileError) as caught:
            self.verify_in("v1.7.0", resigned)
        self.assertIn("next", str(caught.exception))


class AProfileTest(unittest.TestCase):
    def test_its_table_is_read_on_every_check_not_copied(self):
        key = generate_key()
        table: dict[str, str] = {}
        profile = dataclasses.replace(PROFILE, trusted_keys=table)

        table["late"] = public_b64(key)

        self.assertIs(profile.trusted_keys, table)

    def test_it_refuses_what_would_make_files_ambiguous(self):
        for changes in ({"extension": "tgm"}, {"extension": ".TGM"},
                        {"extra_fields": ("files",)}, {"context": b""}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    dataclasses.replace(PROFILE, **changes)

    def test_it_is_not_hashed_by_value(self):
        self.assertIsInstance(hash(PROFILE), int)
        self.assertNotEqual(PROFILE, dataclasses.replace(PROFILE))
        self.assertIsInstance(PROFILE, Profile)


if __name__ == "__main__":
    unittest.main()
