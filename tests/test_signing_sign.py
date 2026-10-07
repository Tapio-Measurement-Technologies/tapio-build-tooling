import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tapio_build_tools.signing import SigningError
from tapio_build_tools.signing.sign import sign_and_pack, sign_module

BUILDER = ["builder"]
COMMIT = "a" * 40
ACTIONS = {
    "GITHUB_SHA": COMMIT,
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "example-org/gadget",
    "GITHUB_RUN_ID": "42",
}


def vault_signature(digest: bytes) -> bytes:
    """What the fake vault signs a digest to: 64 bytes, like an ES256 r||s."""
    return hashlib.sha512(b"key:" + digest).digest()


class FakeSigning:
    """The product's builder and the az CLI, as the signing step sees them.

    The builder writes a manifest, prints its digest, packs the signature it is
    given beside the manifest, and verifies by checking that signature is the
    vault's. az signs by the fake rule above, decoding the digest exactly as
    the real CLI does: base64.b64decode, standard alphabet.
    """

    def __init__(self, *, digest_encoding="standard", signature_encoding="standard",
                 verified_key_id=None, verify_output=None, sign_error=None) -> None:
        self.digest_encoding = digest_encoding
        self.signature_encoding = signature_encoding
        self.verified_key_id = verified_key_id
        self.verify_output = verify_output
        self.sign_error = sign_error
        self.commands: list[list[str]] = []
        self.manifest = b'{"id": "com.example.export", "version": "1.2.0"}\n'

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess:
        self.commands.append(list(args))
        if args[0] == "builder":
            return getattr(self, "_" + args[1])(args)
        if args[:4] == ["az", "keyvault", "key", "sign"]:
            return self._sign(args)
        raise AssertionError(f"unexpected command: {args}")

    @staticmethod
    def _value(args: list[str], flag: str) -> str:
        for index, arg in enumerate(args):
            if arg == flag:
                return args[index + 1]
            if arg.startswith(flag + "="):
                return arg.split("=", 1)[1]
        raise AssertionError(f"{flag} missing from {args}")

    def _done(self, args, stdout=""):
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    def _manifest(self, args):
        Path(self._value(args, "--out")).write_bytes(self.manifest)
        return self._done(args)

    def _digest(self, args):
        digest = hashlib.sha256(Path(self._value(args, "--manifest")).read_bytes()).digest()
        if self.digest_encoding == "base64url":
            return self._done(args, base64.urlsafe_b64encode(digest).rstrip(b"=").decode() + "\n")
        return self._done(args, base64.b64encode(digest).decode() + "\n")

    def _sign(self, args):
        if self.sign_error:
            raise subprocess.CalledProcessError(1, args, stderr=self.sign_error)
        self.assertion_query = self._value(args, "--query")
        digest = base64.b64decode(self._value(args, "--digest").encode("utf-8"))
        signature = vault_signature(digest)
        if self.signature_encoding == "base64url":
            return self._done(args, base64.urlsafe_b64encode(signature).rstrip(b"=").decode() + "\n")
        if self.signature_encoding == "short":
            return self._done(args, base64.b64encode(signature[:32]).decode() + "\n")
        return self._done(args, base64.b64encode(signature).decode() + "\n")

    def _pack(self, args):
        manifest = Path(self._value(args, "--manifest")).read_bytes()
        Path(self._value(args, "--out")).write_text(json.dumps({
            "manifest": manifest.decode(),
            "key_id": self._value(args, "--key-id"),
            "signature": self._value(args, "--signature"),
        }), encoding="utf-8")
        return self._done(args)

    def _verify(self, args):
        if self.verify_output is not None:
            return self._done(args, self.verify_output)
        packed = json.loads(Path(self._value(args, "--file")).read_text(encoding="utf-8"))
        digest = hashlib.sha256(packed["manifest"].encode()).digest()
        assert base64.b64decode(packed["signature"]) == vault_signature(digest), "bad signature"
        return self._done(args, json.dumps({
            "id": "com.example.export", "version": "1.2.0",
            "key_id": self.verified_key_id or packed["key_id"],
        }))


class SignModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "dist" / "export.tpp"

    def sign(self, runner, **overrides):
        options = {
            "builder": BUILDER, "source": self.root / "src", "output": self.output,
            "vault": "example-vault", "key_name": "gadget-2026a", "runner": runner,
            "environ": ACTIONS,
        }
        options.update(overrides)
        return sign_module(**options)

    def test_it_signs_packs_verifies_and_records(self) -> None:
        runner = FakeSigning()
        record = self.sign(runner)

        self.assertTrue(self.output.is_file())
        self.assertEqual((record.id, record.version), ("com.example.export", "1.2.0"))
        self.assertEqual((record.key_id, record.key_name, record.vault),
                         ("gadget-2026a", "gadget-2026a", "example-vault"))
        self.assertEqual(record.manifest_sha256, hashlib.sha256(runner.manifest).hexdigest())
        self.assertEqual(record.file_sha256, hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertEqual(record.commit, COMMIT)
        self.assertEqual(record.run_url, "https://github.com/example-org/gadget/actions/runs/42")
        self.assertEqual([command[1] for command in runner.commands if command[0] == "builder"],
                         ["manifest", "digest", "pack", "verify"])

    def test_it_asks_az_for_the_signature_field(self) -> None:
        """az prints a SignResult as keyId, algorithm and signature; not `result`."""
        runner = FakeSigning()
        self.sign(runner)
        [sign] = [command for command in runner.commands if command[0] == "az"]
        self.assertEqual(sign[sign.index("--query") + 1], "signature")
        self.assertEqual(sign[sign.index("--algorithm") + 1], "ES256")

    def test_the_signature_reaches_the_builder_as_one_argument(self) -> None:
        """--signature=VALUE: one beginning with '-' is never read as an option."""
        runner = FakeSigning()
        self.sign(runner)
        [pack] = [command for command in runner.commands if command[1:2] == ["pack"]]
        self.assertTrue(any(arg.startswith("--signature=") for arg in pack))
        self.assertNotIn("--signature", pack)

    def test_a_digest_az_cannot_decode_is_refused_before_the_vault_is_asked(self) -> None:
        """Unpadded base64url is what az's base64.b64decode chokes on."""
        runner = FakeSigning(digest_encoding="base64url")
        with self.assertRaisesRegex(SigningError, "digest the builder printed is not standard base64"):
            self.sign(runner)
        self.assertFalse([command for command in runner.commands if command[0] == "az"])

    def test_a_signature_that_is_not_an_es256_one_is_refused(self) -> None:
        with self.assertRaisesRegex(SigningError, "is 32 bytes, not 64"):
            self.sign(FakeSigning(signature_encoding="short"))
        self.assertFalse(self.output.exists())

    def test_the_vault_refusing_says_why(self) -> None:
        runner = FakeSigning(sign_error="(Forbidden) Caller is not authorized to perform action")
        with self.assertRaisesRegex(SigningError, "signing with gadget-2026a in example-vault failed: .*Forbidden"):
            self.sign(runner)

    def test_a_file_the_product_verifies_with_another_key_is_not_signed(self) -> None:
        with self.assertRaisesRegex(SigningError, "verified with key 'gadget-2026b', not 'gadget-2026a'"):
            self.sign(FakeSigning(verified_key_id="gadget-2026b"))

    def test_a_verify_that_prints_no_json_is_a_failure(self) -> None:
        with self.assertRaisesRegex(SigningError, "verify printed no JSON"):
            self.sign(FakeSigning(verify_output="looks fine to me"))

    def test_the_pinned_name_may_differ_from_the_vault_name(self) -> None:
        record = self.sign(FakeSigning(), key_id="gadget-active")
        self.assertEqual((record.key_id, record.key_name), ("gadget-active", "gadget-2026a"))

    def test_a_record_reads_as_json_and_as_a_summary(self) -> None:
        record = self.sign(FakeSigning())
        self.assertEqual(json.loads(record.to_json())["id"], "com.example.export")
        self.assertIn("### Signed com.example.export 1.2.0", record.summary())

    def test_sign_and_pack_alone_does_not_verify(self) -> None:
        """For canaries: signed by a key the product does not pin yet."""
        runner = FakeSigning(verify_output="never asked")
        sign_and_pack(builder=BUILDER, source=self.root / "src", output=self.output,
                      vault="example-vault", key_name="gadget-2026b", key_id="gadget-2026b",
                      runner=runner)
        self.assertNotIn("verify", [command[1] for command in runner.commands if command[0] == "builder"])


if __name__ == "__main__":
    unittest.main()
