"""A product that exists only in these tests, and a signed module of its.

The profile is deliberately unlike any real product's, so nothing here passes
because it happens to match one.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
import unittest
import zipfile

from tapio_module_signing import Profile, build
from tapio_module_signing.testing import generate_key, public_b64, trusting, write_key_file

#: Empty, as a product's table is until it is provisioned; each test trusts a
#: key of its own through testing.trusting().
TRUSTED_KEYS: dict[str, str] = {}


def running_version() -> str | None:
    """The release the test product is running. Patched by version tests."""
    return None


PROFILE = Profile(
    app_name="Gadget",
    kind="gadget module",
    context=b"example-gadget-module-manifest-v1\x00",
    extension=".tgm",
    trusted_keys=TRUSTED_KEYS,
    running_version=lambda: running_version(),
    source_config="gadget.toml",
    publisher="Example Publisher",
    package_root="gadget_modules",
    temp_prefix="gadget-modules-test-",
)

KEY_ID = "gadget-test-key"
MODULE_SOURCE = 'DESCRIPTION = "Test export"\n\n\ndef run(folder_path):\n    return True\n'


def quietly(arguments: list[str], profile: Profile = PROFILE) -> str:
    """Run the builder and return what it printed."""
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        build.main(arguments, profile=profile)
    return printed.getvalue()


class SignedModuleFixture(unittest.TestCase):
    """A real signed module, built the way the release pipeline builds one."""

    profile = PROFILE

    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = generate_key()
        cls.public_key_b64 = public_b64(cls.private_key)

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="module-signing-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.source = os.path.join(self.tmp, "src")
        os.makedirs(self.source)
        self.write("mill_export.py", MODULE_SOURCE)
        self.write("helpers.py", "VALUE = 1\n")
        self.write("gadget.toml",
                   'id = "com.example.test"\n'
                   'name = "Test module"\n'
                   'version = "1.0.0"\n'
                   'module = "mill_export.py"\n')

        self.key_file = write_key_file(self.private_key, os.path.join(self.tmp, "key.pem"))

        trust = trusting(self.profile, {KEY_ID: self.public_key_b64})
        trust.__enter__()
        self.addCleanup(trust.__exit__, None, None, None)

    def write(self, name: str, text: str) -> None:
        path = os.path.join(self.source, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)

    def build(self, out_name: str = "module.tgm", source: str | None = None) -> str:
        out = os.path.join(self.tmp, out_name)
        quietly(["pack", "--source", source or self.source, "--out", out,
                 "--key-id", KEY_ID, "--key-file", self.key_file], self.profile)
        return out

    def rewrite(self, path: str, changes: dict[str, bytes | None]) -> str:
        """Rebuild an archive with some members replaced or dropped.

        Replacing a member in place is not enough: a signature check that only
        looked at the first entry of a duplicated name would pass, so the
        archive is written out fresh with exactly the members intended.
        """
        rebuilt = os.path.join(self.tmp, "rewritten" + self.profile.extension)
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(rebuilt, "w") as out:
            for name in source.namelist():
                data = changes.get(name, source.read(name))
                if data is not None:
                    out.writestr(name, data)
            for name, data in changes.items():
                if name not in source.namelist() and data is not None:
                    out.writestr(name, data)
        return rebuilt
