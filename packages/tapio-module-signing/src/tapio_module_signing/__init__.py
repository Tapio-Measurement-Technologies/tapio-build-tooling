"""Signed modules: code a Tapio product loads at runtime, checked before it runs.

A product describes its modules once, in a :class:`Profile`, and hands that to
everything here: :func:`verify` to check a signed file, a :class:`Loader` to
import one, :func:`prepare_install` to put one in the operator's folder, the
builder in :mod:`tapio_module_signing.build` to make one, and the checks in
:mod:`tapio_module_signing.pins` to hold its key table to the keys that really
sign. :mod:`tapio_module_signing.testing` is for its tests.

Signing itself - asking the key vault, and keeping the record of what was
issued - is ``tapio-build signing sign`` in tapio-build-tooling, which drives
the builder.
"""

from tapio_module_signing.install import InstalledCopy, PendingInstall, prepare_install
from tapio_module_signing.load import Loader
from tapio_module_signing.profile import Profile
from tapio_module_signing.verify import (
    MANIFEST_NAME,
    SIGNATURE_ALGORITHM,
    SIGNATURE_NAME,
    SUPPORTED_SCHEMA,
    FileError,
    SignatureError,
    Verified,
    VersionError,
    is_signed_file,
    parse_app_version,
    verify,
)

__version__ = "0.1.0"

__all__ = [
    "MANIFEST_NAME",
    "SIGNATURE_ALGORITHM",
    "SIGNATURE_NAME",
    "SUPPORTED_SCHEMA",
    "FileError",
    "InstalledCopy",
    "Loader",
    "PendingInstall",
    "Profile",
    "SignatureError",
    "Verified",
    "VersionError",
    "is_signed_file",
    "parse_app_version",
    "prepare_install",
    "verify",
]
