"""Whether a module was signed by a key the product trusts, decided before it runs.

A module is Python that the product imports and calls, so loading one is
running it. It arrives as a signed file - a zip - and until the check in this
module passes, nothing in that file is opened for import; a file that fails it
is never unpacked.

What is checked is a signature over the file's manifest, made by a key held in
a key vault, against the public half of that key compiled into the product. The
manifest in turn carries a SHA-256 for every file the module is made of, so one
signature covers the lot: change a byte of the module and its hash stops
matching the manifest, change the manifest and the signature stops matching.

The trust in that pinned key comes from the executable it ships inside, which
the product signs. That is the anchor - an attacker who could replace the key
table could replace the whole program and would not need a module to do it.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import posixpath
import re
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.serialization import load_der_public_key

from tapio_module_signing.profile import Profile

MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "signature.json"
#: Members that carry the signature rather than being covered by it.
UNSIGNED_MEMBERS = frozenset({MANIFEST_NAME, SIGNATURE_NAME})

SUPPORTED_SCHEMA = 1
SIGNATURE_ALGORITHM = "ECDSA-P256-SHA256"
#: An ECDSA P-256 signature as the key vault returns it: r and s, 32 bytes each.
RAW_SIGNATURE_LENGTH = 64

#: The module becomes a Python module name, so the stem has to be an identifier.
#: It sits at the top of the archive, beside the manifest.
MODULE_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\.py")

#: A product version as a release is tagged ("v1.7.0", "v1.7.0-beta.2") or as a
#: module names one ("1.7.0", "1.7"). Anything after the numbers is a
#: pre-release or build label and does not take part in the comparison.
_APP_VERSION = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?:[-+][0-9A-Za-z.\-+]*)?$")

#: Caps on what is read out of an untrusted archive before it has been checked.
#: A manifest is a few kilobytes; anything of this size is not one.
MAX_METADATA_BYTES = 256 * 1024
MAX_MEMBERS = 256
#: A module is a file and a few helpers, a few hundred kilobytes at most.
#: Anything this size is not one, and its directory is not even parsed.
MAX_FILE_BYTES = 64 * 1024 * 1024


class SignatureError(Exception):
    """The module is not signed by a key this product trusts.

    Distinct from FileError because the two mean different things to whoever
    sees the message: this one says the file did not come from the publisher,
    or was changed after it did.
    """


class FileError(Exception):
    """The file is signed, but it is not a module this product can read.

    A truncated download, a manifest from a newer schema, a file whose hash
    does not match what the manifest says it should be.
    """


class VersionError(Exception):
    """The module is signed and intact, but written for a newer release.

    Kept apart from the other two because it is the only one the operator can
    fix without asking anybody: update the software and the same file loads.
    """

    def __init__(self, required: str, running: str, app_name: str = "the application",
                 id: str = "", version: str = "") -> None:
        super().__init__(f"requires {app_name} {required} or later (running {running})")
        self.required = required
        self.running = running
        #: From a manifest whose signature has verified, so they can be
        #: believed: which module this is, though it cannot load here.
        self.id = id
        self.version = version


@dataclass(frozen=True)
class Verified:
    """A module whose signature and file hashes have both been checked.

    Holds the archive open. The bytes that were verified are the bytes this
    hands out: re-opening the path afterwards would leave a window in which the
    file on disk could be replaced between the check and the use.
    """

    path: str
    id: str
    name: str
    version: str
    #: The file in the archive that is imported as the module. Anything else
    #: the manifest covers is carried for it: helpers, data.
    module: str
    #: The trusted-key entry whose key the signature verified with.
    key_id: str = ""
    manifest: dict = field(default_factory=dict)
    _archive: zipfile.ZipFile | None = None

    def open(self) -> zipfile.ZipFile:
        """The verified archive. Owned by this object; do not close it."""
        assert self._archive is not None
        return self._archive

    def read(self, member: str) -> bytes:
        """The bytes of one verified member."""
        return self.open().read(member)

    def close(self) -> None:
        if self._archive is not None:
            self._archive.close()


def is_signed_file(path: str, *, profile: Profile) -> bool:
    return path.lower().endswith(profile.extension)


def parse_app_version(text: object) -> tuple[int, int, int] | None:
    """A product version as (major, minor, patch), or None if it is not one.

    Compared as numbers, so 1.10 comes after 1.9. A pre-release counts as the
    release it leads up to: a module that needs 1.7.0 loads in 1.7.0-beta.2,
    which is where it gets tried out before the release ships.
    """
    if not isinstance(text, str):
        return None
    match = _APP_VERSION.match(text.strip())
    if match is None:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


def _decode_base64(value: object, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)  # type: ignore[arg-type]
    except (binascii.Error, TypeError, ValueError) as error:
        raise FileError(f"{what} is not valid base64") from error


def load_public_key(key_id: str, *, profile: Profile) -> ec.EllipticCurvePublicKey:
    """The trusted key named *key_id*, or SignatureError saying why not."""
    encoded = profile.trusted_keys.get(key_id)
    if encoded is None:
        raise SignatureError(f"signed with an unknown key '{key_id}'")
    try:
        key = load_der_public_key(_decode_base64(encoded, "trusted key"))
    except Exception as error:  # a broken table is a build fault, not a bad file
        raise SignatureError(f"trusted key '{key_id}' could not be read: {error}") from error
    if not isinstance(key, ec.EllipticCurvePublicKey) or \
            not isinstance(key.curve, ec.SECP256R1):
        raise SignatureError(f"trusted key '{key_id}' is not an ECDSA P-256 key")
    return key


def _read_metadata(archive: zipfile.ZipFile, name: str) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError:
        raise SignatureError(f"has no {name}") from None
    if info.file_size > MAX_METADATA_BYTES:
        raise FileError(f"{name} is implausibly large")
    return archive.read(name)


def _verify_signature(manifest_bytes: bytes, signature_bytes: bytes, profile: Profile) -> str:
    """Check the signature over the manifest, before the manifest is parsed.

    Nothing in the manifest is believed - or even decoded - until this
    returns, so a malformed manifest cannot reach the JSON parser unless the
    key already vouched for it.
    """
    try:
        signature = json.loads(signature_bytes)
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        raise SignatureError(f"{SIGNATURE_NAME} is not readable: {error}") from error
    if not isinstance(signature, dict):
        raise SignatureError(f"{SIGNATURE_NAME} is not an object")

    algorithm = signature.get("algorithm")
    if algorithm != SIGNATURE_ALGORITHM:
        raise SignatureError(
            f"is signed with {algorithm!r}, which this version does not accept")

    key_id = signature.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        raise SignatureError(f"{SIGNATURE_NAME} names no key")
    public_key = load_public_key(key_id, profile=profile)

    raw = _decode_base64(signature.get("signature", ""), "the signature")
    # The key vault returns ECDSA signatures as r and s concatenated, which is
    # what JSON Web Signature uses; cryptography wants them DER-encoded.
    if len(raw) != RAW_SIGNATURE_LENGTH:
        raise SignatureError(
            f"the signature is {len(raw)} bytes, not {RAW_SIGNATURE_LENGTH}")
    half = RAW_SIGNATURE_LENGTH // 2
    der = asym_utils.encode_dss_signature(
        int.from_bytes(raw[:half], "big"), int.from_bytes(raw[half:], "big"))

    try:
        public_key.verify(der, profile.context + manifest_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SignatureError(f"the signature does not match {MANIFEST_NAME}") from None
    return key_id


def _parse_manifest(manifest_bytes: bytes, profile: Profile) -> dict:
    try:
        manifest = json.loads(manifest_bytes)
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        raise FileError(f"{MANIFEST_NAME} is not readable: {error}") from error
    if not isinstance(manifest, dict):
        raise FileError(f"{MANIFEST_NAME} is not an object")

    schema = manifest.get("schema")
    if schema != SUPPORTED_SCHEMA:
        raise FileError(
            f"was built for {profile.kind} format {schema}, and this version "
            f"reads format {SUPPORTED_SCHEMA}")

    module_id = manifest.get("id")
    if not isinstance(module_id, str) or not profile.id_pattern.fullmatch(module_id):
        raise FileError(f"has an unusable id {module_id!r}")

    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise FileError(f"{MANIFEST_NAME} lists no files")

    module = manifest.get("module")
    if not isinstance(module, str) or module not in files:
        raise FileError(f"names a module {module!r} that {MANIFEST_NAME} does not cover")
    if not MODULE_NAME_PATTERN.fullmatch(module):
        raise FileError(f"names a module {module!r} that cannot be imported")

    required = manifest.get("min_app_version", "")
    if required != "" and parse_app_version(required) is None:
        raise FileError(
            f"names a {profile.app_name} version {required!r} that cannot be read")
    return manifest


def _check_app_version(manifest: dict, profile: Profile) -> None:
    """Refuse a module written for a newer release than the one running.

    A module imports the product's own modules, so one built against a later
    release can fail on import, or import and then misbehave part-way through.
    Checked here, before anything is imported, so the operator is told to
    update rather than that the file could not be loaded.
    """
    required = manifest.get("min_app_version", "")
    if required == "":
        return
    running = profile.running_version()
    running_parsed = parse_app_version(running)
    if running_parsed is None:
        return
    required_parsed = parse_app_version(required)
    assert required_parsed is not None  # _parse_manifest refused anything else
    if running_parsed < required_parsed:
        raise VersionError(
            required, str(running), app_name=profile.app_name, id=manifest["id"],
            version=str(manifest.get("version", "")))


def _check_member_name(name: str) -> None:
    """Reject anything that would not stay inside the directory it unpacks to.

    zipfile.extract() sanitises paths on its way out, but the loader reads
    members by name and writes them itself, so the check has to be here.
    """
    if not name or name.endswith("/"):
        raise FileError(f"contains an unusable entry {name!r}")
    if "\\" in name or name != posixpath.normpath(name):
        raise FileError(f"contains a non-canonical path {name!r}")
    if posixpath.isabs(name) or name.startswith("../") or ".." in name.split("/"):
        raise FileError(f"contains an escaping path {name!r}")
    if re.match(r"^[A-Za-z]:", name):
        raise FileError(f"contains an absolute path {name!r}")


def _check_files(archive: zipfile.ZipFile, files: dict) -> None:
    """Every member is named by the manifest, and every hash matches.

    Both directions matter. Checking only that the listed files match would
    let a file carry an unlisted extra module alongside them; checking only
    that the members are listed would let a listed one be swapped.
    """
    members = [info for info in archive.infolist() if not info.is_dir()]
    if len(members) > MAX_MEMBERS:
        raise FileError(f"contains {len(members)} files")

    present = set()
    for info in members:
        _check_member_name(info.filename)
        if info.filename in UNSIGNED_MEMBERS:
            continue
        if info.filename not in files:
            raise FileError(f"carries {info.filename!r}, which {MANIFEST_NAME} does not cover")
        present.add(info.filename)

    missing = set(files) - present
    if missing:
        raise FileError(f"is missing {', '.join(sorted(missing))}")

    for name, expected in sorted(files.items()):
        if not isinstance(expected, str) or not expected.startswith("sha256:"):
            raise FileError(f"gives {name!r} a hash this version cannot check")
        digest = hashlib.sha256()
        with archive.open(name) as member:
            for block in iter(lambda: member.read(64 * 1024), b""):
                digest.update(block)
        if not hmac.compare_digest(digest.hexdigest().lower(),
                                   expected[len("sha256:"):].lower()):
            raise FileError(f"has a modified {name}")


def verify(path: str, *, profile: Profile) -> Verified:
    """Check a signed file and return it open, or raise saying why not.

    Raises SignatureError if the file was not signed by a key the profile
    trusts, FileError if it was but cannot be read, and VersionError if it is
    sound but needs a newer release. Nothing in the archive is imported,
    executed or written to disk here.
    """
    try:
        size = os.path.getsize(path)
    except OSError as error:
        raise FileError(f"could not be opened: {error}") from error
    if size > MAX_FILE_BYTES:
        raise FileError(f"is {size} bytes, too large to be a {profile.kind}")
    try:
        archive = zipfile.ZipFile(path)
    except Exception as error:  # BadZipFile, OSError, and whatever a hostile header raises
        raise FileError(f"could not be opened: {error}") from error

    try:
        manifest_bytes = _read_metadata(archive, MANIFEST_NAME)
        signature_bytes = _read_metadata(archive, SIGNATURE_NAME)

        # In this order, and only in this order: the manifest is untrusted
        # input until the signature over its exact bytes has been checked.
        key_id = _verify_signature(manifest_bytes, signature_bytes, profile)
        manifest = _parse_manifest(manifest_bytes, profile)
        _check_files(archive, manifest["files"])
        # Last, so "update the software" is only ever said of a module that is
        # the publisher's and arrived whole - updating would not fix anything
        # else.
        _check_app_version(manifest, profile)

        return Verified(
            path=path,
            id=manifest["id"],
            name=manifest.get("name") or manifest["id"],
            version=str(manifest.get("version", "")),
            module=manifest["module"],
            key_id=key_id,
            manifest=manifest,
            _archive=archive,
        )
    except (SignatureError, FileError, VersionError):
        archive.close()
        raise
    except Exception as error:
        # A member whose bytes fail their CRC, an encrypted or unsupported one,
        # a truncated stream: the file is damaged, and saying so is the
        # contract. Anything else escaping here would take down whatever was
        # loading the folder.
        archive.close()
        raise FileError(f"could not be read: {type(error).__name__}: {error}") from error
