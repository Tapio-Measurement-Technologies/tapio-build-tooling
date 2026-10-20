"""Build and sign a module as a signed file: the builder half of the format.

This is the one definition of how a signed file is written, and verify.py is
the one definition of how it is read. A product's tests build with this and
verify with that, so what its signing pipeline produces and what it accepts
cannot drift apart.

A module's source directory holds its module, anything the module needs, and
the product's source config (``Profile.source_config``)::

    id = "acme-mill-export"
    name = "ACME mill export"
    version = "1.2.0"
    min_app_version = "1.7.0"
    module = "mill_export.py"

``module`` is the file that is imported. Every other file in the directory is
carried and hashed too, so it can bring helpers and data, but only ``module``
is imported. One signed file is one module.

:func:`main` answers the four subcommands ``tapio-build signing sign`` drives,
so a product's builder script is a profile and a call::

    <builder> manifest --source DIR --out MANIFEST [--created ISO8601]
    <builder> digest --manifest MANIFEST
    <builder> pack --source DIR --manifest MANIFEST --key-id ID --signature=SIG --out FILE
    <builder> verify --file FILE
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Sequence
from datetime import datetime, timezone
import hashlib
import json
import os
import tomllib
import zipfile

from tapio_module_signing.profile import Profile
from tapio_module_signing.verify import (
    MANIFEST_NAME,
    MODULE_NAME_PATTERN,
    SIGNATURE_ALGORITHM,
    SIGNATURE_NAME,
    SUPPORTED_SCHEMA,
    UNSIGNED_MEMBERS,
    parse_app_version,
    verify,
)


def source_files(source: str, *, profile: Profile) -> list[str]:
    """Every file the module carries, as posix relative paths, sorted.

    A symbolic link is refused rather than followed: whatever it points at -
    anything the signing runner can read - would be signed and shipped as part
    of the module.
    """
    excluded = profile.excluded | {profile.source_config}
    found = []
    for root, dirs, names in os.walk(source):
        dirs[:] = sorted(d for d in dirs if d not in excluded)
        for name in [*dirs, *sorted(names)]:
            absolute = os.path.join(root, name)
            if os.path.islink(absolute):
                raise SystemExit(f"{absolute} is a symbolic link; a signed {profile.kind} "
                                 f"carries only files of its own")
        for name in sorted(names):
            if name in excluded or name.endswith(profile.excluded_suffixes):
                continue
            absolute = os.path.join(root, name)
            found.append(os.path.relpath(absolute, source).replace(os.sep, "/"))
    return sorted(found)


def read_source_config(source: str, *, profile: Profile) -> dict:
    path = os.path.join(source, profile.source_config)
    if not os.path.exists(path):
        raise SystemExit(f"{path} does not exist")
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def build_manifest(source: str, created: str | None = None, *, profile: Profile) -> dict:
    config = read_source_config(source, profile=profile)
    files = source_files(source, profile=profile)
    if not files:
        raise SystemExit(f"{source} holds no files to sign")

    # Each refused here rather than left to the verifier, which would refuse
    # the module at every site it was delivered to - after it had been signed.
    module_id = config.get("id")
    if not isinstance(module_id, str) or not profile.id_pattern.fullmatch(module_id):
        raise SystemExit(f"{profile.source_config} gives an unusable id {module_id!r}")

    module = config.get("module")
    if not isinstance(module, str) or not module:
        raise SystemExit(f"{profile.source_config} names no module")
    if module not in files:
        raise SystemExit(f"{profile.source_config} names {module}, which is not in {source}")
    if not MODULE_NAME_PATTERN.fullmatch(module):
        raise SystemExit(f"{profile.source_config} names {module}, which cannot be imported; "
                         f"the module is a .py file at the top of {source}, named as a "
                         f"Python identifier")
    reserved = sorted(UNSIGNED_MEMBERS.intersection(files))
    if reserved:
        raise SystemExit(f"{source} holds {', '.join(reserved)}, which the signed file "
                         f"writes itself")

    min_app_version = config.get("min_app_version", "")
    if min_app_version != "" and parse_app_version(min_app_version) is None:
        raise SystemExit(
            f"{profile.source_config} gives min_app_version {min_app_version!r}, "
            f"which is not a {profile.app_name} version like \"1.7.0\"")

    hashes = {}
    for name in files:
        with open(os.path.join(source, name), "rb") as handle:
            hashes[name] = "sha256:" + hashlib.sha256(handle.read()).hexdigest()

    manifest = {
        "schema": SUPPORTED_SCHEMA,
        "id": module_id,
        "name": config.get("name", module_id),
        "version": str(config.get("version", "0")),
        "publisher": config.get("publisher", profile.publisher),
        "created": created or datetime.now(timezone.utc).replace(
            microsecond=0).isoformat().replace("+00:00", "Z"),
        "min_app_version": min_app_version,
        "module": module,
        "files": hashes,
    }
    for name in profile.extra_fields:
        if name in config:
            manifest[name] = config[name]
    return manifest


def serialize_manifest(manifest: dict) -> bytes:
    """The exact bytes that get signed, and that go into the archive.

    Sorted keys and a fixed separator so that building the same source twice
    produces the same bytes - the signature is over these, so any wobble here
    is a signature that does not verify against the file that shipped.
    """
    return json.dumps(manifest, sort_keys=True, indent=2,
                      ensure_ascii=False).encode("utf-8") + b"\n"


def signing_digest(manifest_bytes: bytes, *, profile: Profile) -> str:
    """The SHA-256 the key vault is asked to sign, in standard base64.

    `az keyvault key sign --digest` passes its argument to Python's
    base64.b64decode, so it has to be standard base64 with its padding: the
    base64url the Key Vault REST API speaks, unpadded, fails there with
    "Incorrect padding".
    """
    digest = hashlib.sha256(profile.context + manifest_bytes).digest()
    return base64.b64encode(digest).decode("ascii")


def sign_with_key_file(manifest_bytes: bytes, key_file: str, *, profile: Profile) -> str:
    """Sign locally, for development. Releases are signed by the key vault."""
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    with open(key_file, "rb") as handle:
        key = load_pem_private_key(handle.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SystemExit(f"{key_file} is not an ECDSA private key")
    der = key.sign(profile.context + manifest_bytes, ec.ECDSA(crypto_hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    # Written the way the key vault returns it, so both paths produce the
    # same file and the verifier only has one form to read.
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode("ascii")


def normalize_signature(signature: str) -> str:
    """Accept standard base64, as az prints it, and base64url, as the REST API
    returns it, as the same thing."""
    text = signature.strip()
    if "-" in text or "_" in text:
        text = base64.b64encode(
            base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))).decode("ascii")
    elif len(text) % 4:
        text += "=" * (-len(text) % 4)
    return text


def pack(source: str, manifest: dict, manifest_bytes: bytes, key_id: str, signature: str,
         out: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    signature_bytes = json.dumps({
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "signature": normalize_signature(signature),
    }, sort_keys=True, indent=2).encode("utf-8") + b"\n"

    # Deflated and with a fixed timestamp, so that two builds of the same
    # source produce the same archive member for member - apart from the
    # signature, which cannot match: ECDSA draws a random nonce, so signing one
    # manifest twice gives two different signatures. Everything the signature
    # covers is reproducible, which is what lets a release be rebuilt and
    # checked against what shipped.
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        def write(name: str, data: bytes) -> None:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)

        write(MANIFEST_NAME, manifest_bytes)
        write(SIGNATURE_NAME, signature_bytes)
        for name in sorted(manifest["files"]):
            with open(os.path.join(source, name), "rb") as handle:
                write(name, handle.read())
    return out


def main(argv: Sequence[str] | None = None, *, profile: Profile,
         description: str | None = None) -> int:
    """The builder command a product's script hands its profile to."""
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser(
        "manifest", help=f"write {MANIFEST_NAME} for a {profile.kind} source")
    build.add_argument("--source", required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--created", help="ISO-8601 timestamp, for a reproducible build")

    digest = commands.add_parser("digest", help="print the digest the key vault signs")
    digest.add_argument("--manifest", required=True)

    check = commands.add_parser(
        "verify",
        help=f"check a {profile.extension} against the keys {profile.app_name} pins; "
             f"print what it is as JSON")
    check.add_argument("--file", required=True)

    packer = commands.add_parser("pack", help=f"assemble a signed {profile.extension}")
    packer.add_argument("--source", required=True)
    packer.add_argument("--out", required=True)
    packer.add_argument("--manifest", help="a manifest from the 'manifest' command")
    packer.add_argument("--key-id", required=True)
    signing = packer.add_mutually_exclusive_group(required=True)
    # az prints the signature in standard base64. Taken from the REST API it is
    # base64url, which can begin with "-": given as `--signature VALUE`,
    # argparse would read such a value as an option.
    signing.add_argument("--signature",
                         help="base64 signature from the key vault; pass it as "
                              "--signature=VALUE, so that one beginning with '-' "
                              "is not read as an option")
    signing.add_argument("--key-file", help="PEM private key, for development builds")
    packer.add_argument("--created")

    args = parser.parse_args(argv)

    if args.command == "manifest":
        manifest_bytes = serialize_manifest(
            build_manifest(args.source, args.created, profile=profile))
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "wb") as handle:
            handle.write(manifest_bytes)
        print(args.out)
        return 0

    if args.command == "digest":
        with open(args.manifest, "rb") as handle:
            print(signing_digest(handle.read(), profile=profile))
        return 0

    if args.command == "verify":
        # The check the product itself makes, with the keys it ships with: what
        # passes here loads at a site. The signing pipeline runs this before it
        # calls anything signed.
        try:
            verified = verify(args.file, profile=profile)
        except Exception as error:
            raise SystemExit(f"{args.file} does not verify: {error}")
        verified.close()
        print(json.dumps({"id": verified.id, "version": verified.version,
                          "key_id": verified.key_id}))
        return 0

    if args.manifest:
        with open(args.manifest, "rb") as handle:
            manifest_bytes = handle.read()
        manifest = json.loads(manifest_bytes)
    else:
        manifest = build_manifest(args.source, args.created, profile=profile)
        manifest_bytes = serialize_manifest(manifest)

    signature = args.signature or sign_with_key_file(manifest_bytes, args.key_file,
                                                     profile=profile)
    print(pack(args.source, manifest, manifest_bytes, args.key_id, signature, args.out))
    return 0
