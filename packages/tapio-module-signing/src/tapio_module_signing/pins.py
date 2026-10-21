"""The keys a product trusts, checked against the keys that really sign.

The public keys in a product's table are pasted in by hand. A key that is cut
short, on the wrong curve, pasted twice under two ids, or simply not the key
the vault holds is noticed by nothing else: every other test signs with a key
it made itself. It would surface at a site, as a module refused for a
signature that does not verify.

So the table is checked twice over. Each entry must load as an ECDSA P-256
public key, and no two entries may be the same key. And for each entry there
is a canary - a module that does nothing, signed once by the vault with that
key, kept as ``<key id><extension>`` in one directory - which must verify
against the table exactly as it ships.

A product's tests call both and expect no problems. With the table empty they
pass having checked nothing, so a product also refuses to release with an
empty table.
"""

from __future__ import annotations

import json
import os
import zipfile

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tapio_module_signing.profile import Profile
from tapio_module_signing.verify import SIGNATURE_NAME, is_signed_file, load_public_key, verify


def key_table_problems(*, profile: Profile) -> list[str]:
    """Everything wrong with the profile's trusted keys, one sentence each."""
    problems = []
    seen: dict[bytes, str] = {}
    for key_id in sorted(profile.trusted_keys):
        try:
            key = load_public_key(key_id, profile=profile)
        except Exception as error:
            problems.append(f"{key_id}: {error}")
            continue
        der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if der in seen:
            problems.append(f"{key_id} is the same key as {seen[der]}")
        else:
            seen[der] = key_id
    return problems


def canary_problems(canary_dir: str, *, profile: Profile) -> list[str]:
    """Every way the canaries and the trusted keys disagree, one sentence each."""
    extension = profile.extension
    canaries = {
        name[:-len(extension)]: os.path.join(canary_dir, name)
        for name in sorted(os.listdir(canary_dir)) if is_signed_file(name, profile=profile)
    }
    problems = []
    for key_id in sorted(profile.trusted_keys):
        if key_id not in canaries:
            problems.append(f"{key_id} is trusted but has no {key_id}{extension} canary")
    for key_id, path in canaries.items():
        if key_id not in profile.trusted_keys:
            problems.append(
                f"{os.path.basename(path)} is a canary for a key that is not "
                f"trusted; delete it along with the key")
            continue
        # Named before verifying: a canary for one key signed by another
        # trusted key would verify, and prove nothing about the key it is for.
        with zipfile.ZipFile(path) as archive:
            signed_by = json.loads(archive.read(SIGNATURE_NAME)).get("key_id")
        if signed_by != key_id:
            problems.append(
                f"{os.path.basename(path)} is signed with {signed_by!r}, not {key_id!r}")
            continue
        try:
            verify(path, profile=profile).close()
        except Exception as error:
            problems.append(f"{os.path.basename(path)} does not verify: {error}")
    return problems
