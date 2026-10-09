"""Sign one module with a key held in Azure Key Vault.

What a signed module looks like belongs to the product: its manifest, the
context the digest is taken over, the file it is packed into and the keys its
verifier trusts all ship inside the product, which is where they are checked.
The product supplies a *builder* command that knows all of that and answers
four subcommands::

    <builder> manifest --source DIR --out MANIFEST
    <builder> digest --manifest MANIFEST       the SHA-256 to sign, standard base64
    <builder> pack --source DIR --manifest MANIFEST --key-id ID --signature=SIG --out FILE
    <builder> verify --file FILE                checks FILE against the keys the product
                                                pins; prints {"id", "version", "key_id"}

What every product shares is the rest, and that is here: asking the vault for
the signature in the encodings ``az keyvault key sign`` really uses, checking
what comes back, verifying the result against the product's own pinned keys
before calling it signed, and writing the record of what was issued.

``az keyvault key sign --digest`` hands its argument to Python's
``base64.b64decode``, so the digest must be standard base64 with its padding;
the CLI prints the signature under ``signature``, in standard base64. The
signature is passed to the builder as ``--signature=VALUE`` all the same, so a
base64url one - as the Key Vault REST API returns it - could not be read as an
option.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import subprocess
import tempfile

from tapio_build_tools.downloads.package import Runner, _subprocess_runner
from tapio_build_tools.evidence import sha256_file, utc_now
from tapio_build_tools.signing import SigningError

SIGNATURE_ALGORITHM = "ES256"
DIGEST_BYTES = 32
#: An ES256 signature as Key Vault makes it: r and s, 32 bytes each.
SIGNATURE_BYTES = 64


@dataclass(frozen=True)
class SigningRecord:
    """What was issued, for the record every signed module is kept in."""

    id: str
    version: str
    key_id: str
    key_name: str
    vault: str
    file: str
    file_sha256: str
    manifest_sha256: str
    commit: str
    run_url: str
    signed_at: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    def summary(self) -> str:
        """Markdown for $GITHUB_STEP_SUMMARY."""
        rows = "".join(f"| {key} | `{value}` |\n" for key, value in asdict(self).items() if value)
        return f"### Signed {self.id} {self.version}\n\n| | |\n|---|---|\n{rows}"


def _run(runner: Runner, args: list[str], what: str) -> str:
    try:
        return runner(args).stdout
    except FileNotFoundError as exc:
        raise SigningError(f"{args[0]} is not installed") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
        raise SigningError(f"{what} failed: {detail or exc}") from exc


def _decoded(value: str, length: int, what: str) -> bytes:
    """*value* as standard base64 of exactly *length* bytes, or why not."""
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SigningError(f"{what} is not standard base64: {value!r}") from exc
    if len(decoded) != length:
        raise SigningError(f"{what} is {len(decoded)} bytes, not {length}")
    return decoded


def _run_url(environ: Mapping[str, str]) -> str:
    server, repository, run = (environ.get(key, "") for key in (
        "GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"))
    if server and repository and run:
        return f"{server}/{repository}/actions/runs/{run}"
    return ""


def sign_and_pack(
    *,
    builder: Sequence[str],
    source: Path,
    output: Path,
    vault: str,
    key_name: str,
    key_id: str,
    created: str | None = None,
    runner: Runner = _subprocess_runner,
) -> str:
    """Build the manifest, have the vault sign its digest, pack the file.

    Returns the manifest's SHA-256. Does not verify: sign_module() does, and a
    canary is signed with a key the product does not pin yet.
    """
    builder = list(builder)
    if not builder:
        raise SigningError("no builder command given")
    output = Path(output)

    with tempfile.TemporaryDirectory(prefix="tapio-sign-") as work:
        manifest = Path(work) / "manifest.json"
        args = [*builder, "manifest", "--source", str(source), "--out", str(manifest)]
        if created:
            args += ["--created", created]
        _run(runner, args, "building the manifest")
        if not manifest.is_file():
            raise SigningError(f"the builder wrote no manifest to {manifest}")

        digest = _run(runner, [*builder, "digest", "--manifest", str(manifest)],
                      "taking the digest").strip()
        _decoded(digest, DIGEST_BYTES, "the digest the builder printed")

        signature = _run(runner, [
            "az", "keyvault", "key", "sign",
            "--vault-name", vault, "--name", key_name,
            "--algorithm", SIGNATURE_ALGORITHM, "--digest", digest,
            "--query", "signature", "--output", "tsv",
        ], f"signing with {key_name} in {vault}").strip()
        _decoded(signature, SIGNATURE_BYTES, "the signature the vault returned")

        output.parent.mkdir(parents=True, exist_ok=True)
        _run(runner, [
            *builder, "pack", "--source", str(source), "--manifest", str(manifest),
            "--key-id", key_id, f"--signature={signature}", "--out", str(output),
        ], "packing")
        manifest_sha256 = sha256_file(manifest)

    if not output.is_file():
        raise SigningError(f"the builder wrote nothing to {output}")
    return manifest_sha256


def sign_module(
    *,
    builder: Sequence[str],
    source: Path,
    output: Path,
    vault: str,
    key_name: str,
    key_id: str | None = None,
    created: str | None = None,
    runner: Runner = _subprocess_runner,
    environ: Mapping[str, str] = os.environ,
) -> SigningRecord:
    """Build, sign, pack and verify one module; return the record of it.

    *key_id* is the name the product's key table knows the key by, and
    defaults to the key's name in the vault: keeping the two the same leaves
    nothing to map. The module is not reported signed until the product's own
    verifier has accepted the file, so a key the product does not pin - or a
    builder that disagrees with its verifier - stops the run here rather than
    at a site.
    """
    builder = list(builder)
    key_id = key_id or key_name
    output = Path(output)
    manifest_sha256 = sign_and_pack(
        builder=builder, source=source, output=output, vault=vault,
        key_name=key_name, key_id=key_id, created=created, runner=runner)

    printed = _run(runner, [*builder, "verify", "--file", str(output)],
                   "verifying against the product's pinned keys")
    try:
        verified = json.loads(printed)
    except ValueError as exc:
        raise SigningError(f"the builder's verify printed no JSON: {printed!r}") from exc
    if verified.get("key_id") != key_id:
        raise SigningError(
            f"{output} verified with key {verified.get('key_id')!r}, not {key_id!r}")

    return SigningRecord(
        id=str(verified.get("id", "")),
        version=str(verified.get("version", "")),
        key_id=key_id,
        key_name=key_name,
        vault=vault,
        file=output.name,
        file_sha256=sha256_file(output),
        manifest_sha256=manifest_sha256,
        commit=environ.get("GITHUB_SHA", ""),
        run_url=_run_url(environ),
        signed_at=utc_now(),
    )
