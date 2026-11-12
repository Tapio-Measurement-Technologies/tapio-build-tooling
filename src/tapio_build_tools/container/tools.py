"""syft and grype, from their GitHub releases, at pinned versions with pinned digests.

Each build is pinned twice: the release archive by the SHA-256 Anchore's
checksums file gives it, and the binary inside by its own SHA-256. The archive
digest is checked once, when it is downloaded; the binary's every time a
command is about to run it, so a binary changed on disk since it was installed
is refused rather than run. Nothing is fetched by a script and nothing is piped
into a shell.

To move a pin: take a release that is past the cooldown, download its
`<tool>_<version>_checksums.txt` and its `.sigstore.json` bundle, verify the
bundle against the identity
`https://github.com/anchore/<tool>/.github/workflows/release.yaml@refs/heads/main`
(issuer `https://token.actions.githubusercontent.com`), take each archive's
digest from the file, and hash the binary each archive holds.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import platform as host
import tarfile
import tempfile
from typing import BinaryIO, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

from tapio_build_tools.container import ContainerError

USER_AGENT = "tapio-build-tooling"
TIMEOUT_SECONDS = 120
CHUNK = 1 << 20
# Several times what either tool weighs, as a stop for a download or an
# archive member that keeps going: the digest is only checked at the end.
MAXIMUM_ARCHIVE_BYTES = 256 << 20
MAXIMUM_BINARY_BYTES = 512 << 20


@dataclass(frozen=True)
class Build:
    """One platform's release archive and the binary it holds."""

    archive_sha256: str
    binary_sha256: str


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    repository: str
    builds: dict[str, Build]

    def archive(self, platform: str) -> str:
        return f"{self.name}_{self.version}_{platform}.tar.gz"

    def url(self, platform: str) -> str:
        return (f"https://github.com/{self.repository}/releases/download/"
                f"v{self.version}/{self.archive(platform)}")

    def build(self, platform: str) -> Build:
        try:
            return self.builds[platform]
        except KeyError as exc:
            raise ContainerError(
                f"no pinned {self.name} build for {platform}; pinned: {', '.join(self.builds)}"
            ) from exc


# Both released 2026-11-02, grype 0.121.1 built on syft 1.56.0. Later releases
# fix advisories in their own Go dependencies; take them once they are past
# the cooldown.
SYFT = Tool("syft", "1.56.0", "anchore/syft", {
    "linux_amd64": Build(
        "1c2493cfcf52d3367d6cb25780d9190c111c2219c34c820574c43e8bae15c528",
        "20572660f157af9f9bd4db5541e89f306ad108cdec0376eabd7d682ed98cbf2d",
    ),
    "linux_arm64": Build(
        "ace61b9397ae28189c674ae332d67a8074dafd71e87724dfb8b22412d8253bb5",
        "4d0a13ee6990168e7eba965a687e790c5067ba901729c2ebe060ab5388c0f929",
    ),
})
GRYPE = Tool("grype", "0.121.1", "anchore/grype", {
    "linux_amd64": Build(
        "bc3ea3f9e6fd56ac781c08c6c5e614271b79f438200757f6932085c19b0a4657",
        "497a3587a0a9fbce68888dffc7cb80670ddf92d827ca49939e430a02168e7c91",
    ),
    "linux_arm64": Build(
        "33670612aad351c48cf3c37f4a85d8b043d1b64b21e6034e675bb00b956d78c1",
        "11ce78fe1ee658ac519f53c3f04b110203d2f1ea3ab98a14c88cc92523a2a8ca",
    ),
})
TOOLS = (SYFT, GRYPE)


def current_platform(system: str | None = None, machine: str | None = None) -> str:
    """The release platform this host runs, as Anchore names it."""
    system = (system or host.system()).lower()
    machine = (machine or host.machine()).lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if system != "linux" or arch is None:
        raise ContainerError(f"no pinned scanner builds for {system} {machine}; Linux x86_64 or "
                             f"aarch64 is needed, as on a GitHub-hosted Ubuntu runner")
    return f"{system}_{arch}"


def default_directory() -> Path:
    """Where the scanners are kept: the runner's temp in Actions, a user cache elsewhere."""
    if os.environ.get("RUNNER_TEMP"):
        return Path(os.environ["RUNNER_TEMP"]) / "tapio-container-tools"
    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return cache / "tapio-build-tooling" / "tools"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, destination: BinaryIO, *, limit: int = MAXIMUM_ARCHIVE_BYTES) -> None:
    """Write what *url* serves into *destination*, stopping past *limit* bytes.

    GitHub redirects a release asset to its asset host. Nothing about the
    response is trusted until the caller checks the digest, so its size is
    capped here, before that.
    """
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            written = 0
            for chunk in iter(lambda: response.read(CHUNK), b""):
                written += len(chunk)
                if written > limit:
                    raise ContainerError(f"{url} is larger than {limit} bytes; stopped")
                destination.write(chunk)
    except (URLError, OSError) as exc:
        raise ContainerError(f"downloading {url} failed: {exc}") from exc


def _extract(tool: Tool, archive: Path, target: Path) -> None:
    """Write the one regular file named like *tool* at the archive's root to *target*."""
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = [member for member in bundle.getmembers() if member.name == tool.name]
            if len(members) != 1 or not members[0].isreg():
                raise ContainerError(f"{archive.name} holds no single {tool.name} binary")
            [member] = members
            if member.size > MAXIMUM_BINARY_BYTES:
                raise ContainerError(f"{archive.name}: {tool.name} is {member.size} bytes")
            source = bundle.extractfile(member)
            assert source is not None
            with source, target.open("wb") as written:
                for chunk in iter(lambda: source.read(CHUNK), b""):
                    written.write(chunk)
    except (tarfile.TarError, OSError) as exc:
        raise ContainerError(f"{archive.name} could not be read: {exc}") from exc


def install(
    tool: Tool,
    directory: Path,
    *,
    platform: str | None = None,
    fetch: Callable[[str, BinaryIO], None] = download,
) -> Path:
    """*tool*'s binary under *directory*, checked against its pin; call it just before a run.

    A binary already there is checked against its pin before it is returned;
    one that does not match is replaced from the release, which is checked
    in turn. A mismatch in the download is an error, and leaves nothing.
    """
    platform = platform or current_platform()
    build = tool.build(platform)
    home = directory / f"{tool.name}-{tool.version}-{platform}"
    binary = home / tool.name
    if binary.is_file() and sha256_of(binary) == build.binary_sha256:
        return binary

    home.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{tool.name}-", dir=home) as work:
        archive = Path(work) / tool.archive(platform)
        with archive.open("wb") as stream:
            fetch(tool.url(platform), stream)
        found = sha256_of(archive)
        if found != build.archive_sha256:
            raise ContainerError(f"{tool.url(platform)} has SHA-256 {found}; "
                                 f"{build.archive_sha256} is pinned")
        extracted = Path(work) / tool.name
        _extract(tool, archive, extracted)
        found = sha256_of(extracted)
        if found != build.binary_sha256:
            raise ContainerError(f"{tool.name} in {archive.name} has SHA-256 {found}; "
                                 f"{build.binary_sha256} is pinned")
        extracted.chmod(0o755)
        os.replace(extracted, binary)
    return binary
