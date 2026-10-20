"""Install a signed module into the operator's folder, checked before it lands.

The folder is where the product looks, so a file copied into it unchecked
would only be refused at the next load - after the operator had been told it
was installed. The check happens here instead, on the copy that is going to be
installed rather than on the file that was chosen: the chosen file is read
once, written beside the folder's contents under a name the product ignores,
and that copy is what is verified and, once the operator confirms, renamed
into place. Nothing in it is imported here; that is the loader's job, and the
product checks again when it does.

Installing in two steps - prepare_install(), then commit() or discard() - is
what lets the operator see what they are about to install, and what it
replaces, between the check and the change to the folder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import tempfile

from tapio_module_signing.profile import Profile
from tapio_module_signing.verify import FileError, VersionError, is_signed_file, verify

#: A module is a file and a few helpers, a few hundred kilobytes at most.
#: Anything this size was picked by mistake, and is not read into memory.
MAX_FILE_BYTES = 64 * 1024 * 1024

#: The staged copy is named so the product passes it by: it reads only signed
#: files - and, where it allows them, loose .py ones - and this is neither.
STAGING_PREFIX = ".installing-"
STAGING_SUFFIX = ".part"


@dataclass(frozen=True)
class InstalledCopy:
    """A file already in the folder that holds the module being installed."""

    path: str
    version: str


@dataclass
class PendingInstall:
    """A verified module, staged in the folder, waiting to be confirmed."""

    id: str
    name: str
    version: str
    staged_path: str
    target_path: str
    #: Every file in the folder holding the same module. Removed once the new
    #: one is in place, so an update never leaves the old one beside it.
    replaces: list[InstalledCopy] = field(default_factory=list)
    #: What the verified manifest said, for a product that shows more of it.
    manifest: dict = field(default_factory=dict)

    @property
    def is_update(self) -> bool:
        return bool(self.replaces)

    @property
    def is_reinstall(self) -> bool:
        """The same version is already installed: installing again repairs it."""
        return any(copy.version == self.version for copy in self.replaces)

    @property
    def replaced_version(self) -> str:
        """The version being replaced, as the operator would read it."""
        versions = sorted({copy.version for copy in self.replaces if copy.version})
        return ", ".join(versions)

    def commit(self) -> None:
        """Move the staged copy into place and remove what it replaces.

        os.replace is atomic within one folder, so the product never sees half
        a file under the final name, and a copy already at that name - the
        same module, installed before - is overwritten in the same step.
        """
        os.replace(self.staged_path, self.target_path)
        for copy in self.replaces:
            if os.path.normcase(os.path.abspath(copy.path)) != \
                    os.path.normcase(os.path.abspath(self.target_path)):
                try:
                    os.remove(copy.path)
                except FileNotFoundError:
                    pass

    def discard(self) -> None:
        try:
            os.remove(self.staged_path)
        except FileNotFoundError:
            pass


def identify(path: str, *, profile: Profile) -> tuple[str, str] | None:
    """Which module a file in the folder holds, and its version.

    None for a file that cannot be told: unsigned, damaged, not a signed
    file. A file written for a newer release is still identified - its
    signature verified before the version was looked at - so installing over
    one that the running release cannot load still replaces it.
    """
    try:
        verified = verify(path, profile=profile)
    except VersionError as error:
        return error.id, error.version
    except Exception:
        return None
    verified.close()
    return verified.id, verified.version


def installed_copies(folder: str, module_id: str, *, profile: Profile,
                     skip: str | None = None) -> list[InstalledCopy]:
    copies = []
    for filename in sorted(os.listdir(folder)):
        path = os.path.join(folder, filename)
        if path == skip or not is_signed_file(filename, profile=profile) \
                or not os.path.isfile(path):
            continue
        identified = identify(path, profile=profile)
        if identified is not None and identified[0] == module_id:
            copies.append(InstalledCopy(path=path, version=identified[1]))
    return copies


def prepare_install(source_path: str, folder: str, *, profile: Profile,
                    max_bytes: int = MAX_FILE_BYTES) -> PendingInstall:
    """Check a chosen signed file and stage it in *folder*, ready to be confirmed.

    Raises what verify raises for a file that would not load, and OSError if
    it cannot be read or written. Nothing is left in the folder when it
    raises; when it returns, the caller must commit() or discard().
    """
    size = os.path.getsize(source_path)
    if size > max_bytes:
        raise FileError(f"is {size} bytes, too large to be a {profile.kind}")
    with open(source_path, "rb") as handle:
        data = handle.read()

    os.makedirs(folder, exist_ok=True)
    descriptor, staged_path = tempfile.mkstemp(
        dir=folder, prefix=STAGING_PREFIX, suffix=STAGING_SUFFIX)
    try:
        with os.fdopen(descriptor, "wb") as staged:
            staged.write(data)
        verified = verify(staged_path, profile=profile)
        verified.close()

        return PendingInstall(
            id=verified.id,
            name=verified.name,
            version=verified.version,
            staged_path=staged_path,
            target_path=os.path.join(folder, verified.id + profile.extension),
            replaces=installed_copies(folder, verified.id, profile=profile,
                                      skip=staged_path),
            manifest=verified.manifest,
        )
    except BaseException:
        try:
            os.remove(staged_path)
        except FileNotFoundError:
            pass
        raise
