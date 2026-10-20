"""Unpack a verified module and import it.

Nothing here decides whether a module is trustworthy - verify.py does that,
and this module will not touch an archive it has not been handed as a
Verified. What it adds is the part after the check: writing the files out
somewhere they can be imported from, and importing the module under a name
that cannot collide with another module's or with anything else in the
program.

Modules are unpacked into a temporary directory rather than into the folder
the operator installs them in. That folder stays a place that holds the signed
files they put there; nothing appears in it that they did not.
"""

from __future__ import annotations

import atexit
from collections.abc import Mapping
import importlib.util
import os
import re
import shutil
import sys
import tempfile
import types

from tapio_module_signing.profile import Profile
from tapio_module_signing.verify import Verified, verify

_UNSAFE = re.compile(r"[^a-z0-9_]+")

#: A reload cannot delete the directory the modules it is replacing were
#: imported from - on Windows the files are still open, and on any platform a
#: module may be mid-run - so a generation is kept until the one after it has
#: replaced it.
GENERATIONS_KEPT = 2


def package_name(module_id: str) -> str:
    """A module id as a Python identifier, without losing which it was."""
    return _UNSAFE.sub("_", module_id.lower()).strip("_") or "module"


class Loader:
    """Unpacks and imports one product's verified modules.

    One per product, for the life of the process: it owns the temporary
    directories modules are unpacked into, newest generation first, and
    removes them at exit.
    """

    def __init__(self, profile: Profile, *, kept: int = GENERATIONS_KEPT) -> None:
        self.profile = profile
        self.kept = kept
        #: Unpacked generations, newest first. Mutated in place, never
        #: replaced, so whoever holds it sees the current list.
        self.generations: list[str] = []
        atexit.register(self.discard)

    def start_generation(self) -> str:
        """Begin a fresh unpacking round. Called once per reload."""
        root = tempfile.mkdtemp(prefix=self.profile.temp_prefix)
        self.generations.insert(0, root)
        for stale in self.generations[self.kept:]:
            # ignore_errors because a virus scanner or an editor may still hold
            # a handle open on Windows. A directory left behind is litter in
            # the system's temporary folder, not a failure worth stopping a
            # reload for.
            shutil.rmtree(stale, ignore_errors=True)
        del self.generations[self.kept:]
        return root

    def current_generation(self) -> str:
        if not self.generations:
            return self.start_generation()
        return self.generations[0]

    def discard(self) -> None:
        """Drop every unpacked module. Called at exit, and by tests."""
        for root in self.generations:
            shutil.rmtree(root, ignore_errors=True)
        self.generations.clear()

    def _unpack(self, verified: Verified, root: str) -> str:
        unpacked_dir = os.path.join(root, package_name(verified.id))
        os.makedirs(unpacked_dir, exist_ok=True)
        archive = verified.open()
        for name in sorted(verified.manifest["files"]):
            # The names were checked against escaping when the file was
            # verified; joining them here is safe because of that, not in
            # spite of it.
            target = os.path.join(unpacked_dir, *name.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with archive.open(name) as member, open(target, "wb") as out:
                shutil.copyfileobj(member, out)
        return unpacked_dir

    def _install_package(self, verified: Verified, unpacked_dir: str) -> str:
        """A package for the module, so it can import the helpers it carries.

        Gives the module `from . import helpers` and leaves `import helpers`
        failing, which is what keeps one module's helper from being picked up
        by another module - or by the application.
        """
        root_name = self.profile.package_root
        name = f"{root_name}.{package_name(verified.id)}"
        if root_name not in sys.modules:
            root_package = types.ModuleType(root_name)
            root_package.__path__ = []
            sys.modules[root_name] = root_package
        # What an earlier load of this module imported beneath its package.
        # Left in sys.modules, a reload after an update would hand the new
        # module the old version of any helper it imports.
        for stale in [key for key in sys.modules if key.startswith(name + ".")]:
            del sys.modules[stale]
        package = types.ModuleType(name)
        package.__path__ = [unpacked_dir]
        sys.modules[name] = package
        return name

    def _import_module(self, package: str, unpacked_dir: str, member: str,
                       attributes: Mapping[str, object]) -> types.ModuleType:
        stem = os.path.splitext(os.path.basename(member))[0]
        full_name = f"{package}.{stem}"
        path = os.path.join(unpacked_dir, *member.split("/"))

        spec = importlib.util.spec_from_file_location(full_name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # Registered before it is executed, so that a helper importing it back
        # part-way through its own import finds it rather than loading it
        # twice, and so that dataclasses, which look their module up by name,
        # work in it.
        sys.modules[full_name] = module
        # Set before its code runs, so the module can name itself - for its
        # settings file, say - without repeating the id its manifest gives.
        for key, value in attributes.items():
            setattr(module, key, value)
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(full_name, None)
            raise
        return module

    def load(self, verified: Verified, *, attributes: Mapping[str, object] | None = None,
             root: str | None = None) -> types.ModuleType:
        """Unpack a module that has been verified, and import it.

        Takes the Verified rather than a path, so that what is imported is
        what was checked, and closes it: the archive has been read by the time
        this returns, and what the manifest said stays on the object.
        """
        try:
            unpacked_dir = self._unpack(
                verified, root if root is not None else self.current_generation())
            package = self._install_package(verified, unpacked_dir)
            return self._import_module(package, unpacked_dir, verified.module,
                                       attributes or {})
        finally:
            verified.close()

    def load_file(self, path: str, *, attributes: Mapping[str, object] | None = None,
                  root: str | None = None) -> tuple[Verified, types.ModuleType]:
        """Verify a signed file, unpack it, and import its module.

        Raises whatever verify raises, before anything is written or run.
        """
        verified = verify(path, profile=self.profile)
        return verified, self.load(verified, attributes=attributes, root=root)
