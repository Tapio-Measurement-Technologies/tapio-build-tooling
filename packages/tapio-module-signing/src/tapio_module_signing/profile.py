"""What a product says about its signed modules. Everything else is shared.

The format, the checks and the order they run in are the same for every
product. What differs is held here: the keys a product trusts, the context its
signatures are taken over, the extension its files carry, what it calls them in
a message, and which version of it is running.

A product builds one Profile and passes it to everything in this package. It
keeps its key table out of any module that can be overridden at run time - a
settings file read from the command line, say - since whoever can change the
table can choose which keys the product trusts.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import re

#: Lowercase letters and digits, joined by single hyphens or dots. An id names
#: a source directory, an installed file, a directory a module is unpacked
#: into and a package in sys.modules, so it is kept to what is safe in all of
#: them.
DEFAULT_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:[.\-][a-z0-9]+)*$")

#: Never carried into a signed file: build leavings and editor droppings, which
#: would otherwise be hashed and shipped as though they were part of it, and
#: the documentation beside the source - a README, an example settings file -
#: which is for whoever installs it, and is unreadable once packed.
DEFAULT_EXCLUDED = frozenset({"__pycache__", ".git", ".gitignore", "README.md"})
DEFAULT_EXCLUDED_SUFFIXES = (".pyc", ".pyo", "~", ".example.toml")

#: Manifest fields the format itself defines. A product's extra fields are
#: carried beside them and may not shadow one.
CORE_FIELDS = frozenset({
    "schema", "id", "name", "version", "publisher", "created",
    "min_app_version", "module", "files",
})


# eq=False: compared and hashed by identity. A profile holds a mutable key
# table on purpose - tests patch it in place - so it must never be hashed by
# value.
@dataclass(frozen=True, eq=False)
class Profile:
    #: The product, as messages name it: "requires RollView 1.8.0 or later".
    app_name: str
    #: What a signed module is called in this product, as messages name it:
    #: "too large to be a postprocessor".
    kind: str
    #: Prefixed to the manifest before signing and before verifying, so a
    #: signature made for this product's modules can only ever be read as one.
    #: Without it, a signature over some other JSON the same key was asked to
    #: sign would verify as a manifest. Never changed once a file is signed.
    context: bytes
    #: The extension of a signed file, with its dot: ".tpp".
    extension: str
    #: The public halves of the keys whose signatures are accepted, by the key
    #: id a file names in its signature: base64 of the SubjectPublicKeyInfo DER.
    #: Read on every check rather than copied, so a test that patches the
    #: product's table patches what is checked.
    trusted_keys: Mapping[str, str]
    #: The version of the product doing the checking, or None when it has
    #: none - a source run, a build from something other than a release tag.
    #: Called on every check, so pass a function that looks the version up
    #: then: a test patching the product's own function is then obeyed.
    running_version: Callable[[], str | None]
    #: The file in a module's source directory that describes it, e.g.
    #: "postprocessor.toml". Read by the builder; never packed.
    source_config: str
    #: Written into each manifest unless the source names its own.
    publisher: str
    #: The package every loaded module is imported beneath, so two modules
    #: that both name their file export.py stay apart in sys.modules.
    package_root: str
    #: The prefix of the temporary directories modules are unpacked into.
    temp_prefix: str
    id_pattern: re.Pattern[str] = DEFAULT_ID_PATTERN
    #: Further fields a source config may set, carried into the signed
    #: manifest when it does and left out when it does not - so adding one to
    #: a profile changes no manifest already built.
    extra_fields: tuple[str, ...] = ()
    excluded: frozenset[str] = DEFAULT_EXCLUDED
    excluded_suffixes: tuple[str, ...] = DEFAULT_EXCLUDED_SUFFIXES

    def __post_init__(self) -> None:
        if not self.extension.startswith(".") or self.extension != self.extension.lower():
            raise ValueError(f"extension {self.extension!r} must be lowercase and start with '.'")
        shadowed = sorted(CORE_FIELDS.intersection(self.extra_fields))
        if shadowed:
            raise ValueError(f"extra fields shadow the format's own: {', '.join(shadowed)}")
        if not self.context:
            raise ValueError("a profile needs a signing context")
