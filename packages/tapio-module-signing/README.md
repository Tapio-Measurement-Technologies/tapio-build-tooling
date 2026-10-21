# tapio-module-signing

Verify, build and load signed modules: code a product loads at runtime -
plug-ins, postprocessors, custom analysis modules - checked before it runs.

A signed module is a zip holding the module's files, a `manifest.json` with a
SHA-256 for each of them, and a `signature.json`: an ECDSA P-256 signature over
the manifest, made by a key held in a key vault. The product pins the public
keys it trusts and refuses anything else before a byte of it is imported.

The format and every check are shared. What a product supplies is a
`Profile`:

```python
from tapio_module_signing import Loader, Profile

TRUSTED_KEYS = {
    "gadget-2026a": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",  # active
    "gadget-2026b": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",  # standby
}

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
    temp_prefix="gadget-modules-",
)
LOADER = Loader(PROFILE)
```

Keep the key table out of anything that can be overridden at run time. Never
change `context` once a file has been signed with it.

- `verify(path, profile=...)` returns a `Verified` holding the checked archive
  open, or raises `SignatureError`, `FileError` or `VersionError`.
- `Loader.load(verified)` unpacks it into a temporary directory and imports its
  module as `<package_root>.<id>.<module>`, so it can import the helpers it
  carries with `from . import helpers`.
- `prepare_install(path, folder, profile=...)` stages a chosen file in the
  folder, verifies that copy, and returns a `PendingInstall` to `commit()` or
  `discard()`.
- `build.main(argv, profile=...)` is the builder command
  `tapio-build signing sign` drives: `manifest`, `digest`, `pack`, `verify`.
  A product's builder script is its profile and that call.
- `pins.key_table_problems` and `pins.canary_problems` hold the key table to
  canaries signed by the vault; `testing` signs test modules the way the
  vault does.

## Installing

Released as a wheel on the tapio-build-tooling GitHub releases, tagged
`module-signing-v<version>`. Pin it by URL in `requirements.in`, without a
hash; the lock compiled from it carries the hash:

```
tapio-module-signing @ https://github.com/<owner>/tapio-build-tooling/releases/download/module-signing-v0.1.0/tapio_module_signing-0.1.0-py3-none-any.whl
```

## License

GPL-3.0-or-later. See `LICENSE`.
