# Tapio Build Tooling

Shared supply-chain tooling for Tapio products. Current adapter supports Python
requirements, vulnerability audits, and CycloneDX SBOM evidence. Ecosystem layout
allows later Node and PlatformIO adapters without changing Python interfaces.

## Install

Use repository's hashed tooling lock:

```bash
python -m pip install --require-hashes -r requirements.txt
python -m pip install --no-deps .
```

## Configure

Add `build-tooling.toml` to consumer repository. See `examples/` for supported
layouts. Validate before other commands:

```bash
tapio-build --project . config validate
```

## Python commands

```bash
tapio-build --project . python requirements compile
tapio-build --project . python requirements compile --check
tapio-build --project . python requirements compile --upgrade
tapio-build --project . python audit --group runtime
tapio-build --project . python sbom --group runtime --product PRODUCT --output sbom.cdx.json
```

End-user installs remain standard `pip install -r requirements.txt`.

## GitHub Actions

- `actions/python-supply-chain`: lock freshness, source SBOM, audit
- `actions/python-release-evidence`: optional audit and artifact-bound PyInstaller SBOM

Pin action use to full commit SHA. Push tooling repository before consumer changes
that reference that SHA.

## License

GPL-3.0-or-later. See `LICENSE`.

