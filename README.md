# Tapio Build Tooling

Shared supply-chain tooling for Tapio products. Current adapters support Python
requirements and npm package locks, vulnerability audits, and CycloneDX SBOM
evidence. Ecosystem layout allows later PlatformIO adapters without changing
existing interfaces.

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

Requirement compilation uses uv's universal resolver so one hashed lock includes
platform-specific dependencies for Linux, macOS, and Windows.

## Node/npm commands

```bash
tapio-build --project . node audit
tapio-build --project . node sbom --product PRODUCT --output sbom.cdx.json
```

Node evidence uses `package-lock.json` without omitting development or optional
dependencies. `npm audit` fails on any reported vulnerability.

## GitHub Actions

- `actions/python-supply-chain`: lock freshness, source SBOM, audit
- `actions/python-release-evidence`: optional audit and artifact-bound PyInstaller SBOM
- `actions/node-supply-chain`: npm lock validation, source SBOM, audit

This repository runs the source-evidence action against itself on pushes, pull
requests, a weekly schedule, and manual dispatch. Generated CycloneDX evidence is
uploaded as the `tapio-build-tooling-source-sbom` workflow artifact.

Pin action use to full commit SHA. Push tooling repository before consumer changes
that reference that SHA.

## License

GPL-3.0-or-later. See `LICENSE`.
