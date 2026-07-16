# Compatibility Examples

Example configurations are stored outside consumer repositories for validation.
Copy chosen file to consumer root as `build-tooling.toml` before adoption.

| Repository | Dependency evidence | Release capability |
| --- | --- | --- |
| tapio-analysis | Lock-only combined dependency set | PyInstaller |
| rqp-configurator | Complete npm package lock | Source only |

Lock-only groups cannot be regenerated. Every locked component is conservatively
connected as direct root dependency. Add input files later to enable lock freshness
checks and precise direct dependency graphs.

PyInstaller evidence requires final artifact, for example:

```bash
tapio-build --project /path/to/repository --config /path/to/example.toml python sbom \
  --group combined --product tapio-analysis --output /tmp/product.cdx.json \
  --version 1.0.0 --artifact dist/product.exe --artifact-kind pyinstaller
```
