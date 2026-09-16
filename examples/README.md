# Compatibility Examples

Example configurations are stored outside consumer repositories for validation.
Copy chosen file to consumer root as `build-tooling.toml` before adoption.

| Repository | Dependency evidence | Release capability |
| --- | --- | --- |
| tapio-analysis | Lock-only combined dependency set | PyInstaller |
| rqp-configurator | Complete npm package lock | Source only |

The `downloads-*.toml` files are not tied to a repository. They show the two
shapes of a `downloads` table: one copyleft program publishing its source
beside the binary, and one product shipped as several programs for several
operating systems. Product and program names in them are placeholders.

| Example | Shape |
| --- | --- |
| downloads-single-program | One GPL program, Windows only, source archive and SBOM published |
| downloads-program-suite | One proprietary product, two programs, Windows and Linux |

Lock-only groups cannot be regenerated. Every locked component is conservatively
connected as direct root dependency. Add input files later to enable lock freshness
checks and precise direct dependency graphs.

PyInstaller evidence requires final artifact, for example:

```bash
tapio-build --project /path/to/repository --config /path/to/example.toml python sbom \
  --group combined --product tapio-analysis --output /tmp/product.cdx.json \
  --version 1.0.0 --artifact dist/product.exe --artifact-kind pyinstaller
```
