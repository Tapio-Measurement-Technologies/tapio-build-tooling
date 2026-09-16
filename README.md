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
- `actions/python-release-checks`: config, lock freshness, audit, no artifact
- `actions/python-release-evidence`: optional audit and artifact-bound PyInstaller SBOM
- `actions/node-supply-chain`: npm lock validation, source SBOM, audit
- `actions/publish-downloads`: package a release, publish its download pages to S3

A release workflow runs `python-release-checks` before it builds anything and
`python-release-evidence` after the artifact is signed, with `audit: 'false'`
on the evidence step. Evidence binds to a signed artifact, so it cannot run
until signing is done; keeping the checks in a separate earlier step means a
stale lock or a known vulnerability stops the run before the build spends time
or the signing certificate is used.

This repository runs the source-evidence action against itself on pushes, pull
requests, a weekly schedule, and manual dispatch. Generated CycloneDX evidence is
uploaded as the `tapio-build-tooling-source-sbom` workflow artifact.

Pin action use to full commit SHA. Push tooling repository before consumer changes
that reference that SHA.

## Release downloads

`tapio-build downloads publish` turns a release's build outputs into a static
download site in an S3 bucket, one prefix per program:

```
<slug>/index.html             permanent page; always offers the latest release
<slug>/versions/index.html    every release, newest first
<slug>/releases.json          the manifest the pages are written from
<slug>/<version>/index.html   the page for one release
<slug>/<version>/<files>      that release's files; never rewritten
```

The manifest is the source of truth. Each publish fetches it, adds the
release, writes every page from the result and uploads files before the pages
that link them. The permanent page is written last, and only when the release
is the newest by version - a patch to an older line is published without
displacing it. A tag with a hyphen (`v1.3.0-beta.1`) is a pre-release and is
refused. Publishing the same version again with the same files is a no-op;
with different files it fails unless `--force` is given.

Pages load nothing from anywhere else, carry `noindex, nofollow, noarchive`
unless the program is marked `indexable`, and show every operating system's
download; a few lines of inline script move the visitor's own first. Links are
relative and spell out `index.html`, so a tree written with `--output-dir` can
be opened from disk, and the S3 REST endpoint - which has no index document -
serves it as it is.

### Configure

Add a `downloads` table to `build-tooling.toml`. Deployment settings - bucket,
public URL, region, IAM role - are not configuration and stay in the
consumer's repository variables.

```toml
[downloads]
contact = "downloads@example.com"    # inherited by programs; must be an address
logo = "src/assets/logo.png"         # optional; .png or .svg, inlined into every page

[downloads.programs.app]
product = "example-app"              # a configured product; optional when there is one
slug = "example-app"                 # bucket prefix and file-name prefix: [a-z0-9-]
name = "Example App"
notes = "Nothing to install: save the program anywhere and run it."
source-package = true                # git archive of the tag, offered on the page
indexable = true                     # let search engines index the pages
listed = true                        # name the program on the bucket-root index page

[[downloads.programs.app.assets]]
os = "windows"                       # windows | linux | macos
arch = "x86_64"                      # x86_64 | aarch64; default x86_64
glob = "dist/example-app-${version}.exe"   # ${version} is the tag; exactly one match
archive = "none"                     # zip | tar.gz | none; default zip on Windows, tar.gz elsewhere
sbom = "dist/example-app-${version}.cdx.json"   # optional; linked from the page
```

`source-package` needs the product's `license-id`: the page names the licence
and carries a written offer of the corresponding source, which is published in
the same prefix as the binary and stays there for as long as it does. A
`tar.gz` archive forces the executable bit, which workflow artifacts drop.
Files are named `<slug>-<version>-<os>-<arch>.<ext>`, the source
`<slug>-<version>-source.tar.gz`.

### Run

```bash
tapio-build --project . downloads publish --version v1.4.0 \
  --bucket BUCKET --base-url https://downloads.example.com
tapio-build --project . downloads publish --version v1.4.0 \
  --bucket BUCKET --base-url https://downloads.example.com \
  --dry-run --existing-manifest /dev/null --output-dir /tmp/site   # preview from disk
tapio-build --project . downloads render --program app \
  --manifest releases.json --output-dir /tmp/site                  # pages from a manifest
```

Uploads go through the `aws` CLI with the credentials in the environment;
`--dry-run` still reads the bucket unless `--existing-manifest` supplies the
manifest. The output directory receives the site tree, `summary.json`,
`release-notes.md` (Markdown linking every file, for the GitHub release) and
`aws-commands.txt`. `--root-index` also writes a bucket-root `index.html`
listing every program that has a manifest; `tapio-build downloads root-index
--bucket BUCKET` writes that page on its own, for a hand that can write the
root when the release roles cannot.

### GitHub Action

```yaml
- uses: Tapio-Measurement-Technologies/tapio-build-tooling/actions/publish-downloads@<sha>
  id: downloads
  with:
    version: ${{ github.ref_name }}
    bucket: ${{ vars.DOWNLOADS_BUCKET }}
    base-url: ${{ vars.DOWNLOADS_BASE_URL }}
    aws-region: ${{ vars.DOWNLOADS_AWS_REGION }}
    aws-role-to-assume: ${{ vars.DOWNLOADS_AWS_ROLE_ARN }}
- run: gh release edit "$TAG" --notes-file "$NOTES" --latest="$LATEST"
  env:
    GH_TOKEN: ${{ github.token }}
    TAG: ${{ github.ref_name }}
    NOTES: ${{ steps.downloads.outputs.release-notes-file }}
    LATEST: ${{ steps.downloads.outputs.latest }}
```

The job needs `id-token: write` for the role and a checkout of the tag (the
source archive is read from it). `force` can only come from a manual run: a
tag push has no inputs, and the workflow file is read from the tagged commit.
Give the workflow a `workflow_dispatch` boolean input, pass it as
`force: ${{ inputs.force == true }}`, and run it on the tag -
`gh workflow run build.yml --ref v1.4.0 -f force=true` - to replace what that
version has published. Make the release step tolerate an existing release
(`gh release upload --clobber` when `gh release view` succeeds), or the re-run
fails before it reaches the action. The next patch version is the normal
answer to a bad release; this is for a version that must not stay out. Outputs: `published`, `prerelease`, `latest`,
`page-urls`, `release-notes-file`, `summary-file`; a pre-release publishes
nothing and still writes notes saying so. The role needs `s3:GetObject` and
`s3:PutObject` under `<bucket>/<slug>/*` and `s3:ListBucket` on the bucket
with an `s3:prefix` condition of `<slug>/*` - without it a missing manifest
is a 403, which is an error, rather than a 404, which is the first release.
Only `--root-index` writes the bucket root. Serialise release jobs with a
`concurrency` group: two publishes racing on one manifest keep only the last.
`robots.txt` belongs to the bucket's owner, not the tooling.

## License

GPL-3.0-or-later. See `LICENSE`.
