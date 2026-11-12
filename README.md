# Tapio Build Tooling

Shared supply-chain tooling for Tapio products. Current adapters support Python
requirements and npm package locks, vulnerability audits, and CycloneDX SBOM
evidence, container image SBOMs and scans, release download pages and private
build archives. Ecosystem layout
allows later PlatformIO adapters without changing existing interfaces.

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
tapio-build --project . python cooldown --group runtime
tapio-build --project . python audit --group runtime
tapio-build --project . python sbom --group runtime --product PRODUCT --output sbom.cdx.json
```

End-user installs remain standard `pip install -r requirements.txt`.

Requirement compilation uses uv's universal resolver so one hashed lock includes
platform-specific dependencies for Linux, macOS, and Windows.

## Node/npm commands

```bash
tapio-build --project . node cooldown
tapio-build --project . node audit
tapio-build --project . node sbom --product PRODUCT --output sbom.cdx.json
```

Node evidence uses `package-lock.json` without omitting development or optional
dependencies. `node audit` fails on any reported vulnerability, whatever its
severity, that is not an [accepted risk](#accepted-risks).

## Release cooldown

A supply-chain attack on a package arrives as a version published minutes ago
and is usually spotted and pulled within hours. `cooldown-days` keeps a release
out of a lock until it has sat on the index that long:

```toml
[ecosystems.python]
version = "3.12"
cooldown-days = 7

[ecosystems.node]
version = "24"
package = "package.json"
lock = "package-lock.json"
cooldown-days = 7
```

It applies in two places.

**While a lock is compiled.** `python requirements compile` hands uv
`--exclude-newer` at that many days ago, which uv compares against the upload
time of each distribution file, so a fresh release is never a candidate.

The cutoff only binds where the resolver is free to choose: without `--upgrade`
uv keeps the pins already in the lock, so an advancing cutoff never turns a
current lock stale and `compile --check` stays stable. A release younger than
the window - a security fix, say - is taken with `--no-cooldown`, which leaves
the decision in the commit that made it:

```bash
tapio-build --project . python requirements compile --upgrade --no-cooldown
```

Until that release is older than the window, though, uv's cutoff leaves it
unsatisfiable, so `compile --check` and `cooldown` both refuse the lock. Name
it as a [cooldown exception](#cooldown-exceptions) to keep both passing.

**Once a lock is written.** The `cooldown` commands read the lock itself and
ask the index when each release in it appeared:

```bash
tapio-build --project . python cooldown --group runtime
tapio-build --project . node cooldown
```

Both fail naming every release that is too young, newest first. This is the
only enforcement an npm lock gets, because npm writes it; for Python it covers
a lock hand-edited or compiled elsewhere. `--days` checks a window other than
the configured one, and a project that configures none passes without asking
the index anything.

Python releases are dated through their hashes: the files behind the `--hash`
lines are the ones dated, and a hash no file on PyPI has is an error rather
than a pass. A lock-only group carries no hashes, and its releases are dated
whole. npm releases are dated by the registry's publication time, and a tarball
resolved from anywhere but the public registry is refused.

A Python lock may also pin a wheel by URL, as long as it is an asset of a
GitHub release - a first-party library such as `tapio-module-signing`. Write
it in `requirements.in` without a hash; the compiled lock carries one:

```
tapio-module-signing @ https://github.com/<owner>/<repo>/releases/download/<tag>/<wheel>
```

`cooldown` dates it by the later of its upload and its release, through the
GitHub API, and refuses it unless the asset's digest is the lock's hash - a
replaced asset is an error, not a pass. The actions hand the API the job's
token. Any other URL in a lock is refused by `cooldown`, `audit` and `sbom`
alike. `audit` names each URL wheel as not audited - PyPI does not know it -
audits its dependencies like any other pin, and fails on anything else it
cannot audit. The SBOM gives the wheel the version and hash the lock pins.

`audit` still fails on a known vulnerability inside the window, so a cooldown
delays a fix rather than hiding the need for one.

### Cooldown exceptions

A release taken inside the window on purpose is named, with the reason, in the
ecosystem it belongs to:

```toml
[[ecosystems.node.cooldown-exceptions]]
package = "follow-redirects"
version = "1.16.3"                 # this release only; a later one waits as usual
reason = "Fixes GHSA-xxxx-xxxx-xxxx in 1.16.2; taken 2026-11-11 with npm install."
review-by = 2026-11-30             # optional: stop excepting it after this date

[[ecosystems.python.cooldown-exceptions]]
package = "certifi"
version = "2026.10.19"
reason = "Fixes PYSEC-2026-4320; taken with compile --no-cooldown."
```

`cooldown` lets the release through, printing it with its reason, for as long
as it is younger than the window and, with a `review-by`, through that date. A
release still inside the window after its `review-by` fails again, and the
error says the exception lapsed. Once the release is older than the window the
entry does nothing; `cooldown` then flags it as a warning - an annotation in
GitHub Actions - so it is removed, and does the same for an entry naming a
release the lock does not pin. With several requirement groups, a group's
check flags an entry only when no group's lock pins that release: a group
pinning the package at another version leaves it to the group that pins it.

For Python, `python requirements compile` also gives uv a cutoff of its own for
each excepted package, `--exclude-newer-package <name>=<upload time + 1s>`,
looked up on PyPI. That keeps the excepted release satisfiable without
admitting a still newer one, so `compile --check` passes and a later
`compile --upgrade` keeps the fix instead of falling back below it. An
exception whose release is past the window gets no such cutoff: the global one
already allows it. Nor does a package an input or lock requires by URL - a
GitHub release wheel: uv takes a URL requirement as written and never holds it
back by the cutoff, and PyPI does not know it to date it. With exceptions
configured, `compile` and `compile --check` therefore need PyPI reachable,
and fail naming the entry they could not date. The entries need
`cooldown-days` in the same table; names are compared as the ecosystem
compares them (PEP 503 names and PEP 440 versions for Python, exactly for
npm).

## Accepted risks

An advisory a product carries on purpose - a fix it cannot take yet, a
vulnerability its use never reaches - is recorded beside the ecosystem's
other settings, with the package it applies to, why it is accepted, and when
that is to be looked at again:

```toml
[[ecosystems.python.accepted-risks]]
id = "GHSA-h35f-9h28-mq5c"         # PYSEC-, GHSA- or CVE- id
package = "setuptools"
reason = "zappa 0.60.2 pins setuptools<80; used at build time only. Risk R-08."
review-by = 2027-01-31             # a TOML date, or "2027-01-31"

[[ecosystems.node.accepted-risks]]
id = "GHSA-gcqx-w48m-w2h4"         # GHSA only: npm audit names nothing else
package = "deepmerge"
reason = "Pulled in by react-data-table-component 7.x; merges our own column config only."
review-by = 2027-03-31
```

`python audit` and `node audit` then:

- accept a finding when an entry names its package and one of its ids - for
  Python the advisory's own id or any alias pip-audit gives it, so a CVE id
  covers the PYSEC and GHSA records of the same vulnerability;
- print every finding with how it was judged: `accepted` with the entry and
  its reason, `vulnerable`, or `no longer accepted`;
- fail on any finding no entry accepts, and on any whose entries are past
  their `review-by` - an entry applies through that date, not after it, and
  the error names the entry and the date;
- flag, as a warning annotation in GitHub Actions, every entry that matches no
  finding, so a fixed or withdrawn advisory's entry is removed rather than
  left to accept something nobody has looked at.

`id`, `package`, a non-empty `reason` and `review-by` are all required; the
same id for the same package twice is an error. Python package names are
compared as PEP 503 normalises them.

pip-audit's own `--ignore-vuln` is not used: it drops an id from every package
and does not say what it dropped, so it could neither tie an entry to its
package nor tell a stale entry from a used one. `python audit` reads
pip-audit's JSON report (`--format json --aliases on`) and applies the entries
itself. npm audit has no per-advisory ignore at all, and its severity floor
would wave through everything under it unread, so `node audit` reads
`npm audit --json`: each advisory there is named by its GitHub URL, which
gives the GHSA id, and a package that is vulnerable only through a dependency
carries no advisory of its own - accepting the dependency's covers both. An
advisory npm gives no GHSA URL for cannot be accepted and always fails. npm
lists every installed copy of a vulnerable package; a copy outside the
advisory's range is left out, and one whose range cannot be read is kept.

### Why per ecosystem

Entries sit in `[ecosystems.python]` and `[ecosystems.node]`, not in each
requirement group:

- An acceptance is a judgement about a package release - the risk analysis
  names the package and the advisory - not about which lock happens to pin
  it. A package pinned in two groups carries the same risk in both, and one
  entry per group would be copies free to drift apart, with different reasons
  and review dates for the same thing.
- An entry names its package, so sharing it across groups cannot accept an
  advisory in some other package.
- Groups are a Python notion; npm has one lock. Per ecosystem is the one
  shape both read, and the one a [scan of a container image](#container-images),
  which holds packages of both ecosystems and no groups at all, reuses.

The cost is in telling a stale entry from another group's. Each audit sees one
lock, and a group pinning a fixed release says nothing about a group that
pins a vulnerable one. So with several groups an audit calls an entry stale
only when no other group's lock pins its package; where another does, an
entry this lock matches nothing for is printed as not matched in this group,
not flagged for removal.

## Container images

A product shipped as a container image gets an SBOM of the image itself and a
vulnerability scan of it, on every build. A registry's basic scan, such as
ECR's, reads the operating-system packages once, when the image is pushed;
this one also sees the Python and npm packages the image installed, and fails
the build.

```bash
tapio-build --project . container tools                 # download and verify syft and grype
tapio-build --project . container sbom --image example-backend:local \
  --output dist/image.cdx.json --product example-backend --version 1.4.0
tapio-build --project . container scan --sbom dist/image.syft.json \
  --report dist/image-vulnerabilities.json --image example-backend:local
```

`sbom` reads the image from the local Docker daemon, where the job built it -
no registry is asked - and has [syft](https://github.com/anchore/syft) write
two documents from one pass: the CycloneDX SBOM kept as evidence and syft's
own JSON, beside it as `<name>.syft.json` unless `--syft-output` says
otherwise. `scan` has [grype](https://github.com/anchore/grype) read that
JSON back, writes grype's JSON report, prints grype's table, and fails on any
finding at or above the threshold **with a fix available** that no accepted
risk covers. A finding below the threshold, or one the distribution has not
fixed or will not fix, is counted and passes. A severity grype does not know
counts as at the threshold.

```toml
[container]
fail-on = "high"                   # negligible | low | medium | high | critical; high by default

[[container.accepted-risks]]
id = "CVE-2026-12345"              # CVE or GHSA
package = "openssl-libs"           # an rpm, deb, apk, or language package in the image
reason = "The base image's fix is not released yet; the function terminates no TLS itself."
review-by = 2026-12-31
```

The `container` table is optional - without it the scan fails on `high` - and
is configuration enough on its own, for a repository with no lock to audit.
Entries have the shape and the rules of the [accepted risks](#accepted-risks)
above. A container entry covers a package of any kind; for a Python or npm
package in the image, that ecosystem's entries apply as well, so the risk
accepted for the lock is accepted for the image without a second entry. An id
matches grype's id for the finding or any related vulnerability it lists, so a
CVE covers a distribution advisory (`ALAS2023-…`, `DSA-…`) raised for it.
grype names Python advisories by GHSA and CVE, never PYSEC: an ecosystem
entry the image scan should honour uses one of those. A Python entry by PYSEC
id is named in a warning when the image holds a finding on its package that
no entry accepts, which is when it may have been meant to. Only container
entries are flagged when they match nothing; an ecosystem's are its own
audit's to flag. `--fail-on` overrides the configured threshold. The summary
line counts the findings that gate - at or above the threshold with a fix -
apart from those that pass anyway, each with how many were accepted.

### Why grype

grype reads the SBOM syft has just written, so the scan judges exactly the
packages the published SBOM lists, and the image is catalogued once. Trivy
would bring a second cataloguer whose idea of the image's contents could
differ from the SBOM's. grype's report also carries what the gate needs per
match: the fix state (`fixed`, `not-fixed`, `wont-fix`, `unknown`) with the
fixed versions, and the related CVEs behind a distribution's advisory. syft
and grype come from one project with one release process - a checksums file
per release, signed with Sigstore by the release workflow - so one way of
pinning covers both.

### The scanners

`container tools` downloads each scanner's release archive from its GitHub
release at the version `src/tapio_build_tools/container/tools.py` pins,
checks the archive against its pinned SHA-256 - stopping a download past
256 MiB before that - extracts the one binary, and checks that against its
own pinned SHA-256. `sbom` and `scan` install the same
way if needed, and check the binary's digest again every time before they run
it. A mismatch is an error and leaves nothing behind. Builds are pinned for
Linux x86_64 and aarch64, the GitHub-hosted runners; nothing is fetched by a
script or piped into a shell. Both scanners run in an empty directory with
every `SYFT_*` and `GRYPE_*` variable removed, so a `.grype.yaml` in the
repository or a variable in the job cannot ignore matches or leave packages
out. grype fetches its vulnerability database at run time, as it must to be
current, and checks it itself.

The pins are syft 1.56.0 and grype 0.121.1, whose checksum files were
verified against Anchore's release-workflow identity with Sigstore. To move
them, take releases past the cooldown and follow the steps in the module's
docstring.

### GitHub Action

```yaml
- run: docker build --tag "example-backend:${GITHUB_SHA}" backend
- uses: Tapio-Measurement-Technologies/tapio-build-tooling/actions/container-supply-chain@<sha>
  with:
    image: example-backend:${{ github.sha }}
    product: example-backend
    upload-name: example-backend-image-sbom
```

The action sets up Python, installs the tooling from its hashed lock,
validates the configuration, downloads and verifies the scanners, writes the
SBOM and uploads it as the `upload-name` artifact, then scans. The grype
report is uploaded as `<upload-name>-vulnerabilities`, also when the scan
fails. Inputs: `image` (required), `config`, `product`, `version`, `output`
(`dist/image.cdx.json`), `report` (`dist/image-vulnerabilities.json`),
`fail-on`, `scan` (`'false'` writes and uploads the SBOM only), `upload-name`,
`python-version`. Outputs: `sbom-file`, `report-file`. The job needs nothing
beyond `contents: read`. `.github/workflows/container-supply-chain.yml` runs
it against a fixture image on both runner architectures.

## GitHub Actions

- `actions/python-supply-chain`: lock freshness, release ages, source SBOM, audit
- `actions/python-release-checks`: config, lock freshness, release ages, audit, no artifact
- `actions/python-release-evidence`: optional audit and artifact-bound PyInstaller SBOM
- `actions/node-supply-chain`: npm lock validation, release ages, source SBOM, audit
- `actions/container-supply-chain`: image SBOM with syft, uploaded; grype scan that fails on fixable findings
- `actions/publish-downloads`: package a release, publish its download pages to S3
- `actions/publish-release-notes`: put a GitHub release's notes on its download pages
- `actions/builder-image`: build the image a build runs in and push it to GHCR
- `actions/publish-archive`: bundle a build's prepared files and upload them to a private bucket
- `actions/sign-module`: sign one module with a key in Azure Key Vault, verify it, record it
- `actions/keep-signed-module`: keep a signed module and its record as a pre-release

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
security-contact = "security@example.com"   # optional, inherited; where a vulnerability is reported
logo = "src/assets/logo.png"         # optional; .png or .svg, inlined into every page

[downloads.programs.app]
product = "example-app"              # a configured product; optional when there is one
slug = "example-app"                 # bucket prefix and file-name prefix: [a-z0-9-]
name = "Example App"
notes = "Nothing to install: save the program anywhere and run it."
source-package = true                # git archive of the tag, offered on the page
indexable = true                     # let search engines index the pages
listed = true                        # name the program on the bucket-root index page
support-years = 5                    # optional; security updates promised this long after the newest release

[[downloads.programs.app.assets]]
os = "windows"                       # windows | linux | macos
arch = "x86_64"                      # x86_64 | aarch64; default x86_64
glob = "dist/example-app-${version}.exe"   # ${version} is the tag; exactly one match
archive = "none"                     # zip | tar.gz | none; default zip on Windows, tar.gz elsewhere
sbom = "dist/example-app-${version}.cdx.json"   # optional; linked from the page
```

`support-years` puts "Security updates are provided in the latest version,
free of charge, until at least <month year>" on every page of the program,
counted from the newest release, so the date moves forward with each release
and never promises more than that many years at once. `security-contact` adds
where to report a security issue. Both are shown unfolded.

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
root when the release roles cannot. The page reads each program's
`releases.json` in the browser and shows the newest release it names, so a
release that cannot write the root still shows there; run `root-index` again
only to add a program or rename one.

### Release notes

The notes written on a GitHub release can be shown on the version's page:

```bash
tapio-build --project . downloads notes --version v1.4.0 --notes-file body.md --bucket BUCKET
```

The Markdown is rendered by a small converter - headings, paragraphs, lists,
fenced code, emphasis, inline code and `http(s)`/`mailto` links - with every
character escaped first, so markup in the notes is shown rather than run. The
`publish-release-notes` action wraps it for a workflow on the `release` event:

```yaml
on:
  release:
    types: [published, edited]
```

with a step that writes `gh release view "$TAG" --json body --jq .body` to a
file and passes it as `notes-file`. A version the site never published is
reported and left alone. An empty file clears the notes. The notes appear on
the page folded, under a "Release notes" heading the visitor can open.

A release event runs the workflow file of the tag's own commit, so a release
tagged before the workflow existed never triggers it; put its notes on the
pages with the command above instead.

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

### Telling users about a newer release

A product that offers its users a newer release reads `<slug>/releases.json`
with `packages/tapio-update-check`: where the manifest and the page are, which
release in it is the newest final one, and whether to offer it to the running
copy. Fetching it, asking consent and showing the notice stay in the product.
`tests/test_update_check_contract.py` holds that reader to the manifest this
tooling writes. It is released from an `update-check-v<version>` tag by
`.github/workflows/release-library.yml` and pinned by URL like
`tapio-module-signing`. See its README.

## Release archives

`tapio-build archive publish` keeps a build's outputs in a private bucket,
one prefix per build, in the same shape as a download site:

```
<slug>/<archive-id>/<file>                              each file the build prepared
<slug>/<archive-id>/build.json                          commit, builder image, workflow run, archive ID
<slug>/<archive-id>/<zip>                               the files and build.json together
<slug>/<archive-id>/<slug>-<archive-id>-builder.tar.gz  a release's builder image
<slug>/<archive-id>/SHA256SUMS                          every file above, by bare name
```

The archive ID is the tag of a tag push, or the tag a manual run is given as
`--release-tag`; any other run is `run-<number>-sha-<12-character commit>`. A
build that is not a release is archived all the same - it is what a push to
the default branch left - but only a release keeps the image it was built in,
because the image is hundreds of megabytes and only a release is worth
rebuilding byte for byte years later. The `run-` prefix is also what a
lifecycle rule can expire without touching a release.

The build decides what goes in and the tooling only names, bundles, sums and
uploads it, so nothing about a particular product - its file formats, flash
layout or build steps - lives here. Every file lands under its own name; two
with one name, or one named like a file the archive writes itself, is an
error. `SHA256SUMS` is uploaded last, so an archive that has one is whole, and
`sha256sum -c SHA256SUMS` works in a downloaded copy of the prefix. A GitHub
release carries the zip and `SHA256SUMS` but not the image; check it with
`sha256sum -c --ignore-missing SHA256SUMS`.

### Configure

An `archive` table is enough on its own: a project without a Python or npm
lock - firmware, say - needs no `ecosystems` table beside it. Bucket, region,
role and retention are not configuration and stay in the consumer's
repository variables.

```toml
[archive]
product = "example-firmware"               # a configured product; optional when there is one
slug = "example-firmware"                  # bucket prefix and file-name prefix: [a-z0-9-]
zip = "example_firmware-${version}.zip"    # optional; "<slug>-${version}.zip" by default
files = ["dist/package/firmware.hex"]      # project-relative globs; each must match a file
```

`${version}` in `zip` is the archive ID.

### Run

```bash
tapio-build --project . archive names --release-tag v1.4.0
tapio-build --project . archive publish --release-tag v1.4.0 \
  --builder-image example-firmware-builder:local --bucket BUCKET --dry-run \
  --output-dir /tmp/archive                                     # write it, list the uploads
tapio-build --project . archive publish --output-dir /tmp/archive   # write it, no bucket at all
```

`names` prints `slug`, `archive-id`, `release-tag`, `builder-repository` and
`builder-image` as `key=value` lines for `$GITHUB_OUTPUT`; outside Actions a
`--release-tag` is required, since there is no run number to name the build
by. `--retention-days` locks every upload in governance mode for that long;
the bucket needs Object Lock enabled for it. Uploads go through the `aws` CLI
with the credentials in the environment, and the output directory receives
the archive under `<slug>/<archive-id>/`, `summary.json` and, given a bucket,
`aws-commands.txt`.

### GitHub Actions

```yaml
jobs:
  builder:
    permissions: {contents: read, packages: write}
    outputs:
      ref: ${{ steps.builder.outputs.ref }}
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/setup-python@<sha>
        with: {python-version: '3.12'}
      - uses: Tapio-Measurement-Technologies/tapio-build-tooling/actions/builder-image@<sha>
        id: builder

  build:
    needs: builder
    permissions: {contents: write, packages: read, id-token: write}
    steps:
      # check out, pull ${{ needs.builder.outputs.ref }}, build and test in it,
      # copy the files to archive where build-tooling.toml's archive.files says
      - uses: actions/setup-python@<sha>
        with: {python-version: '3.12'}
      - uses: Tapio-Measurement-Technologies/tapio-build-tooling/actions/publish-archive@<sha>
        id: archive
        with:
          release-tag: ${{ inputs.release_tag }}
          builder-image: ${{ needs.builder.outputs.ref }}
          bucket: ${{ github.event_name != 'pull_request' && vars.S3_ARCHIVE_BUCKET || '' }}
          aws-region: ${{ vars.AWS_REGION }}
          aws-role-to-assume: ${{ vars.AWS_ROLE_TO_ASSUME }}
          retention-days: ${{ vars.S3_OBJECT_LOCK_RETENTION_DAYS }}
```

`builder-image` builds the Dockerfile in `context` as
`ghcr.io/<owner>/<slug>-builder:sha-<commit>` and pushes it on every run, pull
requests included, since the build that follows pulls it; only a push to the
default branch also moves `latest`. It needs `packages: write` and no AWS
access. `publish-archive` saves the builder image from the build job, after
the build has passed, so a failed build never leaves half an archive; the
job has therefore pulled the image already. An empty `bucket` writes the
archive without uploading it, which is what a pull request gets. Outputs:
`archive-id`, `release-tag` (empty unless a release), `zip-file`, `sums-file`,
`archive-dir`, `summary-file` - enough to upload the archive as a workflow
artifact and to attach the zip and `SHA256SUMS` to a GitHub release.

Python comes from the calling workflow: the tooling will not install into the
runner's system Python. The role needs only `s3:PutObject`,
`s3:PutObjectRetention` and `s3:AbortMultipartUpload` under
`<bucket>/<slug>/*`; nothing is read back. Serialise builds of one ref with a
`concurrency` group, as a re-run of a release uploads the same keys again.

## License

GPL-3.0-or-later. See `LICENSE`.

## Module signing

A product that loads code at runtime - plug-ins, postprocessors - can require
that code to be signed. The keys live in one Azure Key Vault shared by every
product; each product gets its own:

```
<product>-<year>a   active key: the only one its signing pipeline may use
<product>-<year>b   standby: pinned by the product, disabled in the vault
```

and its own signing identity: an app registration whose one federated
credential is one GitHub environment in the product's repository, and whose one
role is Key Vault Crypto User on that product's active key. A key per product
keeps a leak of one product's pipeline from signing what another product
would load; a signing context the product prefixes cannot, because whoever
signs chooses it.

### The library

`packages/tapio-module-signing` is the verifier a product ships, and the
builder its signing pipeline runs: the manifest and signature format, the
checks in the order they must run, the staged install, unpacking and
importing, and the checks that hold a key table to its canaries. A product
describes itself in a `Profile` - the keys it pins, the context its
signatures are taken over, its file extension, what it calls a module - and
its builder script is that profile handed to `tapio_module_signing.build.main`.
See its README.

It is released as a wheel from a `module-signing-v<version>` tag on main, by
`.github/workflows/release-library.yml`, and a product pins it by URL
as above.

### The builder

What a signed module looks like - its manifest, the context its digest is
taken over, its file format, the keys that verify it - belongs to the product,
which ships the verifier. The product supplies a builder command answering:

```
<builder> manifest --source DIR --out MANIFEST [--created ISO8601]
<builder> digest --manifest MANIFEST       SHA-256 to sign, standard base64 with padding
<builder> pack --source DIR --manifest MANIFEST --key-id ID --signature=SIG --out FILE
<builder> verify --file FILE                checks FILE against the product's pinned keys
                                            and prints {"id", "version", "key_id"}
```

`az keyvault key sign --digest` passes its argument to Python's
`base64.b64decode`, so the digest must be standard base64; unpadded base64url
fails there with "Incorrect padding". The CLI prints the signature under
`signature`, in standard base64.

### Provision a product

```bash
tapio-build signing provision \
  --subscription SUBSCRIPTION_ID --resource-group RG --location REGION \
  --vault VAULT --product PRODUCT --repository OWNER/NAME --reviewer LOGIN \
  [--canary-builder "python scripts/build_module.py" \
   --canary-source path/to/canary --canary-dir path/to/canaries \
   --canary-extension .tpp] \
  --dry-run
```

Creates what is missing and leaves what is right: the Key Vault provider
registration, the group, the vault (Standard, Azure RBAC, purge protection,
90-day soft delete), both keys, a canary per key if asked, the identity, its
federated credential, its role on the active key, and the GitHub environment -
limited to one branch, a named reviewer, with the identity's IDs as secrets
and `SIGNING_VAULT` and `SIGNING_KEY_NAME` as variables. `--no-reviewer`
sets the environment up without a reviewer instead, and anyone who can push to
the branch can then sign. It prints the public keys in the form a product's key
table holds them.

The signed-in user is given Key Vault Crypto Officer on the vault for the run
and loses it at the end, even when a step fails (`--keep-admin` keeps it). A
rerun changes nothing except that role and enabling the standby long enough to
read its public key. `--dry-run` performs every lookup and prints every change
instead of making it. Purge protection cannot be turned off once the vault
has it; to try a new setup out first, pass `--no-purge-protection`, and run
again without it once everything works - that run turns it on.

Nothing about a deployment lives here. Keep the concrete invocation - which
subscription, vault, products and reviewers - in the product's private
repository.

### Sign in a workflow

```yaml
jobs:
  sign:
    runs-on: ubuntu-latest
    environment: module-signing
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@<sha>
        with:
          persist-credentials: false
      - uses: actions/setup-python@<sha>
        with:
          python-version: "3.12"
      - uses: Tapio-Measurement-Technologies/tapio-build-tooling/actions/sign-module@<sha>
        with:
          builder: python scripts/build_module.py
          source: modules/example
          expect-id: example
          output: dist/example.tpp
          record: dist/signing-record.json
          vault: ${{ vars.SIGNING_VAULT }}
          key-name: ${{ vars.SIGNING_KEY_NAME }}
          azure-client-id: ${{ secrets.AZURE_CLIENT_ID }}
          azure-tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          azure-subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

The action verifies the signed file with the product's own builder before
calling it signed, so a key the product does not pin stops the run, and writes
a record - id, version, key, manifest and file SHA-256, commit, run - to the
job summary and to `signing-record.json`. With `expect-id` it also fails
unless the module verifies as that id.

### Keep what was signed

Hand the signed file and its record to a second job, which may write to the
repository and cannot sign:

```yaml
  keep:
    needs: sign
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@<sha>
        with:
          name: signed-module
          path: dist
      - uses: actions/setup-python@<sha>
        with:
          python-version: "3.12"
      - uses: Tapio-Measurement-Technologies/tapio-build-tooling/actions/keep-signed-module@<sha>
        with:
          files: dist/*.tpp
          record: dist/signing-record.json
          tag-prefix: module
          kind: module
```

It keeps them as a pre-release tagged `<tag-prefix>/<id>/v<version>`, never
Latest. Signing the same content again changes nothing; different content
under a version already issued is refused, so raise the version instead.
