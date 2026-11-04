# tapio-update-check

Tell a product's user that a newer release is out, from the manifest the
download site already publishes.

`tapio-build downloads publish` writes a `releases.json` beside each
program's permanent download page:

```
<base-url>/<slug>/               the download page, always the newest release
<base-url>/<slug>/releases.json  every published release, never a pre-release
```

This library is the part of an update check that every product shares:

```python
import tapio_update_check as updates

url = updates.manifest_url(BASE_URL, SLUG)          # what to fetch
page = updates.download_page_url(BASE_URL, SLUG)    # where to send the user

latest = updates.parse_manifest(payload, expected_slug=SLUG)
offer = updates.update_to_offer(latest, running_version, skipped_version)
if offer:
    ...  # tell the user, with a button that opens `page`
```

- `parse_manifest` returns the newest final release's tag as the manifest
  wrote it ("v1.6.5"), or None. It skips entries it cannot read and
  pre-releases, finds the newest by version rather than by position, and
  raises `ManifestError` for anything that is not a schema-1 manifest. With
  `expected_slug`, a manifest written for another program is refused.
- `update_to_offer` returns that tag only if it is newer than the running
  version and is not the one the user chose to skip. A running version that is
  not a release - `"(development version)"` from a run from source - is
  offered nothing, so a developer is never asked.
- `parse_version` reads a tag with or without its "v" and returns None for
  anything that is not a version.

What stays in the product:

- **Fetching.** A Qt product uses `QNetworkAccessManager`; a Tk product uses
  `urllib` in a thread. Whatever fetches it should verify TLS against the
  operating system's trust store, refuse a redirect away from https, and cap
  the size of what it reads. The manifest is small (a few KB).
- **Consent.** Ask before the first check, remember the answer, and let the
  user change it in the product's settings.
- **The notice**, and remembering a skipped release.
- **The base URL and slug.** Nothing here names a deployment.

The library depends on `packaging` and nothing else.

## Releasing

Released as a wheel from an `update-check-v<version>` tag on main by
`.github/workflows/release-library.yml`, the same way as
`tapio-module-signing`, and pinned by URL in a product's `requirements.in`:

```
tapio-update-check @ https://github.com/<owner>/<repo>/releases/download/update-check-v<version>/tapio_update_check-<version>-py3-none-any.whl
```

The manifest format itself is written by `tapio_build_tools.downloads.manifest`
in this repository; `tests/test_update_check_contract.py` holds the reader
here to what that writer produces.

## License

GPL-3.0-or-later. See `LICENSE`.
