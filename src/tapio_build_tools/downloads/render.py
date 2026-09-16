"""The pages of a program's download site, written from its manifest.

Every page is complete on its own: the stylesheet is inline, the logo is
inlined, and nothing is fetched from anywhere else, so the page looks the
same behind a customer's proxy as it does here. Links between pages and to
the files are relative, so the same tree works from a bucket and from a
directory opened in a browser.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import html
from importlib import resources
from pathlib import Path
import posixpath
from string import Template

from tapio_build_tools.config import DownloadProgram, OPERATING_SYSTEMS
from tapio_build_tools.downloads.manifest import Asset, Manifest, Release, latest


ROBOTS = '<meta name="robots" content="noindex, nofollow, noarchive">\n'

# Reorders the buttons so the visitor's own operating system comes first and
# is the one painted solid. Without it every button is solid and in the order
# the configuration lists them, which is a complete page too.
SCRIPT = """\
<script>
(function () {
  var data = navigator.userAgentData;
  var platform = ((data && data.platform) || navigator.platform || "").toLowerCase();
  var os = "";
  if (platform.indexOf("win") === 0) { os = "windows"; }
  else if (platform.indexOf("mac") === 0) { os = "macos"; }
  else if (platform.indexOf("linux") === 0) { os = "linux"; }
  if (!os) { return; }
  var list = document.querySelector(".downloads");
  if (!list) { return; }
  var mine = list.querySelectorAll('.download[data-os="' + os + '"]');
  if (!mine.length) { return; }
  list.classList.add("detected");
  for (var i = mine.length - 1; i >= 0; i--) {
    mine[i].classList.add("is-yours");
    list.insertBefore(mine[i], list.firstChild);
  }
})();
</script>
"""


@dataclass(frozen=True)
class Page:
    key: str
    html: str


def _template() -> Template:
    text = (resources.files("tapio_build_tools.downloads") / "templates" / "base.html").read_text(
        encoding="utf-8"
    )
    return Template(text)


def _escape(value: str) -> str:
    return html.escape(value, quote=True)


def logo_data_uri(path: Path) -> str:
    media_type = "image/svg+xml" if path.suffix.lower() == ".svg" else "image/png"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{media_type};base64,{encoded}"


def _href(page_key: str, target_key: str) -> str:
    return posixpath.relpath(target_key, posixpath.dirname(page_key))


def released_on(timestamp: str) -> str:
    moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return f"{moment.day} {moment:%B %Y}"


def file_size(size: int) -> str:
    # In the units a file manager shows next to the downloaded file.
    if size < 1024 * 1024:
        return f"{max(size, 1) / 1024:.0f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _button_label(asset: Asset, release: Release) -> str:
    same_os = [item for item in release.binaries() if item.os == asset.os]
    label = f"Download for {OPERATING_SYSTEMS[asset.os or '']}"
    if len(same_os) > 1:
        label += f" ({asset.arch})"
    return label


def _paragraphs(text: str | None) -> str:
    if not text:
        return ""
    blocks = [" ".join(block.split()) for block in text.strip().split("\n\n")]
    return "".join(f'<p class="note">{_escape(block)}</p>\n' for block in blocks if block)


def _asset_rows(page_key: str, release: Release) -> str:
    rows = []
    for asset in release.assets:
        if asset.kind == "binary":
            what = OPERATING_SYSTEMS[asset.os or ""] + (f" ({asset.arch})" if asset.arch else "")
        elif asset.kind == "source":
            what = "Source code"
        else:
            what = "SBOM" + (f", {OPERATING_SYSTEMS[asset.os]}" if asset.os else "")
        rows.append(
            "<tr>"
            f'<td><a class="mono" href="{_escape(_href(page_key, asset.key))}">{_escape(asset.file)}</a></td>'
            f"<td>{_escape(what)}</td>"
            f"<td>{_escape(file_size(asset.size))}</td>"
            f'<td class="mono">{_escape(asset.sha256)}</td>'
            "</tr>"
        )
    return (
        "<table>\n<thead><tr><th>File</th><th>For</th><th>Size</th><th>SHA-256</th></tr></thead>\n"
        "<tbody>\n" + "\n".join(rows) + "\n</tbody>\n</table>\n"
    )


def _release_body(
    page_key: str,
    program: DownloadProgram,
    manifest: Manifest,
    release: Release,
    newest: Release,
) -> str:
    parts = [
        '<p class="eyebrow">Download</p>\n',
        f"<h1>{_escape(program.name)}</h1>\n",
        f'<p class="release">Version {_escape(release.version)}, released '
        f"{_escape(released_on(release.released))}</p>\n",
    ]
    if release.version != newest.version:
        latest_href = _escape(_href(page_key, f"{manifest.slug}/index.html"))
        parts.append(
            f'<p class="notice">A newer version, {_escape(newest.version)}, is available. '
            f'<a href="{latest_href}">Get the latest release</a>.</p>\n'
        )
    buttons = "".join(
        f'  <li><a class="download" data-os="{_escape(asset.os or "")}" '
        f'href="{_escape(_href(page_key, asset.key))}">{_escape(_button_label(asset, release))}</a></li>\n'
        for asset in release.binaries()
    )
    parts.append(f'<ul class="downloads">\n{buttons}</ul>\n')

    source = release.source()
    if source is not None:
        licence = manifest.license_id or "open source"
        parts.append(
            "<h2>Source code</h2>\n"
            f'<p class="note">{_escape(program.name)} is free software under the {_escape(licence)} '
            "licence. The complete corresponding source code of this version is offered here, "
            "next to the program, for as long as the program itself is. "
            f'You can also request it from <a href="mailto:{_escape(program.contact)}">'
            f"{_escape(program.contact)}</a>.</p>\n"
            f'<p><a class="download secondary" href="{_escape(_href(page_key, source.key))}">'
            f"Source code ({_escape(licence)})</a></p>\n"
        )

    parts.append("<h2>Files</h2>\n")
    parts.append(_asset_rows(page_key, release))
    if release.sboms():
        parts.append(
            '<p class="note muted">The SBOM lists every third-party component inside the '
            "program, in CycloneDX form.</p>\n"
        )
    parts.append(_paragraphs(program.notes))
    parts.append(
        f'<p class="note">Questions and licences: <a href="mailto:{_escape(program.contact)}">'
        f"{_escape(program.contact)}</a>.</p>\n"
    )
    versions_href = _escape(_href(page_key, f"{manifest.slug}/versions/index.html"))
    parts.append(f'<p class="note"><a href="{versions_href}">All versions</a></p>\n')
    return "".join(parts)


def _render(
    program_or_none: DownloadProgram | None,
    *,
    title: str,
    main: str,
    footer: str,
    logo: str | None,
    script: bool,
) -> str:
    indexable = program_or_none.indexable if program_or_none is not None else False
    logo_tag = (
        f'<img class="logo" src="{logo}" alt="" width="144">\n' if logo else ""
    )
    return _template().substitute(
        title=_escape(title),
        robots="" if indexable else ROBOTS,
        logo=logo_tag,
        main=main,
        footer=footer,
        script=SCRIPT if script else "",
    )


def render_program_pages(
    program: DownloadProgram,
    manifest: Manifest,
    organization: str,
    logo: Path | None = None,
) -> list[Page]:
    """Every page of *program*'s site: the permanent one, one per version, the list."""
    newest = latest(manifest)
    if newest is None:
        return []
    logo_uri = logo_data_uri(logo) if logo else None
    pages: list[Page] = []
    footer_note = _escape(organization)

    latest_key = f"{manifest.slug}/index.html"
    pages.append(
        Page(
            latest_key,
            _render(
                program,
                title=f"Download {program.name}",
                main=_release_body(latest_key, program, manifest, newest, newest),
                footer=f"This page always offers the latest release of {_escape(program.name)}.<br>\n{footer_note}",
                logo=logo_uri,
                script=True,
            ),
        )
    )
    for release in manifest.releases:
        key = f"{manifest.slug}/{release.version}/index.html"
        pages.append(
            Page(
                key,
                _render(
                    program,
                    title=f"Download {program.name} {release.version}",
                    main=_release_body(key, program, manifest, release, newest),
                    footer=footer_note,
                    logo=logo_uri,
                    script=True,
                ),
            )
        )

    versions_key = f"{manifest.slug}/versions/index.html"
    rows = []
    for release in manifest.releases:
        systems = ", ".join(
            dict.fromkeys(OPERATING_SYSTEMS[asset.os or ""] for asset in release.binaries())
        )
        extras = []
        if release.source() is not None:
            extras.append("source")
        if release.sboms():
            extras.append("SBOM")
        marker = " (latest)" if release.version == newest.version else ""
        rows.append(
            "<tr>"
            f'<td><a href="{_escape(_href(versions_key, f"{manifest.slug}/{release.version}/index.html"))}">'
            f"{_escape(release.version)}</a>{_escape(marker)}</td>"
            f"<td>{_escape(released_on(release.released))}</td>"
            f"<td>{_escape(systems)}{_escape(', ' + ', '.join(extras) if extras else '')}</td>"
            "</tr>"
        )
    versions_main = (
        '<p class="eyebrow">All versions</p>\n'
        f"<h1>{_escape(program.name)}</h1>\n"
        f'<p class="release"><a href="{_escape(_href(versions_key, latest_key))}">'
        f"Latest release: {_escape(newest.version)}</a></p>\n"
        "<table>\n<thead><tr><th>Version</th><th>Released</th><th>Downloads</th></tr></thead>\n"
        "<tbody>\n" + "\n".join(rows) + "\n</tbody>\n</table>\n"
    )
    pages.append(
        Page(
            versions_key,
            _render(
                program,
                title=f"{program.name} versions",
                main=versions_main,
                footer=footer_note,
                logo=logo_uri,
                script=False,
            ),
        )
    )
    return pages


def render_root_page(manifests: list[Manifest], organization: str, logo: Path | None = None) -> Page:
    """The page at the root of the bucket: one line per program."""
    rows = []
    for manifest in sorted(manifests, key=lambda item: item.name.lower()):
        newest = latest(manifest)
        if newest is None:
            continue
        rows.append(
            "<tr>"
            f'<td><a href="{_escape(manifest.slug)}/index.html">{_escape(manifest.name)}</a></td>'
            f"<td>{_escape(newest.version)}</td>"
            f"<td>{_escape(released_on(newest.released))}</td>"
            "</tr>"
        )
    main = (
        '<p class="eyebrow">Downloads</p>\n'
        f"<h1>{_escape(organization)}</h1>\n"
        "<table>\n<thead><tr><th>Program</th><th>Latest</th><th>Released</th></tr></thead>\n"
        "<tbody>\n" + "\n".join(rows) + "\n</tbody>\n</table>\n"
    )
    return Page(
        "index.html",
        _render(
            None,
            title=f"{organization} downloads",
            main=main,
            footer=_escape(organization),
            logo=logo_data_uri(logo) if logo else None,
            script=False,
        ),
    )
